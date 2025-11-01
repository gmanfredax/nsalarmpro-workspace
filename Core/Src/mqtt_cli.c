#include "mqtt_cli.h"
#include "http_prov.h"
#include "net_lwip.h"
#include "config.h"
#include "tamper_bus.h"
#include "outputs.h"
#include "zones.h"
#include "app_freertos.h"
#include "battery.h"
#include "cpu_temp.h"
#include "adc_frontend.h"
#include "stm32f4xx_hal.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/x509_crt.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define MQTT_KEEPALIVE_SECONDS       60U
#define MQTT_RECONNECT_MIN_MS        2000U
#define MQTT_RECONNECT_MAX_MS        300000U
#define MQTT_RX_BUFFER_SIZE          1024U
#define MQTT_TOPIC_MAX               192U
#define MQTT_STATUS_PAYLOAD_OFFLINE  "offline"
#define MQTT_STATUS_PAYLOAD_ONLINE   "online"

typedef struct
{
    mbedtls_net_context net;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    mbedtls_x509_crt ca;
    bool seeded;
} mqtt_tls_ctx_t;

typedef struct
{
    mqtt_tls_ctx_t tls;
    bool active;
    bool subscribed;
    bool birth_sent;
    uint16_t packet_id;
    uint32_t backoff_ms;
    uint32_t next_retry_tick;
    uint32_t last_tx_tick;
    uint32_t last_rx_tick;
    uint8_t rx_buffer[MQTT_RX_BUFFER_SIZE];
    size_t rx_length;
} mqtt_session_t;

static mqtt_state_t current_state = MQTT_STATE_DISCONNECTED;
static flash_store_blob_t stored_blob;
static bool credentials_valid;
static uint8_t ca_buffer[2048];
static uint16_t ca_len;
static bool mqtt_connected;
static mqtt_session_t mqtt_session;
static char device_id[32];
static char topic_status[MQTT_TOPIC_MAX];
static char topic_cmd_prefix[MQTT_TOPIC_MAX];
static char topic_event_prefix[MQTT_TOPIC_MAX];
static char topic_diag_prefix[MQTT_TOPIC_MAX];

static void update_provisioning_status(provisioning_status_t status, const char *message);
static void mqtt_session_reset(void);
static void mqtt_schedule_retry(bool immediate);
static int mqtt_tls_connect(mqtt_session_t *session, const char *host, uint16_t port);
static int mqtt_send_connect(mqtt_session_t *session);
static int mqtt_send_subscribe(mqtt_session_t *session);
static int mqtt_publish_status(const char *payload);
static int mqtt_publish_packet(const char *topic, const uint8_t *payload, size_t payload_len, int qos, bool retained);
static void mqtt_process_incoming(mqtt_session_t *session);
static bool mqtt_try_consume_packet(mqtt_session_t *session);
static void mqtt_handle_packet(const uint8_t *packet, size_t length);
static void mqtt_handle_publish(const uint8_t *packet, size_t length);
static void mqtt_cmd_cb(const char *topic_suffix, const uint8_t *payload, size_t payload_len);
static int publish_birth(void);
static const char *skip_ws(const char *ptr)
{
    while (ptr != NULL && (*ptr == ' ' || *ptr == '\t' || *ptr == '\r' || *ptr == '\n'))
    {
        ptr++;
    }
    return ptr;
}

static const char *json_find_value(const char *json, const char *key)
{
    if (json == NULL || key == NULL)
    {
        return NULL;
    }
    char pattern[64];
    size_t key_len = strlen(key);
    if (key_len > (sizeof(pattern) - 3U))
    {
        return NULL;
    }
    int written = snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    if (written <= 0)
    {
        return NULL;
    }
    const char *p = json;
    size_t pattern_len = (size_t)written;
    while ((p = strstr(p, pattern)) != NULL)
    {
        const char *after = skip_ws(p + pattern_len);
        if (after == NULL)
        {
            return NULL;
        }
        if (*after != ':')
        {
            p += pattern_len;
            continue;
        }
        after = skip_ws(after + 1);
        return after;
    }
    return NULL;
}

static bool json_get_str(const char *json, size_t len, const char *key, char *out, size_t out_len)
{
    (void)len;
    if (json == NULL || key == NULL || out == NULL || out_len == 0U)
    {
        return false;
    }
    const char *value = json_find_value(json, key);
    if (value == NULL || *value != '\"')
    {
        return false;
    }
    value++;
    size_t i = 0U;
    while (value[i] != '\0' && value[i] != '\"' && i < (out_len - 1U))
    {
        out[i] = value[i];
        i++;
    }
    out[i] = '\0';
    if (value[i] != '\"')
    {
        return false;
    }
    return true;
}

static bool json_get_int(const char *json, size_t len, const char *key, int *value)
{
    (void)len;
    if (json == NULL || key == NULL || value == NULL)
    {
        return false;
    }
    const char *ptr = json_find_value(json, key);
    if (ptr == NULL)
    {
        return false;
    }
    char *endptr = NULL;
    long parsed = strtol(ptr, &endptr, 10);
    if (ptr == endptr)
    {
        return false;
    }
    *value = (int)parsed;
    return true;
}

static bool json_get_bool(const char *json, size_t len, const char *key, bool *value)
{
    (void)len;
    if (json == NULL || key == NULL || value == NULL)
    {
        return false;
    }
    const char *ptr = json_find_value(json, key);
    if (ptr == NULL)
    {
        return false;
    }
    if (strncmp(ptr, "true", 4) == 0)
    {
        *value = true;
        return true;
    }
    if (strncmp(ptr, "false", 5) == 0)
    {
        *value = false;
        return true;
    }
    return false;
}

static bool topic_equals(const char *suffix, const char *expected)
{
    size_t len = strlen(expected);
    return (strncmp(suffix, expected, len) == 0) && (suffix[len] == '\0');
}

static void publish_command_error(const char *cmd, const char *reason)
{
    if (cmd == NULL || reason == NULL)
    {
        return;
    }
    char payload[128];
    snprintf(payload, sizeof(payload), "{\"cmd\":\"%s\",\"reason\":\"%s\"}", cmd, reason);
    mqtt_cli_publish_event("command_error", payload, 1, false);
}
static void mqtt_tls_context_init(mqtt_tls_ctx_t *ctx)
{
    mbedtls_net_init(&ctx->net);
    mbedtls_ssl_init(&ctx->ssl);
    mbedtls_ssl_config_init(&ctx->conf);
    mbedtls_ctr_drbg_init(&ctx->ctr_drbg);
    mbedtls_entropy_init(&ctx->entropy);
    mbedtls_x509_crt_init(&ctx->ca);
    ctx->seeded = false;
}

void mqtt_cli_init(void)
{
    memset(&stored_blob, 0, sizeof(stored_blob));
    mqtt_tls_context_init(&mqtt_session.tls);
    mqtt_session_reset();
    mqtt_session.backoff_ms = MQTT_RECONNECT_MIN_MS;
    mqtt_session.next_retry_tick = 0U;
    const char *id = net_lwip_get_device_id();
    if (id != NULL)
    {
        strncpy(device_id, id, sizeof(device_id) - 1U);
        device_id[sizeof(device_id) - 1U] = '\0';
    }
    else
    {
        snprintf(device_id, sizeof(device_id), "nsap-unknown");
    }
    snprintf(topic_status, sizeof(topic_status), "nsalarmpro/%s/status", device_id);
    snprintf(topic_cmd_prefix, sizeof(topic_cmd_prefix), "nsalarmpro/%s/cmd/", device_id);
    snprintf(topic_event_prefix, sizeof(topic_event_prefix), "nsalarmpro/%s/event/", device_id);
    snprintf(topic_diag_prefix, sizeof(topic_diag_prefix), "nsalarmpro/%s/diag/", device_id);

    if (flash_store_load(&stored_blob) && stored_blob.provisioned)
    {
        credentials_valid = true;
        current_state = MQTT_STATE_OPERATIONAL;
        http_prov_set_enabled(false);
    }
    else
    {
        current_state = MQTT_STATE_BOOTSTRAP;
        http_prov_set_enabled(true);
        credentials_valid = false;
    }
}

void mqtt_cli_set_bootstrap(const char *host, uint16_t port, const char *password)
{
    if (host != NULL)
    {
        strncpy(stored_blob.mqtt_host, host, sizeof(stored_blob.mqtt_host) - 1U);
        stored_blob.mqtt_host[sizeof(stored_blob.mqtt_host) - 1U] = '\0';
    }
    stored_blob.mqtt_port = port;
    if (password != NULL)
    {
        strncpy(stored_blob.claim_code, password, sizeof(stored_blob.claim_code) - 1U);
        stored_blob.claim_code[sizeof(stored_blob.claim_code) - 1U] = '\0';
    }
    current_state = MQTT_STATE_BOOTSTRAP;
}

void mqtt_cli_set_claim(const char *code)
{
    if (code != NULL)
    {
        strncpy(stored_blob.claim_code, code, sizeof(stored_blob.claim_code) - 1U);
        stored_blob.claim_code[sizeof(stored_blob.claim_code) - 1U] = '\0';
    }
}

void mqtt_cli_set_credentials(const char *username, const char *password)
{
    if (username != NULL)
    {
        strncpy(stored_blob.mqtt_username, username, sizeof(stored_blob.mqtt_username) - 1U);
        stored_blob.mqtt_username[sizeof(stored_blob.mqtt_username) - 1U] = '\0';
    }
    if (password != NULL)
    {
        strncpy(stored_blob.mqtt_password, password, sizeof(stored_blob.mqtt_password) - 1U);
        stored_blob.mqtt_password[sizeof(stored_blob.mqtt_password) - 1U] = '\0';
    }
    credentials_valid = true;
    stored_blob.provisioned = 1U;
    if (!flash_store_save(&stored_blob))
    {
        credentials_valid = false;
        http_prov_set_progress(PROV_STATUS_ERROR, "Persistenza credenziali fallita");
        return;
    }
    http_prov_set_progress(PROV_STATUS_DONE, "Provisioning completato");
    current_state = MQTT_STATE_OPERATIONAL;
    mqtt_schedule_retry(true);
}

void mqtt_cli_set_ca(const uint8_t *pem, uint16_t len)
{
    if (pem == NULL || len == 0U)
    {
        ca_len = 0U;
        stored_blob.ca_cert_len = 0U;
        return;
    }
    if (len > sizeof(ca_buffer))
    {
        len = sizeof(ca_buffer);
    }
    memcpy(ca_buffer, pem, len);
    ca_len = len;
    stored_blob.ca_cert_len = len;
    memcpy(stored_blob.ca_cert, pem, len);
}

void mqtt_cli_tick(void)
{
    if (!credentials_valid)
    {
        mqtt_connected = false;
        return;
    }

    if (net_lwip_get_state() != NET_STATE_READY)
    {
        mqtt_session_reset();
        return;
    }

    uint32_t now = HAL_GetTick();

    if (!mqtt_session.active)
    {
        if (now < mqtt_session.next_retry_tick)
        {
            return;
        }
        if (mqtt_tls_connect(&mqtt_session, stored_blob.mqtt_host, stored_blob.mqtt_port != 0U ? stored_blob.mqtt_port : NSAP_MQTT_PORT_SECURE) == 0)
        {
            if (mqtt_send_connect(&mqtt_session) == 0)
            {
                mqtt_session.active = true;
                mqtt_session.subscribed = false;
                mqtt_session.birth_sent = false;
                mqtt_session.packet_id = 1U;
                mqtt_session.rx_length = 0U;
                mqtt_session.last_tx_tick = now;
                mqtt_session.last_rx_tick = now;
                mqtt_session.backoff_ms = MQTT_RECONNECT_MIN_MS;
                current_state = MQTT_STATE_OPERATIONAL;
                update_provisioning_status(PROV_STATUS_BOOTSTRAP_CONNECTED, "MQTT connesso");
            }
            else
            {
                mqtt_session_reset();
                mqtt_schedule_retry(false);
            }
        }
        else
        {
            mqtt_session_reset();
            mqtt_schedule_retry(false);
        }
        return;
    }

    if (mqtt_session.active && !mqtt_session.subscribed)
    {
        if (mqtt_send_subscribe(&mqtt_session) != 0)
        {
            mqtt_session_reset();
            mqtt_schedule_retry(false);
            return;
        }
    }

    mqtt_process_incoming(&mqtt_session);

    if (mqtt_session.subscribed && !mqtt_session.birth_sent)
    {
        if (publish_birth() == 0)
        {
            mqtt_session.birth_sent = true;
            mqtt_connected = true;
            update_provisioning_status(PROV_STATUS_MQTT_CONNECTED, "Broker operativo");
        }
    }

    if (mqtt_session.active)
    {
        if ((now - mqtt_session.last_tx_tick) > (MQTT_KEEPALIVE_SECONDS * 500U))
        {
            uint8_t ping[2] = {0xC0, 0x00};
            if (mbedtls_ssl_write(&mqtt_session.tls.ssl, ping, sizeof(ping)) < 0)
            {
                mqtt_session_reset();
                mqtt_schedule_retry(false);
                return;
            }
            mqtt_session.last_tx_tick = HAL_GetTick();
        }
        if ((now - mqtt_session.last_rx_tick) > (MQTT_KEEPALIVE_SECONDS * 2000U))
        {
            mqtt_session_reset();
            mqtt_schedule_retry(false);
        }
    }
}

void mqtt_cli_publish_telemetry(void)
{
    if (!mqtt_connected)
    {
        return;
    }
    adc_sample_t v12;
    bool have_v12 = adc_frontend_get_v12(&v12);
    battery_snapshot_t battery;
    battery_get(&battery);
    cpu_temp_sample_t temp;
    cpu_temp_get(&temp);
    char payload[256];
    snprintf(payload, sizeof(payload),
             "{\"v12\":%.2f,\"vbat\":%.2f,\"cpu_temp\":%.2f}",
             have_v12 ? (v12.value_mv / 1000.0f) : 0.0f,
             battery.voltage,
             temp.celsius);
    mqtt_cli_publish_event("telemetry/voltages", payload, 0, false);
}

void mqtt_cli_publish_tamper(tamper_state_t state, bool analog, float voltage_v, float short_thr_v, float open_thr_v)
{
    if (!mqtt_connected)
    {
        return;
    }
    const char *status = "UNKNOWN";
    switch (state)
    {
    case TAMPER_STATE_NORMAL:
        status = "CLOSED";
        break;
    case TAMPER_STATE_OPEN:
        status = "OPEN";
        break;
    case TAMPER_STATE_SHORT:
        status = "SHORT";
        break;
    default:
        break;
    }
    char payload[160];
    if (analog)
    {
        snprintf(payload, sizeof(payload),
                 "{\"state\":\"%s\",\"analog\":true,\"voltage\":%.3f,\"th\":{\"short_max\":%.3f,\"open_min\":%.3f}}",
                 status,
                 voltage_v,
                 short_thr_v,
                 open_thr_v);
    }
    else
    {
        snprintf(payload, sizeof(payload),
                 "{\"state\":\"%s\",\"analog\":false}",
                 status);
    }
    mqtt_cli_publish_event("telemetry/tamper_bus", payload, 0, false);
}

void mqtt_cli_publish_event(const char *name, const char *json, int qos, bool retained)
{
    if (!mqtt_connected || name == NULL || json == NULL)
    {
        return;
    }

    if (qos < 0)
    {
        qos = 0;
    }
    if (qos > 1)
    {
        qos = 1;
    }

    char topic[MQTT_TOPIC_MAX];
    snprintf(topic, sizeof(topic), "%s%s", topic_event_prefix, name);
    mqtt_publish_packet(topic, (const uint8_t *)json, strlen(json), qos, retained);
}

void mqtt_cli_publish_diag_report(const char *json)
{
    if (!mqtt_connected || json == NULL)
    {
        return;
    }

    char topic[MQTT_TOPIC_MAX];
    snprintf(topic, sizeof(topic), "%sreport", topic_diag_prefix);
    mqtt_publish_packet(topic, (const uint8_t *)json, strlen(json), 1, false);
}

mqtt_state_t mqtt_cli_get_state(void)
{
    return current_state;
}

bool mqtt_cli_is_connected(void)
{
    return mqtt_connected;
}

static void mqtt_session_reset(void)
{
    if (mqtt_session.active)
    {
        mbedtls_ssl_close_notify(&mqtt_session.tls.ssl);
    }
    mbedtls_ssl_free(&mqtt_session.tls.ssl);
    mbedtls_ssl_config_free(&mqtt_session.tls.conf);
    mbedtls_net_free(&mqtt_session.tls.net);
    mbedtls_x509_crt_free(&mqtt_session.tls.ca);
    mbedtls_ssl_init(&mqtt_session.tls.ssl);
    mbedtls_ssl_config_init(&mqtt_session.tls.conf);
    mbedtls_net_init(&mqtt_session.tls.net);
    mbedtls_x509_crt_init(&mqtt_session.tls.ca);
    mqtt_session.active = false;
    mqtt_session.subscribed = false;
    mqtt_session.birth_sent = false;
    mqtt_session.rx_length = 0U;
    mqtt_connected = false;
}

static void mqtt_schedule_retry(bool immediate)
{
    uint32_t now = HAL_GetTick();
    if (immediate)
    {
        mqtt_session.backoff_ms = MQTT_RECONNECT_MIN_MS;
        mqtt_session.next_retry_tick = now;
        return;
    }
    uint32_t jitter = (HAL_GetTick() & 0x3FFU);
    uint32_t delay = mqtt_session.backoff_ms + (jitter % 250U);
    if (delay > MQTT_RECONNECT_MAX_MS)
    {
        delay = MQTT_RECONNECT_MAX_MS;
    }
    mqtt_session.next_retry_tick = now + delay;
    if (mqtt_session.backoff_ms < MQTT_RECONNECT_MAX_MS)
    {
        uint32_t next = mqtt_session.backoff_ms * 2U;
        mqtt_session.backoff_ms = (next > MQTT_RECONNECT_MAX_MS) ? MQTT_RECONNECT_MAX_MS : next;
    }
}

static int mqtt_tls_connect(mqtt_session_t *session, const char *host, uint16_t port)
{
    if (host == NULL || host[0] == '\0')
    {
        return -1;
    }

    const char *pers = "nsalarmpro-mqtt";
    if (!session->tls.seeded)
    {
        if (mbedtls_ctr_drbg_seed(&session->tls.ctr_drbg, mbedtls_entropy_func, &session->tls.entropy,
                                   (const unsigned char *)pers, strlen(pers)) != 0)
        {
            return -1;
        }
        session->tls.seeded = true;
    }

    char port_str[6];
    snprintf(port_str, sizeof(port_str), "%u", (unsigned int)port);

    uint8_t ca_local[sizeof(ca_buffer) + 1U];
    size_t ca_local_len = stored_blob.ca_cert_len;
    if (ca_local_len == 0U && ca_len != 0U)
    {
        ca_local_len = ca_len;
        memcpy(stored_blob.ca_cert, ca_buffer, ca_local_len);
        stored_blob.ca_cert_len = ca_local_len;
    }

    if (ca_local_len > sizeof(ca_buffer))
    {
        ca_local_len = sizeof(ca_buffer);
    }

    if (ca_local_len > 0U)
    {
        memcpy(ca_local, stored_blob.ca_cert, ca_local_len);
        ca_local[ca_local_len] = '\0';
        if (mbedtls_x509_crt_parse(&session->tls.ca, ca_local, ca_local_len + 1U) != 0)
        {
            return -1;
        }
    }
    else
    {
        return -1;
    }

    if (mbedtls_net_connect(&session->tls.net, host, port_str, MBEDTLS_NET_PROTO_TCP) != 0)
    {
        return -1;
    }

    if (mbedtls_ssl_config_defaults(&session->tls.conf,
                                    MBEDTLS_SSL_IS_CLIENT,
                                    MBEDTLS_SSL_TRANSPORT_STREAM,
                                    MBEDTLS_SSL_PRESET_DEFAULT) != 0)
    {
        return -1;
    }
    mbedtls_ssl_conf_authmode(&session->tls.conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_rng(&session->tls.conf, mbedtls_ctr_drbg_random, &session->tls.ctr_drbg);
    mbedtls_ssl_conf_ca_chain(&session->tls.conf, &session->tls.ca, NULL);
    mbedtls_ssl_conf_read_timeout(&session->tls.conf, 1000U);

    if (mbedtls_ssl_setup(&session->tls.ssl, &session->tls.conf) != 0)
    {
        return -1;
    }

    if (mbedtls_ssl_set_hostname(&session->tls.ssl, host) != 0)
    {
        return -1;
    }

    mbedtls_ssl_set_bio(&session->tls.ssl, &session->tls.net, mbedtls_net_send, NULL, mbedtls_net_recv_timeout);

    int ret;
    do
    {
        ret = mbedtls_ssl_handshake(&session->tls.ssl);
    } while (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE);

    if (ret != 0)
    {
        return -1;
    }

    return 0;
}

static size_t mqtt_encode_varint(uint8_t *dst, size_t value)
{
    size_t idx = 0U;
    do
    {
        uint8_t byte = value % 128U;
        value /= 128U;
        if (value > 0U)
        {
            byte |= 0x80U;
        }
        dst[idx++] = byte;
    } while (value > 0U && idx < 4U);
    return idx;
}

static int mqtt_send_connect(mqtt_session_t *session)
{
    uint8_t payload[512];
    size_t len = 0U;

    payload[len++] = 0x00;
    payload[len++] = 0x04;
    payload[len++] = 'M';
    payload[len++] = 'Q';
    payload[len++] = 'T';
    payload[len++] = 'T';
    payload[len++] = 0x04;

    uint8_t connect_flags = 0x02; /* Clean session */
    connect_flags |= 0x04;        /* Will flag */
    connect_flags |= 0x08;        /* Will QoS1 */
    connect_flags |= 0x20;        /* Will retained */
    if (stored_blob.mqtt_username[0] != '\0')
    {
        connect_flags |= 0x80;
    }
    if (stored_blob.mqtt_password[0] != '\0')
    {
        connect_flags |= 0x40;
    }
    payload[len++] = connect_flags;
    payload[len++] = (uint8_t)((MQTT_KEEPALIVE_SECONDS >> 8) & 0xFFU);
    payload[len++] = (uint8_t)(MQTT_KEEPALIVE_SECONDS & 0xFFU);

    uint16_t client_len = (uint16_t)strlen(device_id);
    payload[len++] = (uint8_t)((client_len >> 8) & 0xFFU);
    payload[len++] = (uint8_t)(client_len & 0xFFU);
    memcpy(&payload[len], device_id, client_len);
    len += client_len;

    uint16_t topic_len = (uint16_t)strlen(topic_status);
    payload[len++] = (uint8_t)((topic_len >> 8) & 0xFFU);
    payload[len++] = (uint8_t)(topic_len & 0xFFU);
    memcpy(&payload[len], topic_status, topic_len);
    len += topic_len;

    const char *offline = MQTT_STATUS_PAYLOAD_OFFLINE;
    uint16_t will_len = (uint16_t)strlen(offline);
    payload[len++] = (uint8_t)((will_len >> 8) & 0xFFU);
    payload[len++] = (uint8_t)(will_len & 0xFFU);
    memcpy(&payload[len], offline, will_len);
    len += will_len;

    if (stored_blob.mqtt_username[0] != '\0')
    {
        uint16_t ulen = (uint16_t)strlen(stored_blob.mqtt_username);
        payload[len++] = (uint8_t)((ulen >> 8) & 0xFFU);
        payload[len++] = (uint8_t)(ulen & 0xFFU);
        memcpy(&payload[len], stored_blob.mqtt_username, ulen);
        len += ulen;
    }

    if (stored_blob.mqtt_password[0] != '\0')
    {
        uint16_t plen = (uint16_t)strlen(stored_blob.mqtt_password);
        payload[len++] = (uint8_t)((plen >> 8) & 0xFFU);
        payload[len++] = (uint8_t)(plen & 0xFFU);
        memcpy(&payload[len], stored_blob.mqtt_password, plen);
        len += plen;
    }

    uint8_t header[5];
    header[0] = 0x10;
    size_t enc_len = mqtt_encode_varint(&header[1], len);
    int ret = mbedtls_ssl_write(&session->tls.ssl, header, 1U + enc_len);
    if (ret <= 0)
    {
        return -1;
    }
    ret = mbedtls_ssl_write(&session->tls.ssl, payload, len);
    if (ret <= 0)
    {
        return -1;
    }

    uint8_t connack[4];
    int read_ret;
    size_t read_total = 0U;
    while (read_total < sizeof(connack))
    {
        read_ret = mbedtls_ssl_read(&session->tls.ssl, connack + read_total, sizeof(connack) - read_total);
        if (read_ret == MBEDTLS_ERR_SSL_WANT_READ || read_ret == MBEDTLS_ERR_SSL_WANT_WRITE || read_ret == MBEDTLS_ERR_SSL_TIMEOUT)
        {
            continue;
        }
        if (read_ret <= 0)
        {
            return -1;
        }
        read_total += (size_t)read_ret;
        if (connack[0] == 0x20 && read_total >= 4U)
        {
            break;
        }
    }

    if (connack[0] != 0x20 || connack[1] != 0x02 || connack[3] != 0x00)
    {
        return -1;
    }

    session->last_rx_tick = HAL_GetTick();
    return 0;
}

static int mqtt_send_subscribe(mqtt_session_t *session)
{
    uint8_t buffer[256];
    uint16_t packet_id = session->packet_id++;
    size_t len = 0U;

    uint8_t header_index = 0U;
    buffer[header_index++] = 0x82;

    uint8_t payload[220];
    size_t payload_len = 0U;
    payload[payload_len++] = (uint8_t)((packet_id >> 8) & 0xFFU);
    payload[payload_len++] = (uint8_t)(packet_id & 0xFFU);

    char topic_filter[MQTT_TOPIC_MAX];
    snprintf(topic_filter, sizeof(topic_filter), "%s#", topic_cmd_prefix);
    uint16_t topic_filter_len = (uint16_t)strlen(topic_filter);
    payload[payload_len++] = (uint8_t)((topic_filter_len >> 8) & 0xFFU);
    payload[payload_len++] = (uint8_t)(topic_filter_len & 0xFFU);
    memcpy(&payload[payload_len], topic_filter, topic_filter_len);
    payload_len += topic_filter_len;
    payload[payload_len++] = 0x01; /* QoS1 */

    size_t enc_len = mqtt_encode_varint(&buffer[header_index], payload_len);
    header_index += enc_len;
    memcpy(&buffer[header_index], payload, payload_len);
    header_index += payload_len;

    int written = mbedtls_ssl_write(&session->tls.ssl, buffer, header_index);
    if (written <= 0)
    {
        return -1;
    }
    session->last_tx_tick = HAL_GetTick();
    return 0;
}

static int mqtt_publish_status(const char *payload)
{
    size_t len = strlen(payload);
    return mqtt_publish_packet(topic_status, (const uint8_t *)payload, len, 1, true);
}

static int mqtt_publish_packet(const char *topic, const uint8_t *payload, size_t payload_len, int qos, bool retained)
{
    if (!mqtt_session.active)
    {
        return -1;
    }

    uint8_t header_flags = 0x30;
    if (retained)
    {
        header_flags |= 0x01;
    }
    if (qos == 1)
    {
        header_flags |= 0x02;
    }

    uint8_t header[5];
    uint8_t payload_buf[512];
    size_t pos = 0U;

    uint16_t topic_len = (uint16_t)strlen(topic);
    payload_buf[pos++] = (uint8_t)((topic_len >> 8) & 0xFFU);
    payload_buf[pos++] = (uint8_t)(topic_len & 0xFFU);
    memcpy(&payload_buf[pos], topic, topic_len);
    pos += topic_len;

    uint16_t packet_id = 0U;
    if (qos == 1)
    {
        packet_id = mqtt_session.packet_id++;
        payload_buf[pos++] = (uint8_t)((packet_id >> 8) & 0xFFU);
        payload_buf[pos++] = (uint8_t)(packet_id & 0xFFU);
    }

    if ((pos + payload_len) > sizeof(payload_buf))
    {
        return -1;
    }
    memcpy(&payload_buf[pos], payload, payload_len);
    pos += payload_len;

    header[0] = header_flags;
    size_t enc_len = mqtt_encode_varint(&header[1], pos);
    size_t header_len = 1U + enc_len;

    int ret = mbedtls_ssl_write(&mqtt_session.tls.ssl, header, header_len);
    if (ret <= 0)
    {
        return -1;
    }
    ret = mbedtls_ssl_write(&mqtt_session.tls.ssl, payload_buf, pos);
    if (ret <= 0)
    {
        return -1;
    }
    mqtt_session.last_tx_tick = HAL_GetTick();
    return 0;
}

static void mqtt_process_incoming(mqtt_session_t *session)
{
    int ret = mbedtls_ssl_read(&session->tls.ssl, &session->rx_buffer[session->rx_length],
                                MQTT_RX_BUFFER_SIZE - session->rx_length);
    if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE || ret == MBEDTLS_ERR_SSL_TIMEOUT)
    {
        mqtt_try_consume_packet(session);
        return;
    }
    if (ret <= 0)
    {
        mqtt_session_reset();
        mqtt_schedule_retry(false);
        return;
    }
    session->rx_length += (size_t)ret;
    session->last_rx_tick = HAL_GetTick();

    while (mqtt_try_consume_packet(session))
    {
        ;
    }
}

static bool mqtt_try_consume_packet(mqtt_session_t *session)
{
    if (session->rx_length < 2U)
    {
        return false;
    }
    size_t consumed = 0U;
    size_t multiplier = 1U;
    size_t value = 0U;
    uint8_t encoded_len;
    do
    {
        encoded_len = session->rx_buffer[1U + consumed];
        value += (encoded_len & 0x7FU) * multiplier;
        multiplier *= 128U;
        consumed++;
        if (consumed > 4U)
        {
            return false;
        }
    } while ((encoded_len & 0x80U) != 0U && (1U + consumed) < session->rx_length);

    size_t total_len = 1U + consumed + value;
    if (session->rx_length < total_len)
    {
        return false;
    }

    mqtt_handle_packet(session->rx_buffer, total_len);
    memmove(session->rx_buffer, &session->rx_buffer[total_len], session->rx_length - total_len);
    session->rx_length -= total_len;
    return (session->rx_length >= 2U);
}

static void mqtt_handle_packet(const uint8_t *packet, size_t length)
{
    uint8_t type = packet[0] >> 4;
    switch (type)
    {
    case 3:
        mqtt_handle_publish(packet, length);
        break;
    case 4:
        break;
    case 9:
        mqtt_session.subscribed = true;
        break;
    case 13:
        break;
    default:
        break;
    }
}

static void mqtt_handle_publish(const uint8_t *packet, size_t length)
{
    if (length < 5U)
    {
        return;
    }
    uint8_t header = packet[0];
    int qos = (header >> 1) & 0x03;
    size_t pos = 1U;
    size_t consumed = 0U;
    do
    {
        if ((1U + consumed) >= length)
        {
            return;
        }
        uint8_t encoded = packet[1U + consumed];
        consumed++;
        if ((encoded & 0x80U) == 0U)
        {
            break;
        }
    } while (consumed < 4U);
    pos += consumed;

    uint16_t topic_len = (uint16_t)((packet[pos] << 8) | packet[pos + 1U]);
    pos += 2U;
    if ((pos + topic_len) > length)
    {
        return;
    }
    char topic[MQTT_TOPIC_MAX];
    size_t copy_len = (topic_len < (MQTT_TOPIC_MAX - 1U)) ? topic_len : (MQTT_TOPIC_MAX - 1U);
    memcpy(topic, &packet[pos], copy_len);
    topic[copy_len] = '\0';
    pos += topic_len;

    uint16_t packet_id = 0U;
    if (qos > 0)
    {
        packet_id = (uint16_t)((packet[pos] << 8) | packet[pos + 1U]);
        pos += 2U;
    }

    size_t payload_len = length - pos;
    if (payload_len >= MQTT_RX_BUFFER_SIZE)
    {
        payload_len = MQTT_RX_BUFFER_SIZE - 1U;
    }
    uint8_t payload[MQTT_RX_BUFFER_SIZE];
    memcpy(payload, &packet[pos], payload_len);
    payload[payload_len] = '\0';

    if (strncmp(topic, topic_cmd_prefix, strlen(topic_cmd_prefix)) == 0)
    {
        const char *suffix = topic + strlen(topic_cmd_prefix);
        mqtt_cmd_cb(suffix, payload, payload_len);
    }

    if (qos == 1)
    {
        uint8_t ack[4];
        ack[0] = 0x40;
        ack[1] = 0x02;
        ack[2] = (uint8_t)((packet_id >> 8) & 0xFFU);
        ack[3] = (uint8_t)(packet_id & 0xFFU);
        mbedtls_ssl_write(&mqtt_session.tls.ssl, ack, sizeof(ack));
    }
}

static void mqtt_cmd_cb(const char *topic_suffix, const uint8_t *payload, size_t payload_len)
{
    if (topic_suffix == NULL)
    {
        return;
    }

    char cmd_name[48];
    size_t suffix_len = strlen(topic_suffix);
    size_t cmd_len = (suffix_len < (sizeof(cmd_name) - 1U)) ? suffix_len : (sizeof(cmd_name) - 1U);
    memcpy(cmd_name, topic_suffix, cmd_len);
    cmd_name[cmd_len] = '\0';

    char json_buffer[MQTT_RX_BUFFER_SIZE];
    size_t json_len = 0U;
    if (payload != NULL && payload_len > 0U)
    {
        json_len = (payload_len < (sizeof(json_buffer) - 1U)) ? payload_len : (sizeof(json_buffer) - 1U);
        memcpy(json_buffer, payload, json_len);
        json_buffer[json_len] = '\0';
    }
    else
    {
        json_buffer[0] = '\0';
    }

    bool handled = false;
    bool ok = true;
    const char *error_reason = NULL;

    if (topic_equals(topic_suffix, "arming"))
    {
        handled = true;
        if (json_len == 0U)
        {
            ok = false;
            error_reason = "bad_json";
        }
        else if (!arming_handle_json(json_buffer, (int)json_len))
        {
            ok = false;
            error_reason = "bad_param";
        }
    }
    else if (topic_equals(topic_suffix, "bypass") || topic_equals(topic_suffix, "zones/bypass"))
    {
        handled = true;
        if (json_len == 0U)
        {
            ok = false;
            error_reason = "bad_json";
        }
        else if (!zones_bypass_handle_json(json_buffer, (int)json_len))
        {
            ok = false;
            error_reason = "bad_param";
        }
    }
    else if (topic_equals(topic_suffix, "output") || topic_equals(topic_suffix, "outputs"))
    {
        handled = true;
        if (json_len == 0U)
        {
            ok = false;
            error_reason = "bad_json";
        }
        else if (!outputs_handle_json(json_buffer, (int)json_len))
        {
            ok = false;
            error_reason = "bad_param";
        }
    }
    else if (topic_equals(topic_suffix, "config/zone"))
    {
        handled = true;
        if (json_len == 0U)
        {
            ok = false;
            error_reason = "bad_json";
        }
        else if (!zones_config_handle_json(json_buffer, (int)json_len))
        {
            ok = false;
            error_reason = "bad_param";
        }
    }
    else if (topic_equals(topic_suffix, "maint"))
    {
        handled = true;
        if (json_len == 0U)
        {
            ok = false;
            error_reason = "bad_json";
        }
        else if (!maint_handle_json(json_buffer, (int)json_len))
        {
            ok = false;
            error_reason = "bad_param";
        }
    }
    else if (topic_equals(topic_suffix, "diag") || topic_equals(topic_suffix, "diag/report"))
    {
        handled = true;
        diag_publish_now();
    }
    else if (topic_equals(topic_suffix, "tamper_cal"))
    {
        handled = true;
        if (!tamper_bus_calibrate_normal())
        {
            ok = false;
            error_reason = "bad_param";
        }
    }

    if (handled && !ok && error_reason != NULL)
    {
        publish_command_error(cmd_name, error_reason);
    }
}

static void update_provisioning_status(provisioning_status_t status, const char *message)
{
    http_prov_set_progress(status, message);
}
static int publish_birth(void)
{
    return mqtt_publish_status(MQTT_STATUS_PAYLOAD_ONLINE);
}
