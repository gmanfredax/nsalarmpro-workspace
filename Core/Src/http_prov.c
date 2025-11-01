#include "http_prov.h"
#include "lwip/apps/httpd.h"
#include "lwip/def.h"
#include "config.h"
#include "flash_store.h"
#include "claim.h"
#include "mqtt_cli.h"
#include "net_lwip.h"
#include "led_rgb.h"
#include "stm32f4xx_hal.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#define PROV_MESSAGE_READY           "Interfaccia pronta"
#define PROV_MESSAGE_FORBIDDEN       "Provisioning gi\303\160 completato"
#define PROV_FORM_BUFFER_SIZE        3072U

static bool provisioning_enabled = true;
static provisioning_progress_t current_progress = {PROV_STATUS_IDLE, ""};
static uint32_t progress_generation = 0U;
static flash_store_blob_t cached_blob;
static bool cached_blob_valid = false;
static bool redirect_pending = false;
static bool shutdown_scheduled = false;
static uint32_t shutdown_deadline_ms = 0U;

static char http_form_buffer[PROV_FORM_BUFFER_SIZE];
static char stream_buffer[256];

static const char *cgi_root_handler(int idx, int num, char **param, char **value);
static const char *cgi_provision_handler(int idx, int num, char **param, char **value);
static const char *cgi_stream_handler(int idx, int num, char **param, char **value);
static void update_led(void);
static const char *build_form_page(void);
static const char *status_to_string(provisioning_status_t status);
static const char *param_lookup(int count, char **param, char **value, const char *key);
static void url_decode_inplace(char *value);
static bool handle_provision_request(int count, char **param, char **value);
static void schedule_shutdown(void);

void http_prov_init(void)
{
    cached_blob_valid = flash_store_load(&cached_blob);
    if (cached_blob_valid && cached_blob.provisioned != 0U)
    {
        provisioning_enabled = false;
        current_progress.status = PROV_STATUS_DONE;
        strncpy(current_progress.message, PROV_MESSAGE_FORBIDDEN, sizeof(current_progress.message) - 1U);
        current_progress.message[sizeof(current_progress.message) - 1U] = '\0';
    }
    else
    {
        provisioning_enabled = true;
        http_prov_set_progress(PROV_STATUS_IDLE, PROV_MESSAGE_READY);
    }

    static const tCGI cgi_handlers[] = {
        {"/", cgi_root_handler},
        {"/provision", cgi_provision_handler},
        {"/provision/stream", cgi_stream_handler}
    };

    httpd_init();
    http_set_cgi_handlers(cgi_handlers, LWIP_ARRAYSIZE(cgi_handlers));
    update_led();
}

void http_prov_set_enabled(bool enabled)
{
    provisioning_enabled = enabled;
    if (!enabled)
    {
        shutdown_scheduled = false;
        redirect_pending = false;
        strncpy(current_progress.message, PROV_MESSAGE_FORBIDDEN, sizeof(current_progress.message) - 1U);
        current_progress.message[sizeof(current_progress.message) - 1U] = '\0';
        current_progress.status = PROV_STATUS_DONE;
    }
    else if (current_progress.status == PROV_STATUS_DONE || current_progress.status == PROV_STATUS_ERROR)
    {
        http_prov_set_progress(PROV_STATUS_IDLE, PROV_MESSAGE_READY);
    }
    update_led();
}

bool http_prov_is_enabled(void)
{
    return provisioning_enabled;
}

void http_prov_set_progress(provisioning_status_t status, const char *message)
{
    current_progress.status = status;
    if (message != NULL)
    {
        strncpy(current_progress.message, message, sizeof(current_progress.message) - 1U);
        current_progress.message[sizeof(current_progress.message) - 1U] = '\0';
    }
    else
    {
        current_progress.message[0] = '\0';
    }
    progress_generation++;

    if (status == PROV_STATUS_MQTT_CONNECTED || status == PROV_STATUS_DONE)
    {
        redirect_pending = true;
        schedule_shutdown();
    }
    else if (status == PROV_STATUS_ERROR)
    {
        shutdown_scheduled = false;
    }

    update_led();
}

bool http_prov_get_progress(provisioning_progress_t *progress)
{
    if (progress == NULL)
    {
        return false;
    }
    *progress = current_progress;
    return true;
}

void http_prov_stream_tick(void)
{
    if (!shutdown_scheduled)
    {
        return;
    }

    uint32_t now = HAL_GetTick();
    if ((int32_t)(now - shutdown_deadline_ms) >= 0)
    {
        shutdown_scheduled = false;
        http_prov_set_enabled(false);
    }
}

void http_prov_factory_reset(void)
{
    cached_blob_valid = false;
    memset(&cached_blob, 0, sizeof(cached_blob));
    provisioning_enabled = true;
    redirect_pending = false;
    shutdown_scheduled = false;
    http_prov_set_progress(PROV_STATUS_IDLE, PROV_MESSAGE_READY);
}

static const char *cgi_root_handler(int idx, int num, char **param, char **value)
{
    LWIP_UNUSED_ARG(idx);
    LWIP_UNUSED_ARG(num);
    LWIP_UNUSED_ARG(param);
    LWIP_UNUSED_ARG(value);

    if (!provisioning_enabled)
    {
        snprintf(http_form_buffer, sizeof(http_form_buffer),
                 "<html><head><meta charset=\"utf-8\"><title>NSAlarmPro Provisioning</title></head>"
                 "<body><h1>Provisioning disabilitato</h1><p>%s</p></body></html>",
                 current_progress.message);
        return http_form_buffer;
    }

    return build_form_page();
}

static const char *cgi_provision_handler(int idx, int num, char **param, char **value)
{
    LWIP_UNUSED_ARG(idx);

    if (!provisioning_enabled)
    {
        snprintf(http_form_buffer, sizeof(http_form_buffer),
                 "<html><head><meta charset=\"utf-8\"></head><body><p>%s</p></body></html>",
                 PROV_MESSAGE_FORBIDDEN);
        return http_form_buffer;
    }

    if (num <= 0)
    {
        snprintf(http_form_buffer, sizeof(http_form_buffer),
                 "<html><head><meta charset=\"utf-8\"></head><body><p>Richiesta non valida</p></body></html>");
        return http_form_buffer;
    }

    if (handle_provision_request(num, param, value))
    {
        snprintf(http_form_buffer, sizeof(http_form_buffer),
                 "<html><head><meta charset=\"utf-8\"></head><body><p>Provisioning avviato.</p>"
                 "<p>Controllare lo stato in tempo reale.</p></body></html>");
    }
    else
    {
        snprintf(http_form_buffer, sizeof(http_form_buffer),
                 "<html><head><meta charset=\"utf-8\"></head><body><p>Errore di provisioning.</p></body></html>");
    }

    return http_form_buffer;
}

static const char *cgi_stream_handler(int idx, int num, char **param, char **value)
{
    LWIP_UNUSED_ARG(idx);
    LWIP_UNUSED_ARG(num);
    LWIP_UNUSED_ARG(param);
    LWIP_UNUSED_ARG(value);

    const char *status = status_to_string(current_progress.status);
    char redirect_url[160];
    redirect_url[0] = '\0';

    if (redirect_pending)
    {
        const char *device_id = net_lwip_get_device_id();
        if (device_id == NULL)
        {
            device_id = "unknown";
        }
        snprintf(redirect_url, sizeof(redirect_url),
                 "https://dashboard.tuodominio.it/devices/%s",
                 device_id);
    }

    snprintf(stream_buffer, sizeof(stream_buffer),
             "data: {\"status\":\"%s\",\"message\":\"%s\",\"epoch\":%lu,\"redirect\":\"%s\"}\n\n",
             status,
             current_progress.message,
             (unsigned long)progress_generation,
             redirect_pending ? redirect_url : "");

    return stream_buffer;
}

static void update_led(void)
{
    if (!provisioning_enabled)
    {
        led_rgb_set_pattern(LED_PATTERN_OFF);
        return;
    }

    switch (current_progress.status)
    {
    case PROV_STATUS_IDLE:
        led_rgb_set_pattern(LED_PATTERN_HTTP_READY);
        break;
    case PROV_STATUS_VALIDATING_CA:
        led_rgb_set_pattern(LED_PATTERN_BOOTSTRAP);
        break;
    case PROV_STATUS_BOOTSTRAP_CONNECTED:
        led_rgb_set_pattern(LED_PATTERN_BOOTSTRAP);
        break;
    case PROV_STATUS_CLAIM_WAIT:
        led_rgb_set_pattern(LED_PATTERN_CLAIM_WAIT);
        break;
    case PROV_STATUS_MQTT_CONNECTED:
        led_rgb_set_pattern(LED_PATTERN_FINAL_OK);
        break;
    case PROV_STATUS_DONE:
        led_rgb_set_pattern(LED_PATTERN_OFF);
        break;
    case PROV_STATUS_ERROR:
        led_rgb_set_pattern(LED_PATTERN_TLS_ERROR);
        break;
    default:
        led_rgb_set_pattern(LED_PATTERN_OFF);
        break;
    }
}

static const char *build_form_page(void)
{
    const char *device_id = net_lwip_get_device_id();
    if (device_id == NULL)
    {
        device_id = "unknown";
    }

    const char *host = (cached_blob_valid) ? cached_blob.mqtt_host : "";
    uint16_t port = (cached_blob_valid && cached_blob.mqtt_port != 0U) ? cached_blob.mqtt_port : NSAP_MQTT_PORT_SECURE;
    const char *bootstrap = (cached_blob_valid) ? cached_blob.claim_code : "";

    snprintf(http_form_buffer, sizeof(http_form_buffer),
             "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>NSAlarmPro Provisioning</title>"
             "<style>body{font-family:Arial;margin:2rem;}label{display:block;margin-top:1rem;}textarea{width:100%%;height:10rem;}"
             "input[type=text],input[type=password],input[type=number]{width:100%%;padding:0.5rem;}</style>"
             "<script>function startStream(){if(window.EventSource){var es=new EventSource('/provision/stream');"
             "es.onmessage=function(ev){handleUpdate(ev.data);};}else{setInterval(fetchUpdate,1500);} }"
             "async function fetchUpdate(){try{const r=await fetch('/provision/stream');const t=await r.text();handleUpdate(t);}catch(e){}}
             "function handleUpdate(payload){if(!payload)return;var data=payload;var idx=payload.indexOf('data:');if(idx>=0){data=payload.substring(idx+5);}"
             "try{var json=JSON.parse(data);}catch(e){return;}var status=document.getElementById('status');"
             "if(status){status.textContent=json.status+': '+json.message;}if(json.redirect&&json.redirect.length){setTimeout(function(){window.location.href=json.redirect;},2000);}}
             "document.addEventListener('DOMContentLoaded',startStream);</script></head><body>"
             "<h1>NSAlarmPro Provisioning</h1><p>Device ID: %s</p>"
             "<div id=\"status\">%s: %s</div>"
             "<form method=\"post\" action=\"/provision\">"
             "<label>Broker MQTT (FQDN)</label><input type=\"text\" name=\"host\" value=\"%s\" required>"
             "<label>Porta MQTTS</label><input type=\"number\" name=\"port\" value=\"%u\" min=\"1\" max=\"65535\" required>"
             "<label>Password bootstrap</label><input type=\"password\" name=\"bootstrap\" value=\"%s\" required>"
             "<label>Claim code</label><input type=\"text\" name=\"claim_code\" required>"
             "<label>CA PEM</label><textarea name=\"ca_pem\" placeholder=\"-----BEGIN CERTIFICATE-----\n...\"></textarea>"
             "<button type=\"submit\" style=\"margin-top:1.5rem;padding:0.75rem 2rem;\">Avvia provisioning</button>"
             "</form></body></html>",
             device_id,
             status_to_string(current_progress.status),
             current_progress.message,
             host,
             port,
             bootstrap);

    return http_form_buffer;
}

static const char *status_to_string(provisioning_status_t status)
{
    switch (status)
    {
    case PROV_STATUS_IDLE:
        return "IDLE";
    case PROV_STATUS_VALIDATING_CA:
        return "VALIDATING_CA";
    case PROV_STATUS_BOOTSTRAP_CONNECTED:
        return "BOOTSTRAP_CONNECTED";
    case PROV_STATUS_CLAIM_WAIT:
        return "CLAIM_WAIT";
    case PROV_STATUS_MQTT_CONNECTED:
        return "MQTT_CONNECTED";
    case PROV_STATUS_DONE:
        return "DONE";
    case PROV_STATUS_ERROR:
        return "ERROR";
    default:
        return "UNKNOWN";
    }
}

static const char *param_lookup(int count, char **param, char **value, const char *key)
{
    for (int i = 0; i < count; i++)
    {
        if (param[i] != NULL && value[i] != NULL && strcmp(param[i], key) == 0)
        {
            return value[i];
        }
    }
    return NULL;
}

static void url_decode_inplace(char *value)
{
    if (value == NULL)
    {
        return;
    }
    char *src = value;
    char *dst = value;
    while (*src != '\0')
    {
        if (*src == '+')
        {
            *dst++ = ' ';
            src++;
        }
        else if (*src == '%' && isxdigit((unsigned char)src[1]) && isxdigit((unsigned char)src[2]))
        {
            char hex[3] = {src[1], src[2], '\0'};
            *dst++ = (char)strtol(hex, NULL, 16);
            src += 3;
        }
        else
        {
            *dst++ = *src++;
        }
    }
    *dst = '\0';
}

static bool handle_provision_request(int count, char **param, char **value)
{
    const char *host_param = param_lookup(count, param, value, "host");
    const char *port_param = param_lookup(count, param, value, "port");
    const char *bootstrap_param = param_lookup(count, param, value, "bootstrap");
    const char *claim_param = param_lookup(count, param, value, "claim_code");
    const char *ca_param = param_lookup(count, param, value, "ca_pem");

    if (host_param == NULL || bootstrap_param == NULL || claim_param == NULL || ca_param == NULL)
    {
        http_prov_set_progress(PROV_STATUS_ERROR, "Parametri mancanti");
        return false;
    }

    char host_buf[64];
    char bootstrap_buf[64];
    char claim_buf[32];
    char ca_buf[sizeof(cached_blob.ca_cert) + 32U];

    strncpy(host_buf, host_param, sizeof(host_buf) - 1U);
    host_buf[sizeof(host_buf) - 1U] = '\0';
    strncpy(bootstrap_buf, bootstrap_param, sizeof(bootstrap_buf) - 1U);
    bootstrap_buf[sizeof(bootstrap_buf) - 1U] = '\0';
    strncpy(claim_buf, claim_param, sizeof(claim_buf) - 1U);
    claim_buf[sizeof(claim_buf) - 1U] = '\0';
    strncpy(ca_buf, ca_param, sizeof(ca_buf) - 1U);
    ca_buf[sizeof(ca_buf) - 1U] = '\0';

    url_decode_inplace(host_buf);
    url_decode_inplace(bootstrap_buf);
    url_decode_inplace(claim_buf);
    url_decode_inplace(ca_buf);

    if (host_buf[0] == '\0' || ca_buf[0] == '\0')
    {
        http_prov_set_progress(PROV_STATUS_ERROR, "Host o CA non validi");
        return false;
    }

    long port_long = (port_param != NULL) ? strtol(port_param, NULL, 10) : (long)NSAP_MQTT_PORT_SECURE;
    if (port_long <= 0 || port_long > 65535)
    {
        port_long = NSAP_MQTT_PORT_SECURE;
    }

    flash_store_blob_t blob;
    if (!flash_store_load(&blob))
    {
        memset(&blob, 0, sizeof(blob));
    }

    blob.provisioned = 0U;
    strncpy(blob.mqtt_host, host_buf, sizeof(blob.mqtt_host) - 1U);
    blob.mqtt_host[sizeof(blob.mqtt_host) - 1U] = '\0';
    blob.mqtt_port = (uint16_t)port_long;
    strncpy(blob.claim_code, bootstrap_buf, sizeof(blob.claim_code) - 1U);
    blob.claim_code[sizeof(blob.claim_code) - 1U] = '\0';
    strncpy(blob.mqtt_username, cached_blob.mqtt_username, sizeof(blob.mqtt_username) - 1U);
    blob.mqtt_username[sizeof(blob.mqtt_username) - 1U] = '\0';
    strncpy(blob.mqtt_password, cached_blob.mqtt_password, sizeof(blob.mqtt_password) - 1U);
    blob.mqtt_password[sizeof(blob.mqtt_password) - 1U] = '\0';
    size_t ca_len = strlen(ca_buf);
    if (ca_len > sizeof(blob.ca_cert))
    {
        ca_len = sizeof(blob.ca_cert);
    }
    memcpy(blob.ca_cert, ca_buf, ca_len);
    blob.ca_cert_len = (uint16_t)ca_len;

    if (!flash_store_save(&blob))
    {
        http_prov_set_progress(PROV_STATUS_ERROR, "Salvataggio Flash fallito");
        return false;
    }

    cached_blob = blob;
    cached_blob_valid = true;

    mqtt_cli_set_bootstrap(host_buf, (uint16_t)port_long, bootstrap_buf);
    mqtt_cli_set_claim(claim_buf);
    mqtt_cli_set_ca((const uint8_t *)ca_buf, (uint16_t)ca_len);

    claim_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    strncpy(ctx.host, host_buf, sizeof(ctx.host) - 1U);
    ctx.host[sizeof(ctx.host) - 1U] = '\0';
    ctx.port = (uint16_t)port_long;
    strncpy(ctx.bootstrap_password, bootstrap_buf, sizeof(ctx.bootstrap_password) - 1U);
    ctx.bootstrap_password[sizeof(ctx.bootstrap_password) - 1U] = '\0';
    strncpy(ctx.claim_code, claim_buf, sizeof(ctx.claim_code) - 1U);
    ctx.claim_code[sizeof(ctx.claim_code) - 1U] = '\0';
    if (ca_len > sizeof(ctx.ca_pem))
    {
        ca_len = sizeof(ctx.ca_pem);
    }
    memcpy(ctx.ca_pem, ca_buf, ca_len);
    ctx.ca_len = (uint16_t)ca_len;

    http_prov_set_progress(PROV_STATUS_VALIDATING_CA, "Validazione CA");
    claim_init(&ctx);
    if (!claim_run(&cached_blob))
    {
        http_prov_set_progress(PROV_STATUS_ERROR, "Claim fallito");
        return false;
    }

    schedule_shutdown();
    return true;
}

static void schedule_shutdown(void)
{
    shutdown_deadline_ms = HAL_GetTick() + NSAP_HTTP_OFF_DELAY_MS;
    shutdown_scheduled = true;
}
