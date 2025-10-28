// main/mqtt_client.c
// MQTT over TLS integration for the ESP32 alarm panel. The module connects to
// a managed broker using credentials defined in sdkconfig, publishes telemetry
// (state, zones, scenes) and listens for commands (arm/disarm, outputs, scenes).

#include "app_mqtt.h"
#include "sdkconfig.h"

#include <string.h>
#include <inttypes.h>
#include <strings.h>
#include <stdio.h>
#include <time.h>

#include "esp_check.h"
#include "esp_err.h"
#include "esp_event.h"
#include "esp_eth.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_mac.h"
#include "mqtt_client.h"
#include "nvs.h"


#include "alarm_core.h"
#include "device_identity.h"
#include "gpio_inputs.h"
#include "outputs.h"
#include "scenes.h"
#include "roster.h"
#include "audit_log.h"

#include "cJSON.h"

static uint8_t s_device_secret[DEVICE_SECRET_LEN];
static char    s_password_hex[DEVICE_SECRET_LEN*2 + 1];

extern const uint8_t certs_broker_ca_pem_start[] asm("_binary_broker_ca_pem_start");
extern const uint8_t certs_broker_ca_pem_end[]   asm("_binary_broker_ca_pem_end");

static const char *TAG = "cloud_mqtt";

static esp_mqtt_client_handle_t s_client = NULL;

static bool                     s_connected = false;
static bool                     s_config_initialized = false;
static char                     s_device_id[64] = {0};
static char                     s_mqtt_uri[96] = {0};
static char                     s_mqtt_client_id[64] = {0};
static char                     s_mqtt_user[64] = {0};
static char                     s_mqtt_pass[96] = {0};
static uint32_t                 s_mqtt_keepalive = CONFIG_APP_CLOUD_KEEPALIVE;
static char                     s_topic_state[128];
static char                     s_topic_zones[128];
static char                     s_topic_avail[128];
static char                     s_topic_scenes[128];
static char                     s_topic_cmd_base[128];
static char                     s_topic_cmd_sub[160];
static size_t                   s_cmd_base_len = 0;
static zone_mask_t              s_last_zone_mask;
static int                      s_last_zone_count = -1;
static bool                     s_secret_ready = false;

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────
static bool load_device_secret_hex(void)
{
    memset(s_device_secret, 0, sizeof(s_device_secret));
    memset(s_password_hex, 0, sizeof(s_password_hex));

    esp_err_t err = device_identity_get_secret(s_device_secret);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "Unable to load device secret: %s", esp_err_to_name(err));
        return false;
    }

    for (size_t i = 0; i < DEVICE_SECRET_LEN; ++i) {
        snprintf(&s_password_hex[i * 2], 3, "%02X", s_device_secret[i]);
    }
    return true;
}

static void build_device_id(void)
{
    const char *cfg = CONFIG_APP_CLOUD_DEVICE_ID;
    if (cfg && cfg[0] != '\0') {
        snprintf(s_device_id, sizeof(s_device_id), "%s", cfg);
        return;
    }

    uint8_t mac[6] = {0};
    ESP_ERROR_CHECK(esp_read_mac(mac, ESP_MAC_ETH));
    snprintf(s_device_id, sizeof(s_device_id), "%s%02X%02X%02X%02X",
             CONFIG_APP_CLOUD_CLIENT_ID_PREFIX,
             mac[2], mac[3], mac[4], mac[5]);
}

static void build_topics(void)
{
    const char *root = CONFIG_APP_CLOUD_TOPIC_ROOT;
    snprintf(s_topic_state, sizeof(s_topic_state), "%s/state/%s/status", root, s_device_id);
    snprintf(s_topic_zones, sizeof(s_topic_zones), "%s/state/%s/zones", root, s_device_id);
    snprintf(s_topic_avail, sizeof(s_topic_avail), "%s/state/%s/availability", root, s_device_id);
    snprintf(s_topic_scenes, sizeof(s_topic_scenes), "%s/state/%s/scenes", root, s_device_id);
    snprintf(s_topic_cmd_base, sizeof(s_topic_cmd_base), "%s/cmd/%s", root, s_device_id);
    snprintf(s_topic_cmd_sub, sizeof(s_topic_cmd_sub), "%s/#", s_topic_cmd_base);
    s_cmd_base_len = strlen(s_topic_cmd_base);
}

static void load_mqtt_config_from_nvs(void)
{
    const char *default_uri = CONFIG_APP_CLOUD_MQTT_URI;
    const char *default_user = CONFIG_APP_CLOUD_USERNAME[0] ? CONFIG_APP_CLOUD_USERNAME : s_device_id;
    const char *default_pass = CONFIG_APP_CLOUD_PASSWORD[0] ? CONFIG_APP_CLOUD_PASSWORD :
                              (s_secret_ready ? s_password_hex : "");

    strlcpy(s_mqtt_uri, default_uri, sizeof(s_mqtt_uri));
    strlcpy(s_mqtt_client_id, s_device_id, sizeof(s_mqtt_client_id));
    strlcpy(s_mqtt_user, default_user, sizeof(s_mqtt_user));
    strlcpy(s_mqtt_pass, default_pass, sizeof(s_mqtt_pass));
    s_mqtt_keepalive = CONFIG_APP_CLOUD_KEEPALIVE;

    nvs_handle_t nvs;
    esp_err_t err = nvs_open("sys", NVS_READONLY, &nvs);
    if (err != ESP_OK) {
        return;
    }

    size_t len = sizeof(s_mqtt_uri);
    err = nvs_get_str(nvs, "mq_uri", s_mqtt_uri, &len);
    if (err != ESP_OK) {
        strlcpy(s_mqtt_uri, default_uri, sizeof(s_mqtt_uri));
    }

    len = sizeof(s_mqtt_client_id);
    err = nvs_get_str(nvs, "mq_cid", s_mqtt_client_id, &len);
    if (err != ESP_OK || s_mqtt_client_id[0] == '\0') {
        strlcpy(s_mqtt_client_id, s_device_id, sizeof(s_mqtt_client_id));
    }

    len = sizeof(s_mqtt_user);
    err = nvs_get_str(nvs, "mq_user", s_mqtt_user, &len);
    if (err != ESP_OK || s_mqtt_user[0] == '\0') {
        strlcpy(s_mqtt_user, default_user, sizeof(s_mqtt_user));
    }

    len = sizeof(s_mqtt_pass);
    err = nvs_get_str(nvs, "mq_pass", s_mqtt_pass, &len);

    if (err != ESP_OK || s_mqtt_pass[0] == '\0') {
        strlcpy(s_mqtt_pass, default_pass, sizeof(s_mqtt_pass));
    }

    uint32_t keepalive = 0;
    err = nvs_get_u32(nvs, "mq_keep", &keepalive);
    if (err == ESP_OK && keepalive > 0) {
        s_mqtt_keepalive = keepalive;
    }

    nvs_close(nvs);
}

static void mqtt_prepare_configuration(void)
{
    build_device_id();
    s_secret_ready = load_device_secret_hex();
    build_topics();
    load_mqtt_config_from_nvs();
    s_config_initialized = true;
}

static inline const char* alarm_state_to_name(alarm_state_t st)
{
    switch (st) {
    case ALARM_DISARMED:     return "DISARMED";
    case ALARM_ARMED_HOME:   return "ARMED_HOME";
    case ALARM_ARMED_AWAY:   return "ARMED_AWAY";
    case ALARM_ARMED_NIGHT:  return "ARMED_NIGHT";
    case ALARM_ARMED_CUSTOM: return "ARMED_CUSTOM";
    case ALARM_ALARM:        return "ALARM";
    case ALARM_MAINTENANCE:  return "MAINT";
    default:                 return "UNKNOWN";
    }
}

static esp_err_t publish_raw(const char *topic, const char *payload, int qos, bool retain)
{
    if (!s_client) return ESP_ERR_INVALID_STATE;
    if (!topic || !payload) return ESP_ERR_INVALID_ARG;
    int msg_id = esp_mqtt_client_publish(s_client, topic, payload, 0, qos, retain);
    if (msg_id < 0) {
        ESP_LOGW(TAG, "Publish failed topic=%s", topic);
        return ESP_FAIL;
    }
    ESP_LOGD(TAG, "Publish topic=%s qos=%d retain=%d", topic, qos, retain);
    return ESP_OK;
}

static void publish_availability(const char *state)
{
    if (!state) return;
    publish_raw(s_topic_avail, state, CONFIG_APP_CLOUD_QOS_STATE, true);
}

static void ensure_timestamp(cJSON *root)
{
    if (!root) return;
    time_t now = time(NULL);
    cJSON_AddNumberToObject(root, "timestamp", (double)now);
}

// ─────────────────────────────────────────────────────────────────────────────
// Event handler MQTT
// Telemetry
// ─────────────────────────────────────────────────────────────────────────────
esp_err_t mqtt_publish_state(void)
{
    if (!s_client) return ESP_ERR_INVALID_STATE;

    alarm_state_t st = alarm_get_state();
    uint32_t exit_ms = 0, entry_ms = 0;
    int entry_zone = -1;
    bool exit_pending = alarm_exit_pending(&exit_ms);
    bool entry_pending = alarm_entry_pending(&entry_zone, &entry_ms);

    const char *state_name = alarm_state_to_name(st);
    if (entry_pending) {
        state_name = "PRE_DISARM";
    } else if (exit_pending && (st == ALARM_ARMED_HOME || st == ALARM_ARMED_AWAY ||
                                st == ALARM_ARMED_NIGHT || st == ALARM_ARMED_CUSTOM)) {
        state_name = "PRE_ARM";
    }

    uint16_t outputs_mask = 0;
    outputs_get_mask(&outputs_mask);
    zone_mask_t bypass_mask;
    alarm_get_bypass_mask(&bypass_mask);

    uint16_t gpioab = 0;
    inputs_read_all(&gpioab);
    bool tamper = inputs_tamper(gpioab);
    bool tamper_alarm = (alarm_last_alarm_was_tamper() && st == ALARM_ALARM);

    cJSON *root = cJSON_CreateObject();
    if (!root) return ESP_ERR_NO_MEM;

    uint16_t zones_total = roster_effective_zones(inputs_master_zone_count());
    zone_mask_limit(&bypass_mask, zones_total);
    char bypass_hex[ZONE_MASK_WORDS * 8u + 1u];
    zone_mask_to_hex(&bypass_mask, zones_total, bypass_hex, sizeof(bypass_hex));

    cJSON_AddStringToObject(root, "state", state_name);
    cJSON_AddNumberToObject(root, "zones_count", (double)zones_total);
    cJSON_AddNumberToObject(root, "outputs_mask", (double)outputs_mask);
    cJSON_AddStringToObject(root, "bypass_mask", bypass_hex);
    cJSON_AddNumberToObject(root, "bypass_mask_legacy", (double)zone_mask_to_u32(&bypass_mask));
    cJSON_AddItemToObject(root, "tamper", cJSON_CreateBool(tamper));
    cJSON_AddItemToObject(root, "tamper_alarm", cJSON_CreateBool(tamper_alarm));
    cJSON_AddNumberToObject(root, "exit_pending_ms", (double)exit_ms);
    cJSON_AddNumberToObject(root, "entry_pending_ms", (double)entry_ms);
    cJSON_AddNumberToObject(root, "entry_zone", (double)entry_zone);
    ensure_timestamp(root);

    char *payload = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!payload) return ESP_ERR_NO_MEM;

    esp_err_t err = publish_raw(s_topic_state, payload, CONFIG_APP_CLOUD_QOS_STATE, true);
    cJSON_free(payload);
    return err;
}

static esp_err_t publish_zones_internal(const zone_mask_t *mask, bool force)
{
    if (!s_client) return ESP_ERR_INVALID_STATE;
    uint16_t total = roster_effective_zones(inputs_master_zone_count());
    if (total > SCENES_MAX_ZONES) {
        total = SCENES_MAX_ZONES;
    }

    zone_mask_t limited;
    if (mask) {
        zone_mask_copy(&limited, mask);
    } else {
        zone_mask_clear(&limited);
    }
    zone_mask_limit(&limited, total);

    if (!force && zone_mask_equal(&limited, &s_last_zone_mask) && s_last_zone_count == (int)total) {
        return ESP_OK;
    }

    zone_mask_copy(&s_last_zone_mask, &limited);
    s_last_zone_count = (int)total;

    cJSON *root = cJSON_CreateObject();
    if (!root) return ESP_ERR_NO_MEM;

    char mask_hex[ZONE_MASK_WORDS * 8u + 1u];
    zone_mask_to_hex(&limited, total, mask_hex, sizeof(mask_hex));
    cJSON_AddStringToObject(root, "mask", mask_hex);
    cJSON_AddNumberToObject(root, "mask_legacy", (double)zone_mask_to_u32(&limited));
    ensure_timestamp(root);

    cJSON *arr = cJSON_AddArrayToObject(root, "zones");
    if (!arr) {
        cJSON_Delete(root);
        return ESP_ERR_NO_MEM;
    }
    for (int i = 0; i < total; ++i) {
        bool active = zone_mask_test(&limited, (uint16_t)i);
        cJSON_AddItemToArray(arr, cJSON_CreateBool(active));
    }

    char *payload = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!payload) return ESP_ERR_NO_MEM;

    esp_err_t err = publish_raw(s_topic_zones, payload, CONFIG_APP_CLOUD_QOS_STATE, false);
    cJSON_free(payload);
    return err;
}

esp_err_t mqtt_publish_zones(const zone_mask_t *mask)
{
    return publish_zones_internal(mask, false);
}

esp_err_t mqtt_publish_scenes(void)
{
    if (!s_client) return ESP_ERR_INVALID_STATE;

    zone_mask_t mask_home, mask_night, mask_custom, mask_active;
    scenes_get_mask(SCENE_HOME, &mask_home);
    scenes_get_mask(SCENE_NIGHT, &mask_night);
    scenes_get_mask(SCENE_CUSTOM, &mask_custom);
    scenes_get_active_mask(&mask_active);

    int ids[SCENES_MAX_ZONES];

    cJSON *root = cJSON_CreateObject();
    if (!root) return ESP_ERR_NO_MEM;
    uint16_t total = roster_effective_zones(inputs_master_zone_count());
    if (total > SCENES_MAX_ZONES) {
        total = SCENES_MAX_ZONES;
    }
    cJSON_AddNumberToObject(root, "zones_count", (double)total);
    zone_mask_limit(&mask_home, total);
    zone_mask_limit(&mask_night, total);
    zone_mask_limit(&mask_custom, total);
    zone_mask_limit(&mask_active, total);

    char home_hex[ZONE_MASK_WORDS * 8u + 1u];
    char night_hex[ZONE_MASK_WORDS * 8u + 1u];
    char custom_hex[ZONE_MASK_WORDS * 8u + 1u];
    char active_hex[ZONE_MASK_WORDS * 8u + 1u];
    zone_mask_to_hex(&mask_home, total, home_hex, sizeof(home_hex));
    zone_mask_to_hex(&mask_night, total, night_hex, sizeof(night_hex));
    zone_mask_to_hex(&mask_custom, total, custom_hex, sizeof(custom_hex));
    zone_mask_to_hex(&mask_active, total, active_hex, sizeof(active_hex));

    cJSON_AddStringToObject(root, "home", home_hex);
    cJSON_AddStringToObject(root, "night", night_hex);
    cJSON_AddStringToObject(root, "custom", custom_hex);
    cJSON_AddStringToObject(root, "active", active_hex);
    cJSON_AddNumberToObject(root, "home_legacy",   (double)zone_mask_to_u32(&mask_home));
    cJSON_AddNumberToObject(root, "night_legacy",  (double)zone_mask_to_u32(&mask_night));
    cJSON_AddNumberToObject(root, "custom_legacy", (double)zone_mask_to_u32(&mask_custom));
    cJSON_AddNumberToObject(root, "active_legacy", (double)zone_mask_to_u32(&mask_active));
    ensure_timestamp(root);

    cJSON *arr_home = cJSON_AddArrayToObject(root, "home");
    cJSON *arr_night = cJSON_AddArrayToObject(root, "night");
    cJSON *arr_custom = cJSON_AddArrayToObject(root, "custom");

    if (!arr_home || !arr_night || !arr_custom) {
        cJSON_Delete(root);
        return ESP_ERR_NO_MEM;
    }

    int cnt = scenes_mask_to_ids(&mask_home, ids, total, total);
    for (int i = 0; i < cnt; ++i) cJSON_AddItemToArray(arr_home, cJSON_CreateNumber(ids[i]));
    cnt = scenes_mask_to_ids(&mask_night, ids, total, total);
    for (int i = 0; i < cnt; ++i) cJSON_AddItemToArray(arr_night, cJSON_CreateNumber(ids[i]));
    cnt = scenes_mask_to_ids(&mask_custom, ids, total, total);
    for (int i = 0; i < cnt; ++i) cJSON_AddItemToArray(arr_custom, cJSON_CreateNumber(ids[i]));

    char *payload = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!payload) return ESP_ERR_NO_MEM;

    esp_err_t err = publish_raw(s_topic_scenes, payload, CONFIG_APP_CLOUD_QOS_STATE, true);
    cJSON_free(payload);
    return err;
}

// ─────────────────────────────────────────────────────────────────────────────
// Command handling
// ─────────────────────────────────────────────────────────────────────────────
static void handle_arm_command(const char *payload)
{
    char mode_buf[16];
    strncpy(mode_buf, "away", sizeof(mode_buf) - 1);
    mode_buf[sizeof(mode_buf) - 1] = '\0';
    cJSON *root = NULL;
    if (payload && payload[0]) {
        root = cJSON_Parse(payload);
    }
    zone_mask_t requested_bypass;
    bool bypass_present = false;
    if (root) {
        cJSON *m = cJSON_GetObjectItemCaseSensitive(root, "mode");
        if (cJSON_IsString(m) && m->valuestring) {
            strncpy(mode_buf, m->valuestring, sizeof(mode_buf) - 1);
            mode_buf[sizeof(mode_buf) - 1] = '\0';
        }
        cJSON *bp = cJSON_GetObjectItemCaseSensitive(root, "bypass_mask");
        if (cJSON_IsString(bp) && bp->valuestring) {
            bypass_present = zone_mask_from_hex(&requested_bypass, bp->valuestring);
        } else if (cJSON_IsNumber(bp)) {
            zone_mask_from_u32(&requested_bypass, (uint32_t)bp->valuedouble);
            bypass_present = true;
        }
    }
    uint16_t total = roster_effective_zones(inputs_master_zone_count());
    if (total > SCENES_MAX_ZONES) {
        total = SCENES_MAX_ZONES;
    }
    if (bypass_present) {
        zone_mask_limit(&requested_bypass, total);
        alarm_set_bypass_mask(&requested_bypass);
    }

    zone_mask_t scene_mask;
    scenes_mask_all(total, &scene_mask);
    alarm_state_t target = ALARM_ARMED_AWAY;
    if (strcasecmp(mode_buf, "home") == 0) {
        target = ALARM_ARMED_HOME;
        scenes_get_mask(SCENE_HOME, &scene_mask);
    } else if (strcasecmp(mode_buf, "night") == 0) {
        target = ALARM_ARMED_NIGHT;
        scenes_get_mask(SCENE_NIGHT, &scene_mask);
    } else if (strcasecmp(mode_buf, "custom") == 0) {
        target = ALARM_ARMED_CUSTOM;
        scenes_get_mask(SCENE_CUSTOM, &scene_mask);
    }
    zone_mask_limit(&scene_mask, total);
    scenes_set_active_mask(&scene_mask);

    switch (target) {
    case ALARM_ARMED_HOME:   alarm_arm_home(); break;
    case ALARM_ARMED_AWAY:   alarm_arm_away(); break;
    case ALARM_ARMED_NIGHT:  alarm_arm_night(); break;
    case ALARM_ARMED_CUSTOM: alarm_arm_custom(); break;
    default: break;
    }

    char scene_desc[48];
    zone_mask_format_brief(&scene_mask, total, 4, scene_desc, sizeof(scene_desc));
    char note[64];
    size_t avail = sizeof(note);
    if (avail > 0) {
        const size_t prefix = 12; // strlen("mode=") + strlen(" scene=")
        if (avail > 1) {
            avail -= 1;
        }
        if (avail > prefix) {
            avail -= prefix;
        } else {
            avail = 0;
        }
    }
    size_t mode_len = strnlen(mode_buf, sizeof(mode_buf) - 1);
    if (mode_len > avail) {
        mode_len = avail;
    }
    size_t scene_len = 0;
    if (avail > mode_len) {
        size_t scene_avail = avail - mode_len;
        size_t scene_cap = sizeof(scene_desc) - 1;
        if (scene_avail < scene_cap) {
            scene_cap = scene_avail;
        }
        scene_len = strnlen(scene_desc, scene_cap);
    }
    snprintf(note, sizeof(note), "mode=%.*s scene=%.*s", (int)mode_len, mode_buf, (int)scene_len, scene_desc);
    audit_append("alarm_arm", "mqtt", 1, note);

    if (root) cJSON_Delete(root);
    mqtt_publish_state();
}

static void handle_disarm_command(void)
{
    alarm_state_t prev_state = alarm_get_state();
    zone_mask_t scene_mask;
    scenes_get_active_mask(&scene_mask);
    uint16_t total = roster_effective_zones(inputs_master_zone_count());
    if (total > SCENES_MAX_ZONES) {
        total = SCENES_MAX_ZONES;
    }
    zone_mask_limit(&scene_mask, total);
    char scene_desc[48];
    zone_mask_format_brief(&scene_mask, total, 4, scene_desc, sizeof(scene_desc));
    const char *prev_label = alarm_state_name(prev_state);
    char note[64];
    size_t avail = sizeof(note);
    if (avail > 0) {
        const size_t prefix = 12; // strlen("prev=") + strlen(" scene=")
        if (avail > 1) {
            avail -= 1;
        }
        if (avail > prefix) {
            avail -= prefix;
        } else {
            avail = 0;
        }
    }
    size_t prev_len = strnlen(prev_label, avail);
    size_t scene_len = 0;
    if (avail > prev_len) {
        size_t scene_avail = avail - prev_len;
        size_t scene_cap = sizeof(scene_desc) - 1;
        if (scene_avail < scene_cap) {
            scene_cap = scene_avail;
        }
        scene_len = strnlen(scene_desc, scene_cap);
    }
    snprintf(note, sizeof(note), "prev=%.*s scene=%.*s", (int)prev_len, prev_label, (int)scene_len, scene_desc);
    alarm_disarm();
    audit_append("alarm_disarm", "mqtt", 1, note);
    mqtt_publish_state();
}

static void handle_outputs_command(const char *payload)
{
    if (!payload || !payload[0]) return;
    cJSON *root = cJSON_Parse(payload);
    if (!root) return;

    cJSON *relay = cJSON_GetObjectItemCaseSensitive(root, "relay");
    cJSON *ls    = cJSON_GetObjectItemCaseSensitive(root, "ls");
    cJSON *lm    = cJSON_GetObjectItemCaseSensitive(root, "lm");
    if (cJSON_IsNumber(relay)) outputs_siren(relay->valuedouble > 0.5);
    if (cJSON_IsNumber(ls))    outputs_led_state(ls->valuedouble > 0.5);
    if (cJSON_IsNumber(lm))    outputs_led_maint(lm->valuedouble > 0.5);

    cJSON_Delete(root);
    mqtt_publish_state();
}

static void handle_scenes_set(const char *payload)
{
    if (!payload || !payload[0]) return;
    cJSON *root = cJSON_Parse(payload);
    if (!root) return;

    cJSON *scene = cJSON_GetObjectItemCaseSensitive(root, "scene");
    cJSON *zones = cJSON_GetObjectItemCaseSensitive(root, "zones");

    if (cJSON_IsString(scene) && cJSON_IsArray(zones)) {
        int ids[16];
        int count = 0;
        cJSON *item = NULL;
        cJSON_ArrayForEach(item, zones) {
            if (cJSON_IsNumber(item) && count < 16) {
                ids[count++] = (int)item->valuedouble;
            }
        }
        zone_mask_t mask;
        scenes_ids_to_mask(ids, count, &mask);
        scene_t sc = SCENE_CUSTOM;
        if (strcasecmp(scene->valuestring, "home") == 0) sc = SCENE_HOME;
        else if (strcasecmp(scene->valuestring, "night") == 0) sc = SCENE_NIGHT;
        if (scenes_set_mask(sc, &mask) == ESP_OK) {
            mqtt_publish_scenes();
        } else {
            ESP_LOGW(TAG, "Scene set failed (%s)", scene->valuestring);
        }
    }

    cJSON_Delete(root);
}

static void handle_bypass_set(const char *payload)
{
    if (!payload || !payload[0]) return;
    cJSON *root = cJSON_Parse(payload);
    if (!root) return;

    cJSON *mask = cJSON_GetObjectItemCaseSensitive(root, "mask");
    zone_mask_t bits;
    bool ok = false;
    if (cJSON_IsString(mask) && mask->valuestring) {
        ok = zone_mask_from_hex(&bits, mask->valuestring);
    } else if (cJSON_IsNumber(mask)) {
        zone_mask_from_u32(&bits, (uint32_t)mask->valuedouble);
        ok = true;
    }
    if (ok) {
        uint16_t total = roster_effective_zones(inputs_master_zone_count());
        if (total > SCENES_MAX_ZONES) {
            total = SCENES_MAX_ZONES;
        }
        zone_mask_limit(&bits, total);
        alarm_set_bypass_mask(&bits);
        mqtt_publish_state();
    }

    cJSON_Delete(root);
}

static void handle_command(const char *topic, const char *payload)
{
    if (!topic) return;
    if (strncmp(topic, s_topic_cmd_base, s_cmd_base_len) != 0) return;
    const char *suffix = topic + s_cmd_base_len;
    if (*suffix == '/') ++suffix;

    ESP_LOGI(TAG, "CMD %s", suffix);

    if (strcmp(suffix, "arm") == 0) {
        handle_arm_command(payload);
    } else if (strcmp(suffix, "disarm") == 0) {
        handle_disarm_command();
    } else if (strcmp(suffix, "outputs/set") == 0) {
        handle_outputs_command(payload);
    } else if (strcmp(suffix, "scenes/set") == 0) {
        handle_scenes_set(payload);
    } else if (strcmp(suffix, "scenes/get") == 0) {
        mqtt_publish_scenes();
    } else if (strcmp(suffix, "status/get") == 0) {
        mqtt_publish_state();
        publish_zones_internal(&s_last_zone_mask, true);
    } else if (strcmp(suffix, "bypass/set") == 0) {
        handle_bypass_set(payload);
    } else {
        ESP_LOGW(TAG, "Unhandled command topic=%s", suffix);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MQTT event handler
// ─────────────────────────────────────────────────────────────────────────────
static void mqtt_event_handler(void *handler_args, esp_event_base_t base, int32_t event_id, void *event_data)
{
    esp_mqtt_event_handle_t e = (esp_mqtt_event_handle_t)event_data;
    switch ((esp_mqtt_event_id_t)event_id) {
    case MQTT_EVENT_CONNECTED:
        s_connected = true;
        ESP_LOGI(TAG, "MQTT connected");
        publish_availability("online");
        esp_mqtt_client_subscribe(s_client, s_topic_cmd_sub, CONFIG_APP_CLOUD_QOS_COMMANDS);
        mqtt_publish_state();
        publish_zones_internal(&s_last_zone_mask, true);
        mqtt_publish_scenes();
        break;
    case MQTT_EVENT_DISCONNECTED:
        s_connected = false;
        ESP_LOGW(TAG, "MQTT disconnected");
        break;
    case MQTT_EVENT_DATA: {
        if (!e->topic || !e->data) break;
        char topic[160];
        size_t tlen = (size_t)e->topic_len;
        if (tlen >= sizeof(topic)) tlen = sizeof(topic) - 1;
        memcpy(topic, e->topic, tlen);
        topic[tlen] = '\0';

        char data[256];
        size_t dlen = (size_t)e->data_len;
        if (dlen >= sizeof(data)) dlen = sizeof(data) - 1;
        memcpy(data, e->data, dlen);
        data[dlen] = '\0';

        handle_command(topic, data);
        break;
    }
    case MQTT_EVENT_ERROR:
        ESP_LOGE(TAG, "MQTT error");
        break;
    default:
        break;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────
esp_err_t mqtt_start(void)
{
    if (s_client) return ESP_OK;

    if (!s_config_initialized) {
        mqtt_prepare_configuration();
    }


    esp_mqtt_client_config_t cfg = {
        .broker.address.uri = s_mqtt_uri,
        .broker.verification.certificate = (const char *)certs_broker_ca_pem_start,
        .broker.verification.certificate_len = (size_t)(certs_broker_ca_pem_end - certs_broker_ca_pem_start),
        .credentials = {
            .client_id = s_mqtt_client_id,
            .username = s_mqtt_user[0] ? s_mqtt_user : NULL,
            .authentication.password = s_mqtt_pass[0] ? s_mqtt_pass : NULL,
        },
        .session = {
            .keepalive = (uint16_t)s_mqtt_keepalive,
            .last_will = {
                .topic = s_topic_avail,
                .msg = "offline",
                .msg_len = 7,
                .qos = CONFIG_APP_CLOUD_QOS_STATE,
                .retain = true,
            },
        },
        .network = {
            .disable_auto_reconnect = false,
        },
    };

    s_client = esp_mqtt_client_init(&cfg);
    ESP_RETURN_ON_FALSE(s_client != NULL, ESP_ERR_NO_MEM, TAG, "mqtt init");

    ESP_RETURN_ON_ERROR(esp_mqtt_client_register_event(s_client, ESP_EVENT_ANY_ID, mqtt_event_handler, NULL),
                        TAG, "register evt");

    ESP_RETURN_ON_ERROR(esp_mqtt_client_start(s_client), TAG, "start");
    ESP_LOGI(TAG, "MQTT client started (device_id=%s)", s_device_id);

    // Initial availability is offline until we receive MQTT_EVENT_CONNECTED
    publish_availability("offline");
    return ESP_OK;
}


esp_err_t mqtt_stop(void)
{
    if (!s_client) {
        s_connected = false;
        s_config_initialized = false;
        return ESP_OK;
    }

    esp_err_t stop_err = esp_mqtt_client_stop(s_client);
    if (stop_err != ESP_OK) {
        ESP_LOGE(TAG, "MQTT client stop failed: %s", esp_err_to_name(stop_err));
    }

    esp_err_t destroy_err = esp_mqtt_client_destroy(s_client);
    if (destroy_err != ESP_OK) {
        ESP_LOGE(TAG, "MQTT client destroy failed: %s", esp_err_to_name(destroy_err));
    }

    s_client = NULL;
    s_connected = false;
    s_config_initialized = false;

    if (stop_err != ESP_OK) {
        return stop_err;
    }
    return destroy_err;
}

esp_err_t mqtt_reload_config(void)
{
    esp_err_t err = mqtt_stop();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "MQTT reload failed to stop client: %s", esp_err_to_name(err));
        return err;
    }

    mqtt_prepare_configuration();

    err = mqtt_start();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "MQTT reload failed to start client: %s", esp_err_to_name(err));
        return err;
    }

    ESP_LOGI(TAG, "MQTT client configuration reloaded");
    return ESP_OK;
}