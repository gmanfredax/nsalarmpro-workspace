#include "zones.h"
#include "adc_frontend.h"
#include "flash_store.h"
#include "cmsis_os.h"
#include "mqtt_cli.h"
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>

static zone_config_t zone_config[NSAP_MAX_ZONES];
static zone_snapshot_t zone_snapshot[NSAP_MAX_ZONES];
static uint32_t last_publish_tick;

static zone_state_t evaluate_zone(uint8_t index, const adc_sample_t *sample);
static void publish_zone_state(uint8_t index, zone_state_t state);
static const char *zone_mode_to_string(zone_mode_t mode);
static const char *zone_profile_to_string(zone_profile_t profile);
static bool zone_mode_from_string(const char *value, zone_mode_t *mode);
static bool zone_profile_from_string(const char *value, zone_profile_t *profile);
static void apply_wiring_defaults(uint8_t index, zone_mode_t mode);
static const char *skip_ws(const char *ptr);
static const char *json_find_value(const char *json, const char *key);
static bool json_get_str_local(const char *json, const char *key, char *out, size_t out_len);
static bool json_get_int_local(const char *json, const char *key, int *value);
static bool json_get_bool_local(const char *json, const char *key, bool *value);

void zones_init(void)
{
    for (uint8_t i = 0; i < NSAP_MAX_ZONES; i++)
    {
        zone_config[i].profile = ZONE_PROFILE_INSTANT;
        zone_config[i].wiring_mode = ZONE_MODE_EOL;
        zone_config[i].threshold_open_pct = 70.0f;
        zone_config[i].threshold_tamper_pct = 85.0f;
        zone_config[i].threshold_short_pct = 10.0f;
        zone_config[i].auto_exclude_counter = 0;
        zone_config[i].bypassed = false;
        zone_config[i].debounce_ms = 150U;
        zone_config[i].auto_exclude_enabled = false;
        zone_snapshot[i].id = i;
        zone_snapshot[i].profile = zone_config[i].profile;
        zone_snapshot[i].state = ZONE_STATE_OK;
        zone_snapshot[i].wiring_mode = zone_config[i].wiring_mode;
        zone_snapshot[i].threshold_open_pct = zone_config[i].threshold_open_pct;
        zone_snapshot[i].threshold_tamper_pct = zone_config[i].threshold_tamper_pct;
        zone_snapshot[i].threshold_short_pct = zone_config[i].threshold_short_pct;
        zone_snapshot[i].ratio = 0.0f;
        zone_snapshot[i].voltage_mv = 0.0f;
        zone_snapshot[i].updated_at = 0;
        zone_snapshot[i].source_channel = i;
        zone_snapshot[i].debounce_ms = zone_config[i].debounce_ms;
        zone_snapshot[i].bypassed = zone_config[i].bypassed;
        zone_snapshot[i].auto_exclude_enabled = zone_config[i].auto_exclude_enabled;
    }
    zones_load_config();
    last_publish_tick = 0;
}

void zones_load_config(void)
{
    flash_store_blob_t blob;
    if (flash_store_load(&blob))
    {
        for (uint8_t i = 0; i < NSAP_MAX_ZONES; i++)
        {
            zone_config[i] = blob.zone_cfg[i];
            zone_snapshot[i].profile = zone_config[i].profile;
            zone_snapshot[i].wiring_mode = zone_config[i].wiring_mode;
            zone_snapshot[i].threshold_open_pct = zone_config[i].threshold_open_pct;
            zone_snapshot[i].threshold_tamper_pct = zone_config[i].threshold_tamper_pct;
            zone_snapshot[i].threshold_short_pct = zone_config[i].threshold_short_pct;
            zone_snapshot[i].debounce_ms = zone_config[i].debounce_ms;
            zone_snapshot[i].bypassed = zone_config[i].bypassed;
            zone_snapshot[i].auto_exclude_enabled = zone_config[i].auto_exclude_enabled;
        }
    }
}

void zones_save_config(void)
{
    flash_store_blob_t blob;
    if (!flash_store_load(&blob))
    {
        memset(&blob, 0, sizeof(blob));
    }
    for (uint8_t i = 0; i < NSAP_MAX_ZONES; i++)
    {
        blob.zone_cfg[i] = zone_config[i];
    }
    flash_store_save(&blob);
}

void zones_process(void)
{
    for (uint8_t i = 0; i < NSAP_MAX_ZONES; i++)
    {
        adc_sample_t sample;
        if (adc_frontend_get_zone(i, &sample))
        {
            zone_state_t state = evaluate_zone(i, &sample);
            if (state != zone_snapshot[i].state)
            {
                zone_snapshot[i].state = state;
                publish_zone_state(i, state);
            }
            zone_snapshot[i].ratio = sample.ratio * 100.0f;
            zone_snapshot[i].voltage_mv = sample.value_mv;
            zone_snapshot[i].updated_at = xTaskGetTickCount();
            zone_snapshot[i].bypassed = zone_config[i].bypassed;
            zone_snapshot[i].auto_exclude_enabled = zone_config[i].auto_exclude_enabled;
            zone_snapshot[i].wiring_mode = zone_config[i].wiring_mode;
            zone_snapshot[i].debounce_ms = zone_config[i].debounce_ms;
        }
        else
        {
            zone_snapshot[i].state = ZONE_STATE_FAULT;
            zone_snapshot[i].updated_at = xTaskGetTickCount();
            zone_snapshot[i].bypassed = zone_config[i].bypassed;
            zone_snapshot[i].auto_exclude_enabled = zone_config[i].auto_exclude_enabled;
            zone_snapshot[i].wiring_mode = zone_config[i].wiring_mode;
            zone_snapshot[i].debounce_ms = zone_config[i].debounce_ms;
        }
    }
    if ((xTaskGetTickCount() - last_publish_tick) > pdMS_TO_TICKS(1000))
    {
        publish_zone_state(0xFF, ZONE_STATE_OK);
        last_publish_tick = xTaskGetTickCount();
    }
}

static zone_state_t evaluate_zone(uint8_t index, const adc_sample_t *sample)
{
    zone_config_t *cfg = &zone_config[index];
    float pct = sample->ratio * 100.0f;
    if (cfg->bypassed || cfg->profile == ZONE_PROFILE_EXCLUDED)
    {
        return ZONE_STATE_OK;
    }
    if (pct <= cfg->threshold_short_pct)
    {
        if (cfg->auto_exclude_enabled)
        {
            cfg->auto_exclude_counter++;
            if (cfg->auto_exclude_counter > 3)
            {
                cfg->bypassed = true;
                zone_snapshot[index].bypassed = true;
            }
        }
        return ZONE_STATE_SHORT;
    }
    if (pct >= cfg->threshold_tamper_pct)
    {
        return ZONE_STATE_TAMPER2;
    }
    if (pct >= cfg->threshold_open_pct)
    {
        if (cfg->profile == ZONE_PROFILE_DELAYED)
        {
            if (zone_snapshot[index].state != ZONE_STATE_OPEN)
            {
                zone_snapshot[index].updated_at = xTaskGetTickCount();
                return zone_snapshot[index].state;
            }
        }
        return ZONE_STATE_OPEN;
    }
    cfg->auto_exclude_counter = 0;
    return ZONE_STATE_OK;
}

static void publish_zone_state(uint8_t index, zone_state_t state)
{
    char payload[256];
    if (index == 0xFF)
    {
        snprintf(payload, sizeof(payload), "{\"ts\":%lu}", xTaskGetTickCount());
        mqtt_cli_publish_event("telemetry/zones", payload, 0, false);
        return;
    }
    snprintf(payload, sizeof(payload),
             "{\"id\":%u,\"state\":%u,\"profile\":%u,\"ratio\":%.2f}",
             index, state, zone_snapshot[index].profile, zone_snapshot[index].ratio);
    mqtt_cli_publish_event("zone", payload, 1, false);
}

bool zones_get_snapshot(uint8_t index, zone_snapshot_t *snapshot)
{
    if (index >= NSAP_MAX_ZONES || snapshot == NULL)
    {
        return false;
    }
    *snapshot = zone_snapshot[index];
    return true;
}

void zones_set_profile(uint8_t index, zone_profile_t profile)
{
    if (index >= NSAP_MAX_ZONES)
    {
        return;
    }
    zone_config[index].profile = profile;
    zone_config[index].auto_exclude_enabled = (profile == ZONE_PROFILE_AUTO_EXCLUDE);
    zone_snapshot[index].profile = profile;
    zone_snapshot[index].auto_exclude_enabled = zone_config[index].auto_exclude_enabled;
}

void zones_set_bypass(uint8_t index, bool bypass)
{
    if (index >= NSAP_MAX_ZONES)
    {
        return;
    }
    zone_config[index].bypassed = bypass;
    zone_snapshot[index].bypassed = bypass;
}

void zones_set_thresholds(uint8_t index, float open_pct, float tamper_pct, float short_pct)
{
    if (index >= NSAP_MAX_ZONES)
    {
        return;
    }
    zone_config[index].threshold_open_pct = open_pct;
    zone_config[index].threshold_tamper_pct = tamper_pct;
    zone_config[index].threshold_short_pct = short_pct;
    zone_snapshot[index].threshold_open_pct = open_pct;
    zone_snapshot[index].threshold_tamper_pct = tamper_pct;
    zone_snapshot[index].threshold_short_pct = short_pct;
}

bool zones_bypass_handle_json(const char *json, int len)
{
    (void)len;
    if (json == NULL)
    {
        return false;
    }

    int zone_id = 0;
    bool enable = false;
    if (!json_get_int_local(json, "zone_id", &zone_id) ||
        !json_get_bool_local(json, "enable", &enable))
    {
        return false;
    }

    if (zone_id < 1 || zone_id > NSAP_MAX_ZONES)
    {
        return false;
    }

    uint8_t index = (uint8_t)(zone_id - 1);
    zones_set_bypass(index, enable);
    zones_save_config();

    char payload[96];
    snprintf(payload, sizeof(payload), "{\"zone_id\":%d}", zone_id);
    mqtt_cli_publish_event(enable ? "zone_bypass_on" : "zone_bypass_off", payload, 1, false);

    return true;
}

bool zones_config_handle_json(const char *json, int len)
{
    (void)len;
    if (json == NULL)
    {
        return false;
    }

    int zone_id = 0;
    char mode_str[16];
    char profile_str[24];
    zone_mode_t wiring = ZONE_MODE_EOL;
    zone_profile_t profile = ZONE_PROFILE_INSTANT;

    if (!json_get_int_local(json, "id", &zone_id) ||
        !json_get_str_local(json, "mode", mode_str, sizeof(mode_str)) ||
        !json_get_str_local(json, "profile", profile_str, sizeof(profile_str)))
    {
        return false;
    }

    if (!zone_mode_from_string(mode_str, &wiring) ||
        !zone_profile_from_string(profile_str, &profile))
    {
        return false;
    }

    if (zone_id < 1 || zone_id > NSAP_MAX_ZONES)
    {
        return false;
    }

    uint8_t index = (uint8_t)(zone_id - 1);

    int debounce_ms = (int)zone_config[index].debounce_ms;
    (void)json_get_int_local(json, "debounce_ms", &debounce_ms);
    if (debounce_ms < 0)
    {
        debounce_ms = 0;
    }

    bool auto_excl = zone_config[index].auto_exclude_enabled;
    (void)json_get_bool_local(json, "auto_excl_on", &auto_excl);

    if (zone_config[index].wiring_mode != wiring)
    {
        apply_wiring_defaults(index, wiring);
    }
    zone_config[index].wiring_mode = wiring;
    zone_config[index].profile = profile;
    zone_config[index].debounce_ms = (uint16_t)debounce_ms;
    zone_config[index].auto_exclude_enabled = auto_excl;
    zone_config[index].auto_exclude_counter = 0U;
    zone_snapshot[index].wiring_mode = wiring;
    zone_snapshot[index].profile = profile;
    zone_snapshot[index].debounce_ms = (uint16_t)debounce_ms;
    zone_snapshot[index].auto_exclude_enabled = auto_excl;
    zone_snapshot[index].threshold_open_pct = zone_config[index].threshold_open_pct;
    zone_snapshot[index].threshold_tamper_pct = zone_config[index].threshold_tamper_pct;
    zone_snapshot[index].threshold_short_pct = zone_config[index].threshold_short_pct;

    zones_save_config();

    const char *mode_out = zone_mode_to_string(wiring);
    const char *profile_out = zone_profile_to_string(profile);
    char payload[160];
    snprintf(payload, sizeof(payload),
             "{\"zone_id\":%d,\"mode\":\"%s\",\"profile\":\"%s\",\"debounce_ms\":%d,\"auto_excl_on\":%s}",
             zone_id,
             mode_out != NULL ? mode_out : "EOL",
             profile_out != NULL ? profile_out : "istantanea",
             debounce_ms,
             auto_excl ? "true" : "false");
    mqtt_cli_publish_event("zone_config_updated", payload, 1, false);

    return true;
}

static const char *zone_mode_to_string(zone_mode_t mode)
{
    switch (mode)
    {
    case ZONE_MODE_EOL:
        return "EOL";
    case ZONE_MODE_2EOL:
        return "2EOL";
    case ZONE_MODE_3EOL:
        return "3EOL";
    default:
        return NULL;
    }
}

static const char *zone_profile_to_string(zone_profile_t profile)
{
    switch (profile)
    {
    case ZONE_PROFILE_INSTANT:
        return "istantanea";
    case ZONE_PROFILE_DELAYED:
        return "ritardata";
    case ZONE_PROFILE_EXCLUDED:
        return "esclusa";
    case ZONE_PROFILE_AUTO_EXCLUDE:
        return "auto_esclusione";
    default:
        return NULL;
    }
}

static bool zone_mode_from_string(const char *value, zone_mode_t *mode)
{
    if (value == NULL || mode == NULL)
    {
        return false;
    }
    if (strcmp(value, "EOL") == 0)
    {
        *mode = ZONE_MODE_EOL;
        return true;
    }
    if (strcmp(value, "2EOL") == 0)
    {
        *mode = ZONE_MODE_2EOL;
        return true;
    }
    if (strcmp(value, "3EOL") == 0)
    {
        *mode = ZONE_MODE_3EOL;
        return true;
    }
    return false;
}

static bool zone_profile_from_string(const char *value, zone_profile_t *profile)
{
    if (value == NULL || profile == NULL)
    {
        return false;
    }
    if (strcmp(value, "istantanea") == 0)
    {
        *profile = ZONE_PROFILE_INSTANT;
        return true;
    }
    if (strcmp(value, "ritardata") == 0)
    {
        *profile = ZONE_PROFILE_DELAYED;
        return true;
    }
    if (strcmp(value, "esclusa") == 0)
    {
        *profile = ZONE_PROFILE_EXCLUDED;
        return true;
    }
    if (strcmp(value, "auto_esclusione") == 0)
    {
        *profile = ZONE_PROFILE_AUTO_EXCLUDE;
        return true;
    }
    return false;
}

static void apply_wiring_defaults(uint8_t index, zone_mode_t mode)
{
    if (index >= NSAP_MAX_ZONES)
    {
        return;
    }
    float open_pct = zone_config[index].threshold_open_pct;
    float tamper_pct = zone_config[index].threshold_tamper_pct;
    float short_pct = zone_config[index].threshold_short_pct;

    switch (mode)
    {
    case ZONE_MODE_EOL:
        open_pct = 70.0f;
        tamper_pct = 85.0f;
        short_pct = 10.0f;
        break;
    case ZONE_MODE_2EOL:
        open_pct = 65.0f;
        tamper_pct = 80.0f;
        short_pct = 8.0f;
        break;
    case ZONE_MODE_3EOL:
        open_pct = 55.0f;
        tamper_pct = 75.0f;
        short_pct = 6.0f;
        break;
    default:
        break;
    }

    zones_set_thresholds(index, open_pct, tamper_pct, short_pct);
}

static const char *skip_ws(const char *ptr)
{
    while (ptr != NULL && *ptr != '\0' && isspace((unsigned char)*ptr))
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
    char pattern[32];
    int written = snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    if (written <= 0 || (size_t)written >= sizeof(pattern))
    {
        return NULL;
    }
    const char *pos = json;
    while ((pos = strstr(pos, pattern)) != NULL)
    {
        pos += written;
        pos = skip_ws(pos);
        if (pos == NULL || *pos != ':')
        {
            continue;
        }
        pos++;
        pos = skip_ws(pos);
        return pos;
    }
    return NULL;
}

static bool json_get_str_local(const char *json, const char *key, char *out, size_t out_len)
{
    if (json == NULL || key == NULL || out == NULL || out_len == 0U)
    {
        return false;
    }
    const char *value = json_find_value(json, key);
    if (value == NULL || *value != '"')
    {
        return false;
    }
    value++;
    size_t i = 0U;
    while (value[i] != '\0' && value[i] != '"' && i < (out_len - 1U))
    {
        out[i] = value[i];
        i++;
    }
    out[i] = '\0';
    if (value[i] != '"')
    {
        return false;
    }
    return true;
}

static bool json_get_int_local(const char *json, const char *key, int *value)
{
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

static bool json_get_bool_local(const char *json, const char *key, bool *value)
{
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
