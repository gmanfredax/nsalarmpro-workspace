#ifndef ZONES_H
#define ZONES_H

#include <stdint.h>
#include <stdbool.h>
#include "config.h"

typedef enum {
    ZONE_STATE_OK = 0,
    ZONE_STATE_OPEN,
    ZONE_STATE_SHORT,
    ZONE_STATE_TAMPER1,
    ZONE_STATE_TAMPER2,
    ZONE_STATE_FAULT
} zone_state_t;

typedef enum {
    ZONE_PROFILE_INSTANT = 0,
    ZONE_PROFILE_DELAYED,
    ZONE_PROFILE_EXCLUDED,
    ZONE_PROFILE_AUTO_EXCLUDE
} zone_profile_t;

typedef enum {
    ZONE_MODE_EOL = 0,
    ZONE_MODE_2EOL,
    ZONE_MODE_3EOL
} zone_mode_t;

typedef struct {
    uint8_t id;
    zone_profile_t profile;
    zone_state_t state;
    zone_mode_t wiring_mode;
    float threshold_open_pct;
    float threshold_tamper_pct;
    float threshold_short_pct;
    float ratio;
    float voltage_mv;
    uint32_t updated_at;
    uint8_t source_channel;
    uint16_t debounce_ms;
    bool bypassed;
    bool auto_exclude_enabled;
} zone_snapshot_t;

typedef struct {
    zone_profile_t profile;
    zone_mode_t wiring_mode;
    float threshold_open_pct;
    float threshold_tamper_pct;
    float threshold_short_pct;
    uint8_t auto_exclude_counter;
    bool bypassed;
    uint16_t debounce_ms;
    bool auto_exclude_enabled;
} zone_config_t;

void zones_init(void);
void zones_load_config(void);
void zones_save_config(void);
void zones_process(void);
bool zones_get_snapshot(uint8_t index, zone_snapshot_t *snapshot);
void zones_set_profile(uint8_t index, zone_profile_t profile);
void zones_set_bypass(uint8_t index, bool bypass);
void zones_set_thresholds(uint8_t index, float open_pct, float tamper_pct, float short_pct);
bool zones_bypass_handle_json(const char *json, int len);
bool zones_config_handle_json(const char *json, int len);

#endif
