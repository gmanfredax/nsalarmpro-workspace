#ifndef TAMPER_BUS_H
#define TAMPER_BUS_H

#include <stdint.h>
#include <stdbool.h>

typedef enum {
    TAMPER_STATE_UNKNOWN = 0,
    TAMPER_STATE_NORMAL,
    TAMPER_STATE_OPEN,
    TAMPER_STATE_SHORT
} tamper_state_t;

typedef struct {
    tamper_state_t state;
    float ratio;
    uint32_t timestamp;
    bool analog_source;
} tamper_bus_snapshot_t;

void tamper_bus_init(void);
void tamper_bus_process(void);
void tamper_bus_set_thresholds(float short_pct, float open_pct);
void tamper_bus_set_digital_fallback(bool enabled);
tamper_state_t tamper_bus_get_state(void);
bool tamper_bus_get_snapshot(tamper_bus_snapshot_t *snapshot);
bool tamper_bus_calibrate_normal(void);
void tamper_bus_get_thresholds(float *short_v, float *open_v);

#endif
