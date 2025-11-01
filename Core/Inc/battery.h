#ifndef BATTERY_H
#define BATTERY_H

#include <stdint.h>
#include <stdbool.h>

typedef enum {
    BATTERY_STATE_UNKNOWN = 0,
    BATTERY_STATE_OK,
    BATTERY_STATE_LOW,
    BATTERY_STATE_CRIT
} battery_state_t;

typedef struct {
    battery_state_t state;
    float voltage;
    uint32_t timestamp;
} battery_snapshot_t;

void battery_update(float voltage);
bool battery_get(battery_snapshot_t *snapshot);

#endif
