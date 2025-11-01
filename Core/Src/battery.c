#include "battery.h"
#include "config.h"
#include "cmsis_os.h"

static battery_snapshot_t last_snapshot = {BATTERY_STATE_UNKNOWN, 0.0f, 0};

void battery_update(float voltage)
{
    battery_state_t state = BATTERY_STATE_OK;
    if (voltage <= NSAP_BATTERY_CRIT_VOLT)
    {
        state = BATTERY_STATE_CRIT;
    }
    else if (voltage <= NSAP_BATTERY_LOW_VOLT)
    {
        state = BATTERY_STATE_LOW;
    }
    else if (voltage >= (NSAP_BATTERY_LOW_VOLT + NSAP_BATTERY_HYST_VOLT))
    {
        state = BATTERY_STATE_OK;
    }
    last_snapshot.state = state;
    last_snapshot.voltage = voltage;
    last_snapshot.timestamp = xTaskGetTickCount();
}

bool battery_get(battery_snapshot_t *snapshot)
{
    if (snapshot == NULL)
    {
        return false;
    }
    *snapshot = last_snapshot;
    return true;
}
