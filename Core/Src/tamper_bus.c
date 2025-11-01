#include "tamper_bus.h"
#include "adc_frontend.h"
#include "cmsis_os.h"
#include "config.h"
#include "pins.h"
#include "mqtt_cli.h"
#include "stm32f4xx_hal.h"

#define NSAP_TAMPER_DEFAULT_SHORT_V   0.20f
#define NSAP_TAMPER_DEFAULT_OPEN_V    2.50f
#define NSAP_TAMPER_HYSTERESIS_V      0.05f
#define NSAP_TAMPER_DEBOUNCE_TICKS    pdMS_TO_TICKS(80U)
#define NSAP_TAMPER_TELEM_PERIOD      pdMS_TO_TICKS(1000U)
#define NSAP_TAMPER_MAXF(a, b)        (((a) > (b)) ? (a) : (b))
#define NSAP_TAMPER_MINF(a, b)        (((a) < (b)) ? (a) : (b))

static tamper_state_t current_state = TAMPER_STATE_UNKNOWN;
static tamper_state_t pending_state = TAMPER_STATE_UNKNOWN;
static TickType_t pending_since = 0U;
static bool pending_analog = true;
static float pending_voltage_v = 0.0f;

static float short_threshold_v = NSAP_TAMPER_DEFAULT_SHORT_V;
static float open_threshold_v = NSAP_TAMPER_DEFAULT_OPEN_V;
static bool digital_fallback = true;

static tamper_bus_snapshot_t last_snapshot;
static float last_voltage_v = 0.0f;
static TickType_t last_telemetry_tick = 0U;
static tamper_state_t last_telemetry_state = TAMPER_STATE_UNKNOWN;
static bool last_telemetry_analog = true;

static tamper_state_t evaluate_state(float voltage_v);
static void publish_state_change(tamper_state_t next, bool analog, float voltage_v);
static void publish_periodic(TickType_t now);

void tamper_bus_init(void)
{
    current_state = TAMPER_STATE_UNKNOWN;
    pending_state = TAMPER_STATE_UNKNOWN;
    pending_since = 0U;
    pending_analog = true;
    pending_voltage_v = 0.0f;
    short_threshold_v = NSAP_TAMPER_DEFAULT_SHORT_V;
    open_threshold_v = NSAP_TAMPER_DEFAULT_OPEN_V;
    last_snapshot.state = TAMPER_STATE_UNKNOWN;
    last_snapshot.ratio = 0.0f;
    last_snapshot.timestamp = 0U;
    last_snapshot.analog_source = true;
    last_voltage_v = 0.0f;
    last_telemetry_tick = 0U;
    last_telemetry_state = TAMPER_STATE_UNKNOWN;
    last_telemetry_analog = true;
}

void tamper_bus_process(void)
{
    TickType_t now = xTaskGetTickCount();
    bool analog_active = false;
    bool measurement_available = false;
    float voltage_v = 0.0f;
    tamper_state_t candidate = current_state;

    adc_sample_t sample;
    if (adc_frontend_get_tamper(&sample))
    {
        analog_active = true;
        measurement_available = true;
        voltage_v = sample.value_mv / 1000.0f;
        candidate = evaluate_state(voltage_v);
        last_snapshot.ratio = sample.ratio * 100.0f;
    }
    else if (digital_fallback)
    {
        GPIO_PinState state = HAL_GPIO_ReadPin(PIN_TAMPER_BUS_DIGITAL_PORT, PIN_TAMPER_BUS_DIGITAL_PIN);
        measurement_available = true;
        analog_active = false;
        candidate = (state == GPIO_PIN_SET) ? TAMPER_STATE_OPEN : TAMPER_STATE_NORMAL;
        voltage_v = (candidate == TAMPER_STATE_OPEN) ? open_threshold_v : 0.0f;
        last_snapshot.ratio = (state == GPIO_PIN_SET) ? 100.0f : 0.0f;
    }

    if (!measurement_available)
    {
        publish_periodic(now);
        return;
    }

    last_snapshot.timestamp = now;
    last_snapshot.analog_source = analog_active;

    if (candidate != current_state)
    {
        if (pending_state != candidate)
        {
            pending_state = candidate;
            pending_since = now;
            pending_analog = analog_active;
            pending_voltage_v = voltage_v;
        }
        else if ((now - pending_since) >= NSAP_TAMPER_DEBOUNCE_TICKS)
        {
            current_state = candidate;
            pending_state = TAMPER_STATE_UNKNOWN;
            publish_state_change(current_state, pending_analog, pending_voltage_v);
        }
    }
    else
    {
        pending_state = TAMPER_STATE_UNKNOWN;
    }

    last_snapshot.state = current_state;
    if (analog_active)
    {
        last_voltage_v = voltage_v;
    }
    else if (!analog_active && current_state == TAMPER_STATE_OPEN)
    {
        last_voltage_v = open_threshold_v;
    }
    else
    {
        last_voltage_v = 0.0f;
    }

    publish_periodic(now);
}

static tamper_state_t evaluate_state(float voltage_v)
{
    float short_exit = short_threshold_v + NSAP_TAMPER_HYSTERESIS_V;
    float open_exit = open_threshold_v - NSAP_TAMPER_HYSTERESIS_V;

    if (voltage_v <= short_threshold_v)
    {
        return TAMPER_STATE_SHORT;
    }
    if (voltage_v >= open_threshold_v)
    {
        return TAMPER_STATE_OPEN;
    }

    if (current_state == TAMPER_STATE_SHORT && voltage_v <= short_exit)
    {
        return TAMPER_STATE_SHORT;
    }

    if (current_state == TAMPER_STATE_OPEN && voltage_v >= open_exit)
    {
        return TAMPER_STATE_OPEN;
    }

    return TAMPER_STATE_NORMAL;
}

static void publish_state_change(tamper_state_t next, bool analog, float voltage_v)
{
    const char *event_name = NULL;
    char payload[128];
    switch (next)
    {
    case TAMPER_STATE_OPEN:
        event_name = "tamper_bus_open";
        break;
    case TAMPER_STATE_SHORT:
        event_name = "tamper_bus_short";
        break;
    case TAMPER_STATE_NORMAL:
        event_name = "tamper_bus_restore";
        break;
    default:
        break;
    }

    if (event_name != NULL)
    {
        if (analog)
        {
            snprintf(payload, sizeof(payload),
                     "{\"analog\":true,\"voltage\":%.3f,\"short_max\":%.3f,\"open_min\":%.3f}",
                     voltage_v,
                     short_threshold_v,
                     open_threshold_v);
        }
        else
        {
            snprintf(payload, sizeof(payload),
                     "{\"analog\":false}");
        }
        mqtt_cli_publish_event(event_name, payload, 1, false);
    }

    mqtt_cli_publish_tamper(next, analog, voltage_v, short_threshold_v, open_threshold_v);
}

static void publish_periodic(TickType_t now)
{
    if ((now - last_telemetry_tick) >= NSAP_TAMPER_TELEM_PERIOD ||
        last_telemetry_state != current_state ||
        last_telemetry_analog != last_snapshot.analog_source)
    {
        mqtt_cli_publish_tamper(current_state,
                                last_snapshot.analog_source,
                                last_voltage_v,
                                short_threshold_v,
                                open_threshold_v);
        last_telemetry_tick = now;
        last_telemetry_state = current_state;
        last_telemetry_analog = last_snapshot.analog_source;
    }
}

void tamper_bus_set_thresholds(float short_pct, float open_pct)
{
    short_threshold_v = short_pct;
    open_threshold_v = open_pct;
}

void tamper_bus_set_digital_fallback(bool enabled)
{
    digital_fallback = enabled;
}

tamper_state_t tamper_bus_get_state(void)
{
    return current_state;
}

bool tamper_bus_get_snapshot(tamper_bus_snapshot_t *snapshot)
{
    if (snapshot == NULL)
    {
        return false;
    }
    *snapshot = last_snapshot;
    return true;
}

bool tamper_bus_calibrate_normal(void)
{
    const uint32_t samples = 64U;
    const TickType_t wait_ticks = pdMS_TO_TICKS(5U);
    float accumulator = 0.0f;
    uint32_t collected = 0U;

    for (uint32_t i = 0; i < samples; i++)
    {
        adc_sample_t sample;
        if (!adc_frontend_get_tamper(&sample))
        {
            vTaskDelay(wait_ticks);
            if (!adc_frontend_get_tamper(&sample))
            {
                return false;
            }
        }

        accumulator += sample.value_mv / 1000.0f;
        collected++;
        vTaskDelay(wait_ticks);
    }

    if (collected == 0U)
    {
        return false;
    }

    float average_v = accumulator / (float)collected;
    float new_short = NSAP_TAMPER_MAXF(NSAP_TAMPER_DEFAULT_SHORT_V, average_v * 0.25f);
    float new_open = NSAP_TAMPER_MINF(NSAP_TAMPER_DEFAULT_OPEN_V, average_v * 3.5f);

    short_threshold_v = new_short;
    open_threshold_v = new_open;

    TickType_t now = xTaskGetTickCount();
    last_voltage_v = average_v;
    last_snapshot.analog_source = true;
    last_snapshot.timestamp = now;
    last_telemetry_tick = now;
    last_telemetry_state = current_state;
    last_telemetry_analog = true;

    char payload[160];
    snprintf(payload, sizeof(payload),
             "{\"analog\":true,\"v_normal\":%.3f,\"short_max\":%.3f,\"open_min\":%.3f}",
             average_v,
             short_threshold_v,
             open_threshold_v);

    mqtt_cli_publish_event("tamper_cal_ok", payload, 1, false);
    mqtt_cli_publish_tamper(current_state,
                            true,
                            average_v,
                            short_threshold_v,
                            open_threshold_v);

    return true;
}

void tamper_bus_get_thresholds(float *short_v, float *open_v)
{
    if (short_v != NULL)
    {
        *short_v = short_threshold_v;
    }
    if (open_v != NULL)
    {
        *open_v = open_threshold_v;
    }
}
