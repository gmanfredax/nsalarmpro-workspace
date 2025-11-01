#include "outputs.h"
#include "pins.h"
#include "cmsis_os.h"
#include "stm32f4xx_hal.h"
#include "mqtt_cli.h"
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdio.h>

static output_state_t outputs_state[OUTPUT_COUNT];

#define SIREN_DEFAULT_TIMEOUT_S (180)

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

static void publish_output_error(void)
{
    mqtt_cli_publish_event("command_error", "{\"cmd\":\"output\",\"reason\":\"bad_output\"}", 1, false);
}

static bool output_from_name(const char *name, output_channel_t *out, bool *is_siren)
{
    if (name == NULL || out == NULL || is_siren == NULL)
    {
        return false;
    }
    if (strcmp(name, "SIREN_INT") == 0)
    {
        *out = OUTPUT_SIREN_INT;
        *is_siren = true;
        return true;
    }
    if (strcmp(name, "SIREN_EXT") == 0)
    {
        *out = OUTPUT_SIREN_EXT;
        *is_siren = true;
        return true;
    }
    if (strcmp(name, "NEBBIOGENO") == 0)
    {
        *out = OUTPUT_NEBBIOGENO;
        *is_siren = false;
        return true;
    }
    if (strcmp(name, "OUT1") == 0)
    {
        *out = OUTPUT_OUT1;
        *is_siren = false;
        return true;
    }
    if (strcmp(name, "OUT2") == 0)
    {
        *out = OUTPUT_OUT2;
        *is_siren = false;
        return true;
    }
    return false;
}

static void apply_output(output_channel_t output, bool state)
{
    GPIO_TypeDef *port = NULL;
    uint16_t pin = 0;
    switch (output)
    {
    case OUTPUT_SIREN_INT:
        port = PIN_RELAY_SIREN_INT_PORT;
        pin = PIN_RELAY_SIREN_INT_PIN;
        break;
    case OUTPUT_SIREN_EXT:
        port = PIN_RELAY_SIREN_EXT_PORT;
        pin = PIN_RELAY_SIREN_EXT_PIN;
        break;
    case OUTPUT_NEBBIOGENO:
        port = PIN_RELAY_NEBBIOGENO_PORT;
        pin = PIN_RELAY_NEBBIOGENO_PIN;
        break;
    case OUTPUT_OUT1:
        port = PIN_RELAY_OUT1_PORT;
        pin = PIN_RELAY_OUT1_PIN;
        break;
    case OUTPUT_OUT2:
        port = PIN_RELAY_OUT2_PORT;
        pin = PIN_RELAY_OUT2_PIN;
        break;
    default:
        return;
    }
    HAL_GPIO_WritePin(port, pin, state ? GPIO_PIN_SET : GPIO_PIN_RESET);
}

void outputs_init(void)
{
    memset(outputs_state, 0, sizeof(outputs_state));
}

void outputs_set(output_channel_t output, bool state, uint32_t timeout_ms)
{
    if (output >= OUTPUT_COUNT)
    {
        return;
    }
    outputs_state[output].active = state;
    outputs_state[output].timeout_ms = timeout_ms;
    outputs_state[output].activated_at = xTaskGetTickCount();
    apply_output(output, state);
}

void outputs_process(void)
{
    uint32_t now = xTaskGetTickCount();
    for (uint8_t i = 0; i < OUTPUT_COUNT; i++)
    {
        if (outputs_state[i].active && outputs_state[i].timeout_ms > 0U)
        {
            if ((now - outputs_state[i].activated_at) > pdMS_TO_TICKS(outputs_state[i].timeout_ms))
            {
                outputs_state[i].active = false;
                apply_output((output_channel_t)i, false);
            }
        }
    }
}

bool outputs_get_state(output_channel_t output, output_state_t *state)
{
    if (output >= OUTPUT_COUNT || state == NULL)
    {
        return false;
    }
    *state = outputs_state[output];
    return true;
}

bool outputs_handle_json(const char *json, int len)
{
    (void)len;
    if (json == NULL)
    {
        publish_output_error();
        return false;
    }

    char name[16];
    char action[8];
    if (!json_get_str_local(json, "name", name, sizeof(name)) ||
        !json_get_str_local(json, "action", action, sizeof(action)))
    {
        publish_output_error();
        return false;
    }

    output_channel_t channel = OUTPUT_COUNT;
    bool is_siren = false;
    if (!output_from_name(name, &channel, &is_siren))
    {
        publish_output_error();
        return false;
    }

    bool turn_on = false;
    if (strcmp(action, "on") == 0)
    {
        turn_on = true;
    }
    else if (strcmp(action, "off") == 0)
    {
        turn_on = false;
    }
    else
    {
        publish_output_error();
        return false;
    }

    uint32_t timeout_ms = 0U;
    int timeout_s = 0;
    if (turn_on && is_siren)
    {
        if (!json_get_int_local(json, "timeout_s", &timeout_s) || timeout_s <= 0)
        {
            timeout_s = SIREN_DEFAULT_TIMEOUT_S;
        }
        timeout_ms = (uint32_t)timeout_s * 1000U;
    }

    outputs_set(channel, turn_on, timeout_ms);

    if (is_siren)
    {
        if (turn_on)
        {
            char payload[96];
            snprintf(payload, sizeof(payload), "{\"source\":\"cmd\",\"timeout_s\":%d}", timeout_s);
            mqtt_cli_publish_event("siren_on", payload, 1, false);
        }
        else
        {
            mqtt_cli_publish_event("siren_off", "{\"source\":\"cmd\"}", 1, false);
        }
    }
    else
    {
        char payload[96];
        snprintf(payload, sizeof(payload), "{\"name\":\"%s\",\"state\":\"%s\"}", name, turn_on ? "on" : "off");
        mqtt_cli_publish_event("output_changed", payload, 1, false);
    }

    return true;
}
