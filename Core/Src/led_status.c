#include "led_status.h"
#include "pins.h"
#include "stm32f4xx_hal.h"
#include <string.h>

static bool led_state[4];

static void apply_led(led_status_indicator_t indicator)
{
    GPIO_TypeDef *port = NULL;
    uint16_t pin = 0;
    switch (indicator)
    {
    case LED_STATUS_POWER:
        port = PIN_LED_POWER_GPIO_PORT;
        pin = PIN_LED_POWER_PIN;
        break;
    case LED_STATUS_ARMED:
        port = PIN_LED_ARMED_GPIO_PORT;
        pin = PIN_LED_ARMED_PIN;
        break;
    case LED_STATUS_MAINT:
        port = PIN_LED_MAINT_GPIO_PORT;
        pin = PIN_LED_MAINT_PIN;
        break;
    case LED_STATUS_ALARM:
        port = PIN_LED_ALARM_GPIO_PORT;
        pin = PIN_LED_ALARM_PIN;
        break;
    default:
        return;
    }
    HAL_GPIO_WritePin(port, pin, led_state[indicator] ? GPIO_PIN_SET : GPIO_PIN_RESET);
}

void led_status_init(void)
{
    memset(led_state, 0, sizeof(led_state));
    for (uint8_t i = 0; i < 4; i++)
    {
        apply_led((led_status_indicator_t)i);
    }
}

void led_status_set(led_status_indicator_t indicator, bool state)
{
    if (indicator >= 4)
    {
        return;
    }
    led_state[indicator] = state;
    apply_led(indicator);
}

void led_status_process(void)
{
}
