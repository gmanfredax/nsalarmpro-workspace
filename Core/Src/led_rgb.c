#include "led_rgb.h"
#include "pins.h"
#include "cmsis_os.h"
#include "stm32f4xx_hal.h"

extern TIM_HandleTypeDef htim4;

static led_pattern_t current_pattern = LED_PATTERN_BOOT;
static uint32_t pattern_start;

static void set_rgb(uint16_t r, uint16_t g, uint16_t b)
{
    __HAL_TIM_SET_COMPARE(&htim4, TIM_CHANNEL_1, r);
    __HAL_TIM_SET_COMPARE(&htim4, TIM_CHANNEL_2, g);
    __HAL_TIM_SET_COMPARE(&htim4, TIM_CHANNEL_3, b);
}

void led_rgb_init(void)
{
    HAL_TIM_PWM_Start(&htim4, TIM_CHANNEL_1);
    HAL_TIM_PWM_Start(&htim4, TIM_CHANNEL_2);
    HAL_TIM_PWM_Start(&htim4, TIM_CHANNEL_3);
    pattern_start = xTaskGetTickCount();
}

void led_rgb_set_pattern(led_pattern_t pattern)
{
    if (pattern != current_pattern)
    {
        current_pattern = pattern;
        pattern_start = xTaskGetTickCount();
    }
}

void led_rgb_process(void)
{
    uint32_t elapsed = xTaskGetTickCount() - pattern_start;
    switch (current_pattern)
    {
    case LED_PATTERN_BOOT:
        set_rgb((elapsed / 10) % 200, (elapsed / 10) % 200, (elapsed / 10) % 200);
        break;
    case LED_PATTERN_DHCP:
        set_rgb(0, 0, (elapsed / 8) % 400);
        break;
    case LED_PATTERN_HTTP_READY:
        set_rgb(400, 400, 0);
        break;
    case LED_PATTERN_BOOTSTRAP:
        set_rgb(0, 300, 300);
        break;
    case LED_PATTERN_CLAIM_WAIT:
        set_rgb(300, 0, 300);
        break;
    case LED_PATTERN_FINAL_OK:
        if (elapsed < pdMS_TO_TICKS(5000))
        {
            set_rgb(0, 600, 0);
        }
        else
        {
            led_rgb_set_pattern(LED_PATTERN_OFF);
        }
        break;
    case LED_PATTERN_TLS_ERROR:
        set_rgb((elapsed / 50) % 800, 0, 0);
        break;
    case LED_PATTERN_AUTH_ERROR:
        set_rgb((elapsed / 30) % 800, 0, 0);
        break;
    case LED_PATTERN_OFF:
    default:
        set_rgb(0, 0, 0);
        break;
    }
}
