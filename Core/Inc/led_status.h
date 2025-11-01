#ifndef LED_STATUS_H
#define LED_STATUS_H

#include <stdbool.h>

typedef enum {
    LED_STATUS_POWER = 0,
    LED_STATUS_ARMED,
    LED_STATUS_MAINT,
    LED_STATUS_ALARM
} led_status_indicator_t;

void led_status_init(void);
void led_status_set(led_status_indicator_t indicator, bool state);
void led_status_process(void);

#endif
