#ifndef LED_RGB_H
#define LED_RGB_H

#include <stdint.h>

typedef enum {
    LED_PATTERN_BOOT = 0,
    LED_PATTERN_DHCP,
    LED_PATTERN_HTTP_READY,
    LED_PATTERN_BOOTSTRAP,
    LED_PATTERN_CLAIM_WAIT,
    LED_PATTERN_FINAL_OK,
    LED_PATTERN_TLS_ERROR,
    LED_PATTERN_AUTH_ERROR,
    LED_PATTERN_OFF
} led_pattern_t;

void led_rgb_init(void);
void led_rgb_set_pattern(led_pattern_t pattern);
void led_rgb_process(void);

#endif
