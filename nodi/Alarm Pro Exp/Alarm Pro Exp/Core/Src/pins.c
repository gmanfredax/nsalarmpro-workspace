/*
 * pins.c
 *
 *  Created on: Oct 12, 2025
 *      Author: gabriele
 */


#include "pins.h"

const uint16_t INPUT_PINS[INPUT_CHANNEL_COUNT] = {
    GPIO_PIN_0, GPIO_PIN_1, GPIO_PIN_2, GPIO_PIN_3,
    GPIO_PIN_4, GPIO_PIN_5, GPIO_PIN_6, GPIO_PIN_7
};

GPIO_TypeDef *const INPUT_PORTS[INPUT_CHANNEL_COUNT] = {
    GPIOB, GPIOB, GPIOB, GPIOB,
    GPIOB, GPIOB, GPIOB, GPIOB
};

const uint16_t OUTPUT_PINS[OUTPUT_CHANNEL_COUNT] = {
    GPIO_PIN_8, GPIO_PIN_9
};

GPIO_TypeDef *const OUTPUT_PORTS[OUTPUT_CHANNEL_COUNT] = {
    GPIOB, GPIOB
};
