/*
 * pins.h
 *
 *  Created on: Oct 12, 2025
 *      Author: gabriele
 */

#ifndef INC_PINS_H_
#define INC_PINS_H_

#include "stm32f1xx_hal.h"

#define INPUT_CHANNEL_COUNT   8U
#define OUTPUT_CHANNEL_COUNT  2U

extern const uint16_t INPUT_PINS[INPUT_CHANNEL_COUNT];
extern GPIO_TypeDef *const INPUT_PORTS[INPUT_CHANNEL_COUNT];

extern const uint16_t OUTPUT_PINS[OUTPUT_CHANNEL_COUNT];
extern GPIO_TypeDef *const OUTPUT_PORTS[OUTPUT_CHANNEL_COUNT];

#define LED_IDENTIFY_PIN       GPIO_PIN_13
#define LED_IDENTIFY_PORT      GPIOC

#endif /* INC_PINS_H_ */
