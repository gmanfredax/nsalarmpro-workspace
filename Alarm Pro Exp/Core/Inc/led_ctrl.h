/*
 * led_ctrl.h
 *
 *  Created on: Oct 12, 2025
 *      Author: gabriele
 */

#ifndef INC_LED_CTRL_H_
#define INC_LED_CTRL_H_

#include <stdint.h>
#include <stdbool.h>

void LED_Ctrl_Init(void);
void LED_Ctrl_Task(uint32_t now_ms);
void LED_Ctrl_Command(uint8_t cmd, uint16_t duration_ms, uint8_t pattern_arg);
void LED_Ctrl_SetIdentify(bool enable);
bool LED_Ctrl_IsIdentifyActive(void);
void LED_Ctrl_AnnounceTraffic(uint32_t pulse_ms);

#endif /* INC_LED_CTRL_H_ */
