/*
 * can_app.h
 *
 *  Created on: Oct 16, 2025
 *      Author: gabriele
 */

#ifndef INC_CAN_APP_H_
#define INC_CAN_APP_H_

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "stm32f1xx_hal.h"

#ifdef __cplusplus
extern "C" {
#endif

void can_app_init(CAN_HandleTypeDef *handle);
void can_app_periodic(void);
void can_app_on_timer_tick(void);
void can_app_on_message(const CAN_RxHeaderTypeDef *rx_header, const uint8_t *data);

#ifdef __cplusplus
}
#endif

#endif /* INC_CAN_APP_H_ */
