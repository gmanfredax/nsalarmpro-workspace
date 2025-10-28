/*
 * hw_profile.h
 *
 *  Created on: Oct 16, 2025
 *      Author: gabriele
 */

#ifndef INC_HW_PROFILE_H_
#define INC_HW_PROFILE_H_

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "stm32f1xx_hal.h"

#ifdef __cplusplus
extern "C" {
#endif

#define EXP_BOARD_INPUT_COUNT   8u
#define EXP_BOARD_OUTPUT_COUNT  8u

uint32_t hw_profile_read_inputs(void);
void hw_profile_write_outputs(uint32_t bitmap);
void hw_profile_identify(bool enable);
void hw_profile_tick_10ms(void);
void hw_profile_get_unique_id(uint8_t *out_uid, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* INC_HW_PROFILE_H_ */
