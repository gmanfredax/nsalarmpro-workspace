/*
 * sdo_slave.h
 *
 *  Created on: Oct 12, 2025
 *      Author: gabriele
 */

#ifndef INC_SDO_SLAVE_H_
#define INC_SDO_SLAVE_H_

#include <stdint.h>
#include <stdbool.h>

#include "can_bus_stm32.h"

typedef enum
{
    INPUT_TYPE_NO = 0,
    INPUT_TYPE_NC = 1,
    INPUT_TYPE_EOL = 2,
    INPUT_TYPE_2EOL = 3
} input_type_t;

typedef enum
{
    OUTPUT_TYPE_DIGITAL = 0,
    OUTPUT_TYPE_PWM = 1
} output_type_t;

typedef struct
{
    input_type_t type;
    uint16_t debounce_ms;
    bool inverted;
} input_config_t;

typedef struct
{
    output_type_t type;
    uint8_t default_pwm;
} output_config_t;

void SDO_Slave_Init(void);
void SDO_Slave_SetNodeId(uint8_t node_id);
void SDO_Slave_OnFrame(const can_frame_t *frame);
const input_config_t *SDO_Slave_GetInputConfig(uint8_t channel);
const output_config_t *SDO_Slave_GetOutputConfig(uint8_t channel);
void SDO_Slave_LoadDefaults(void);

#endif /* INC_SDO_SLAVE_H_ */
