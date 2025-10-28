/*
 * lss_slave.h
 *
 *  Created on: Oct 12, 2025
 *      Author: gabriele
 */

#ifndef INC_LSS_SLAVE_H_
#define INC_LSS_SLAVE_H_

#include <stdint.h>
#include <stdbool.h>

#include "can_bus_stm32.h"

void LSS_Slave_Init(void);
void LSS_Slave_OnFrame(const can_frame_t *frame);
uint8_t LSS_Slave_GetNodeId(void);
bool LSS_Slave_HasAssignedNodeId(void);
void LSS_Slave_Task(uint32_t now_ms);

#endif /* INC_LSS_SLAVE_H_ */
