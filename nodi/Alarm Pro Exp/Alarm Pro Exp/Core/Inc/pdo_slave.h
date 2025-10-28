/*
 * pdo_slave.h
 *
 *  Created on: Oct 12, 2025
 *      Author: gabriele
 */

#ifndef INC_PDO_SLAVE_H_
#define INC_PDO_SLAVE_H_

#include <stdint.h>
#include <stdbool.h>

#include "can_bus_stm32.h"

void PDO_Slave_Init(void);
void PDO_Slave_Task(uint32_t now_ms);
void PDO_Slave_OnFrame(const can_frame_t *frame);
void PDO_Slave_SetNodeId(uint8_t node_id);
void PDO_Slave_OnInputChange(uint32_t bitmap, uint8_t change_counter);

#endif /* INC_PDO_SLAVE_H_ */
