/*
 * heartbeat_slave.h
 *
 *  Created on: Oct 12, 2025
 *      Author: gabriele
 */

#ifndef INC_HEARTBEAT_SLAVE_H_
#define INC_HEARTBEAT_SLAVE_H_

#include <stdint.h>

void Heartbeat_Slave_Init(void);
void Heartbeat_Slave_SetNodeId(uint8_t node_id);
void Heartbeat_Slave_Task(uint32_t now_ms);
void Heartbeat_Slave_UpdateMetrics(uint16_t voltage_mv, int16_t temperature_cc);

#endif /* INC_HEARTBEAT_SLAVE_H_ */
