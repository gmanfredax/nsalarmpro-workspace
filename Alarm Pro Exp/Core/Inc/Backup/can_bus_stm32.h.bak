/*
 * can_bus_stm32.h
 *
 *  Created on: Oct 12, 2025
 *      Author: gabriele
 */

#ifndef INC_CAN_BUS_STM32_H_
#define INC_CAN_BUS_STM32_H_

#include "stm32f1xx_hal.h"
#include <stdbool.h>
#include <stdint.h>

typedef struct
{
    uint32_t id;
    uint8_t dlc;
    uint8_t data[8];
} can_frame_t;

#define CAN_RX_LOG_DEPTH 8U

typedef struct
{
    can_frame_t frame;
    uint32_t timestamp_ms;
} can_bus_rx_log_entry_t;

typedef struct
{
    HAL_CAN_StateTypeDef state;
    uint32_t error_code;
    uint8_t tx_error_count;
    uint8_t rx_error_count;
    uint8_t last_error_code;
    uint32_t last_error_flags;
    bool error_warning;
    bool error_passive;
    bool bus_off;
    uint32_t tx_successful;
    uint32_t tx_failed;
    uint32_t rx_received;
    uint32_t last_tx_tick;
    uint32_t last_rx_tick;
    uint32_t last_error_tick;
    uint32_t error_notifications;
    bool last_rx_valid;
    can_frame_t last_rx_frame;
    bool last_tx_valid;
    can_frame_t last_tx_frame;
    uint8_t rx_log_count;
} can_bus_diagnostics_t;

void CAN_Bus_Init(void);
bool CAN_Bus_Send(const can_frame_t *frame);
bool CAN_Bus_Read(can_frame_t *frame);
void CAN_Bus_Start(void);
void CAN_Bus_SetFilters(uint8_t node_id);
void CAN_Bus_GetDiagnostics(can_bus_diagnostics_t *diagnostics);
CAN_HandleTypeDef *CAN_Bus_GetHandle(void);
uint8_t CAN_Bus_GetRxLog(can_bus_rx_log_entry_t *entries, uint8_t max_entries);
void CAN_Bus_DebugPrintFrame(const char *direction, const can_frame_t *frame);
void CAN_Bus_DebugPrintNote(const char *note);

#endif /* INC_CAN_BUS_STM32_H_ */
