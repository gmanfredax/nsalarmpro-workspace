/*
 * can_bus_stm32.c
 *
 *  Created on: Oct 12, 2025
 *      Author: gabriele
 */


#include "can_bus_stm32.h"

#include "main.h"

#include <stdbool.h>
#include <string.h>
#include <stdio.h>

extern CAN_HandleTypeDef hcan;
extern UART_HandleTypeDef huart1;

static uint8_t current_node_id = 0xFFU;

static volatile uint32_t tx_successful = 0U;
static volatile uint32_t tx_failed = 0U;
static volatile uint32_t rx_received = 0U;
static volatile uint32_t last_tx_tick = 0U;
static volatile uint32_t last_rx_tick = 0U;
static volatile uint32_t last_error_tick = 0U;
static volatile uint32_t last_error_code_snapshot = 0U;
static volatile uint32_t error_notifications = 0U;
static can_frame_t last_rx_frame = {0};
static bool last_rx_valid = false;
static can_frame_t last_tx_frame = {0};
static bool last_tx_valid = false;
static can_bus_rx_log_entry_t rx_log[CAN_RX_LOG_DEPTH];
static uint8_t rx_log_head = 0U;
static uint8_t rx_log_count = 0U;

#if CAN_TEST_BROADCAST
static can_frame_t rx_queue[CAN_RX_LOG_DEPTH];
static volatile uint8_t rx_queue_head = 0U;
static volatile uint8_t rx_queue_tail = 0U;
static volatile uint8_t rx_queue_count = 0U;
#endif

void CAN_Bus_Init(void)
{
    current_node_id = 0xFFU;
    tx_successful = 0U;
    tx_failed = 0U;
    rx_received = 0U;
    last_tx_tick = 0U;
    last_rx_tick = 0U;
    last_error_tick = 0U;
    last_error_code_snapshot = 0U;
    error_notifications = 0U;
    last_rx_valid = false;
    last_tx_valid = false;
    rx_log_head = 0U;
    rx_log_count = 0U;
    CAN_Bus_SetFilters(current_node_id);
#if CAN_TEST_BROADCAST
    rx_queue_head = 0U;
    rx_queue_tail = 0U;
    rx_queue_count = 0U;
#endif
}

void CAN_Bus_SetFilters(uint8_t node_id)
{
#if CAN_TEST_BROADCAST
    (void)node_id;
    return;
#else
    current_node_id = node_id;
    CAN_FilterTypeDef filter = {0};
    filter.FilterBank = 0;
    filter.FilterMode = CAN_FILTERMODE_IDMASK;
    filter.FilterScale = CAN_FILTERSCALE_32BIT;
    filter.FilterFIFOAssignment = CAN_RX_FIFO0;
    filter.FilterActivation = ENABLE;
    filter.SlaveStartFilterBank = 14;
    filter.FilterIdHigh = 0U;
    filter.FilterIdLow = 0U;
    filter.FilterMaskIdHigh = 0U;
    filter.FilterMaskIdLow = 0U;

    if (HAL_CAN_ConfigFilter(&hcan, &filter) != HAL_OK)
    {
        Error_Handler();
    }
#endif
}

void CAN_Bus_Start(void)
{
    if (HAL_CAN_GetState(&hcan) == HAL_CAN_STATE_READY)
    {
        if (HAL_CAN_Start(&hcan) != HAL_OK)
        {
            Error_Handler();
        }
    }
    uint32_t interrupt_mask = CAN_IT_ERROR_WARNING |
                              CAN_IT_ERROR_PASSIVE |
                              CAN_IT_BUSOFF |
                              CAN_IT_LAST_ERROR_CODE |
                              CAN_IT_ERROR;
#if CAN_TEST_BROADCAST
    interrupt_mask |= CAN_IT_RX_FIFO0_MSG_PENDING;
#endif

    if (HAL_CAN_ActivateNotification(&hcan, interrupt_mask) != HAL_OK)
    {
        Error_Handler();
    }
}

bool CAN_Bus_Send(const can_frame_t *frame)
{
    CAN_TxHeaderTypeDef header = {0};
    header.StdId = frame->id & 0x7FFU;
    header.IDE = CAN_ID_STD;
    header.RTR = CAN_RTR_DATA;
    header.DLC = frame->dlc;

    uint32_t mailbox;
    HAL_StatusTypeDef status = HAL_CAN_AddTxMessage(&hcan, &header, (uint8_t *)frame->data, &mailbox);
    if (status != HAL_OK)
    {
        tx_failed++;
        last_error_tick = HAL_GetTick();
        last_error_code_snapshot = HAL_CAN_GetError(&hcan);
        char note[80];
        uint32_t err = last_error_code_snapshot;
        (void)snprintf(note, sizeof(note),
                       "CAN TXERR %03lX status=%ld err=%08lX",
                       (unsigned long)header.StdId,
                       (long)status,
                       (unsigned long)err);
        CAN_Bus_DebugPrintNote(note);
        return false;
    }
    while (HAL_CAN_IsTxMessagePending(&hcan, mailbox))
    {
    }
    tx_successful++;
    last_tx_tick = HAL_GetTick();
    last_tx_frame = *frame;
    last_tx_valid = true;
    CAN_Bus_DebugPrintFrame("TX", frame);
    return true;
}

bool CAN_Bus_Read(can_frame_t *frame)
{
    if (frame == NULL)
    {
        return false;
    }

#if CAN_TEST_BROADCAST
    uint32_t primask = __get_PRIMASK();
    __disable_irq();
    if (rx_queue_count == 0U)
    {
        if (primask == 0U)
        {
            __enable_irq();
        }
        return false;
    }

    *frame = rx_queue[rx_queue_tail];
    rx_queue_tail = (uint8_t)((rx_queue_tail + 1U) % CAN_RX_LOG_DEPTH);
    rx_queue_count--;

    if (primask == 0U)
    {
        __enable_irq();
    }
    return true;
#else
    CAN_RxHeaderTypeDef header = {0};
    if (HAL_CAN_GetRxMessage(&hcan, CAN_RX_FIFO0, &header, frame->data) != HAL_OK)
    {
        return false;
    }
    frame->id = header.StdId;
    frame->dlc = header.DLC;
    rx_received++;
    last_rx_tick = HAL_GetTick();
    last_rx_frame = *frame;
    last_rx_valid = true;

    rx_log[rx_log_head].frame = *frame;
    rx_log[rx_log_head].timestamp_ms = last_rx_tick;
    rx_log_head = (uint8_t)((rx_log_head + 1U) % CAN_RX_LOG_DEPTH);
    if (rx_log_count < CAN_RX_LOG_DEPTH)
    {
        rx_log_count++;
    }
    return true;
#endif
}

void CAN_Bus_DebugPrintFrame(const char *direction, const can_frame_t *frame)
{
    if ((direction == NULL) || (frame == NULL))
    {
        return;
    }

    char buffer[64];
    int len = snprintf(buffer, sizeof(buffer), "CAN %s %03lX [%u]",
                       direction,
                       (unsigned long)(frame->id & 0x7FFU),
                       (unsigned int)frame->dlc);
    if (len < 0)
    {
        return;
    }

    size_t used = (size_t)len;
    if (used >= sizeof(buffer))
    {
        used = sizeof(buffer) > 0U ? (sizeof(buffer) - 1U) : 0U;
    }

    static const char hex_lookup[] = "0123456789ABCDEF";
    for (uint8_t i = 0U; (i < frame->dlc) && (i < 8U); ++i)
    {
        if ((used + 3U) >= sizeof(buffer))
        {
            break;
        }
        buffer[used++] = ' ';
        buffer[used++] = hex_lookup[(frame->data[i] >> 4) & 0x0FU];
        buffer[used++] = hex_lookup[frame->data[i] & 0x0FU];
    }

    if ((used + 2U) > sizeof(buffer))
    {
        used = sizeof(buffer) > 2U ? (sizeof(buffer) - 2U) : 0U;
    }

    buffer[used++] = '\r';
    buffer[used++] = '\n';

    HAL_UART_Transmit(&huart1, (uint8_t *)buffer, (uint16_t)used, HAL_MAX_DELAY);
}

void CAN_Bus_DebugPrintNote(const char *note)
{
    if (note == NULL)
    {
        return;
    }

    char buffer[96];
    size_t used = 0U;
    while ((used < (sizeof(buffer) - 2U)) && (note[used] != '\0'))
    {
        buffer[used] = note[used];
        used++;
    }

    if (used == 0U)
    {
        return;
    }

    buffer[used++] = '\r';
    buffer[used++] = '\n';

    HAL_UART_Transmit(&huart1, (uint8_t *)buffer, (uint16_t)used, HAL_MAX_DELAY);
}

/*void HAL_CAN_RxFifo0MsgPendingCallback(CAN_HandleTypeDef *hcan_ptr)
{
#if CAN_TEST_BROADCAST
    if (hcan_ptr != &hcan)
    {
        return;
    }

    CAN_RxHeaderTypeDef header = {0};
    uint8_t data[8] = {0};
    if (HAL_CAN_GetRxMessage(&hcan, CAN_RX_FIFO0, &header, data) != HAL_OK)
    {
        return;
    }
    HAL_GPIO_TogglePin(GPIOC, GPIO_PIN_13);// toggle PA3 LED
    can_frame_t frame = {0};
    frame.id = header.StdId;
    frame.dlc = header.DLC;
    memcpy(frame.data, data, sizeof(frame.data));

    uint8_t next_head = (uint8_t)((rx_queue_head + 1U) % CAN_RX_LOG_DEPTH);
    rx_queue[rx_queue_head] = frame;
    if (rx_queue_count == CAN_RX_LOG_DEPTH)
    {
        rx_queue_tail = (uint8_t)((rx_queue_tail + 1U) % CAN_RX_LOG_DEPTH);
        rx_queue_count--;
    }
    rx_queue_head = next_head;
    rx_queue_count++;

    rx_received++;
    last_rx_tick = HAL_GetTick();
    last_rx_frame = frame;
    last_rx_valid = true;

    rx_log[rx_log_head].frame = frame;
    rx_log[rx_log_head].timestamp_ms = last_rx_tick;
    rx_log_head = (uint8_t)((rx_log_head + 1U) % CAN_RX_LOG_DEPTH);
    if (rx_log_count < CAN_RX_LOG_DEPTH)
    {
        rx_log_count++;
    }
#else
    (void)hcan_ptr;
#endif
}*/

CAN_HandleTypeDef *CAN_Bus_GetHandle(void)
{
    return &hcan;
}

void CAN_Bus_GetDiagnostics(can_bus_diagnostics_t *diagnostics)
{
    if (diagnostics == NULL)
    {
        return;
    }

    uint32_t esr = READ_REG(hcan.Instance->ESR);
    diagnostics->state = HAL_CAN_GetState(&hcan);
    diagnostics->error_code = HAL_CAN_GetError(&hcan);
    diagnostics->tx_error_count = (uint8_t)((esr & CAN_ESR_TEC_Msk) >> CAN_ESR_TEC_Pos);
    diagnostics->rx_error_count = (uint8_t)((esr & CAN_ESR_REC_Msk) >> CAN_ESR_REC_Pos);
    diagnostics->last_error_code = (uint8_t)((esr & CAN_ESR_LEC_Msk) >> CAN_ESR_LEC_Pos);
    diagnostics->error_warning = (esr & CAN_ESR_EWGF) != 0U;
    diagnostics->error_passive = (esr & CAN_ESR_EPVF) != 0U;
    diagnostics->bus_off = (esr & CAN_ESR_BOFF) != 0U;
    diagnostics->tx_successful = tx_successful;
    diagnostics->tx_failed = tx_failed;
    diagnostics->rx_received = rx_received;
    diagnostics->last_tx_tick = last_tx_tick;
    diagnostics->last_rx_tick = last_rx_tick;
    diagnostics->last_error_tick = last_error_tick;
    diagnostics->last_error_code = (uint8_t)((esr & CAN_ESR_LEC_Msk) >> CAN_ESR_LEC_Pos);
    diagnostics->last_error_flags = last_error_code_snapshot;
    diagnostics->error_notifications = error_notifications;
    diagnostics->last_rx_valid = last_rx_valid;
    diagnostics->last_rx_frame = last_rx_frame;
    diagnostics->last_tx_valid = last_tx_valid;
    diagnostics->last_tx_frame = last_tx_frame;
    diagnostics->rx_log_count = rx_log_count;
}

void HAL_CAN_ErrorCallback(CAN_HandleTypeDef *hcan_ptr)
{
    (void)hcan_ptr;
    error_notifications++;
    last_error_tick = HAL_GetTick();
    last_error_code_snapshot = HAL_CAN_GetError(&hcan);
}

uint8_t CAN_Bus_GetRxLog(can_bus_rx_log_entry_t *entries, uint8_t max_entries)
{
    if ((entries == NULL) || (max_entries == 0U))
    {
        return 0U;
    }

    uint8_t count = rx_log_count;
    if (count > max_entries)
    {
        count = max_entries;
    }

    for (uint8_t i = 0U; i < count; ++i)
    {
        uint8_t index = (uint8_t)((rx_log_head + CAN_RX_LOG_DEPTH - count + i) % CAN_RX_LOG_DEPTH);
        entries[i] = rx_log[index];
    }

    return count;
}
