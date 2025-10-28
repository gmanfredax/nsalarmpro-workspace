/*
 * lss_slave.c
 *
 *  Created on: Oct 12, 2025
 *      Author: gabriele
 */


#include "lss_slave.h"

#include "can_bus_stm32.h"
#include "eeprom_emul.h"
#include "heartbeat_slave.h"
#include "pdo_slave.h"
#include "sdo_slave.h"

#include "stm32f1xx_hal.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>


#define LSS_MASTER_ID   0x7E5U
#define LSS_SLAVE_ID    0x7E4U
#define LSS_DEFAULT_NODE_ID 0x7FU

#define LSS_OP_DISCOVER 0x01U
#define LSS_OP_IDENTIFY 0x02U
#define LSS_OP_ASSIGN   0x03U
#define LSS_OP_ACK      0x04U

static uint8_t node_id = LSS_DEFAULT_NODE_ID;
static bool node_id_assigned = false;
static uint32_t discover_nonce = 0U;
static uint64_t device_uid = 0U;
static uint32_t identify_deadline = 0U;
static bool pending_identify = false;
static board_info_t board_info;
static uint16_t base_input_index = 0U;
static uint16_t base_output_index = 0U;
static uint8_t assign_buffer[16];
static uint8_t assign_offset = 0U;

static uint64_t derive_uid(void)
{
    uint32_t word0 = *(__IO uint32_t *)0x1FFFF7E8U;
    uint32_t word1 = *(__IO uint32_t *)0x1FFFF7ECU;
    uint32_t word2 = *(__IO uint32_t *)0x1FFFF7F0U;
    uint64_t folded = ((uint64_t)word0 << 32) | word1;
    folded ^= ((uint64_t)word2 << 16) | (word2 & 0xFFFFU);
    return folded;
}

static void send_segmented(uint8_t op, const uint8_t *payload, uint8_t len)
{
    uint8_t offset = 0U;
    uint8_t segment = 0U;
    while (offset < len)
    {
        can_frame_t frame = {0};
        frame.id = LSS_SLAVE_ID;
        frame.data[0] = op;
        frame.data[1] = segment;

        uint8_t remaining = (uint8_t)(len - offset);
        uint8_t chunk = (remaining > 5U) ? 5U : remaining;
        frame.data[2] = chunk;
        memcpy(&frame.data[3], &payload[offset], chunk);

        frame.dlc = (uint8_t)(3U + chunk);

        offset += chunk;
        segment++;

        CAN_Bus_Send(&frame);
    }
}

static void send_identify(void)
{
    uint8_t buffer[24] = {0};
    memcpy(&buffer[0], &discover_nonce, sizeof(discover_nonce));
    memcpy(&buffer[4], &device_uid, sizeof(device_uid));
    memcpy(&buffer[12], &board_info.model, sizeof(board_info.model));
    memcpy(&buffer[14], &board_info.fw_version, sizeof(board_info.fw_version));
    memcpy(&buffer[16], &board_info.caps, sizeof(board_info.caps));
    buffer[18] = board_info.inputs;
    buffer[19] = board_info.outputs;
    send_segmented(LSS_OP_IDENTIFY, buffer, 20U);
}

static void send_assign_ack(uint8_t status)
{
    uint8_t buffer[16] = {0};
    memcpy(&buffer[0], &device_uid, sizeof(device_uid));
    buffer[8] = node_id;
    buffer[9] = status;
    memcpy(&buffer[10], &base_input_index, sizeof(base_input_index));
    memcpy(&buffer[12], &base_output_index, sizeof(base_output_index));

    char note[96];
    (void)snprintf(note, sizeof(note),
            	   "LSS: sending assign ack status=0x%02X node=%u in@0x%04X out@0x%04X",
                   (unsigned int)status,
                   (unsigned int)node_id,
                   (unsigned int)base_input_index,
                   (unsigned int)base_output_index);
    CAN_Bus_DebugPrintNote(note);
    send_segmented(LSS_OP_ACK, buffer, 14U);
}

void LSS_Slave_Init(void)
{
    node_id = LSS_DEFAULT_NODE_ID;
    node_id_assigned = false;
    device_uid = derive_uid();
    EEPROM_LoadBoardInfo(&board_info);
    uint8_t stored_id = 0xFFU;
    if (EEPROM_LoadNodeId(&stored_id) && stored_id != 0xFFU)
    {
        node_id = stored_id;
        node_id_assigned = true;
        CAN_Bus_SetFilters(node_id);
        PDO_Slave_SetNodeId(node_id);
        SDO_Slave_SetNodeId(node_id);
        Heartbeat_Slave_SetNodeId(node_id);
        char note[96];
        (void)snprintf(note, sizeof(note),
                       "LSS: restored node ID %u from EEPROM", (unsigned int)node_id);
        CAN_Bus_DebugPrintNote(note);
    }
    else
    {
        node_id = LSS_DEFAULT_NODE_ID;
        node_id_assigned = false;
        CAN_Bus_SetFilters(0xFFU);
        PDO_Slave_SetNodeId(0xFFU);
        SDO_Slave_SetNodeId(node_id);
        Heartbeat_Slave_SetNodeId(0xFFU);
        CAN_Bus_DebugPrintNote("LSS: no stored node ID, awaiting provisioning");
    }
}

void LSS_Slave_Task(uint32_t now_ms)
{
    if (pending_identify && now_ms >= identify_deadline)
    {
        pending_identify = false;
        char note[96];
        (void)snprintf(note, sizeof(note),
                       "LSS: sending identify for nonce 0x%08lX",
                       (unsigned long)discover_nonce);
        CAN_Bus_DebugPrintNote(note);
        send_identify();
    }
}

static bool uid_matches(const uint8_t *uid)
{
    uint64_t target = 0U;
    memcpy(&target, uid, sizeof(target));
    return target == device_uid;
}

void LSS_Slave_OnFrame(const can_frame_t *frame)
{
    if (frame->id != LSS_MASTER_ID)
    {
        return;
    }
    if (frame->dlc < 4)
    {
        return;
    }

    uint8_t op = frame->data[0];
    switch (op)
    {
    case LSS_OP_DISCOVER:
        if (!node_id_assigned && frame->dlc >= 5)
        {
            memcpy(&discover_nonce, &frame->data[1], sizeof(discover_nonce));
            uint32_t random_delay = HAL_GetTick();
            random_delay ^= (uint32_t)(device_uid & 0xFFFFFFFFu);
            random_delay &= 0x0FU;
            identify_deadline = HAL_GetTick() + random_delay;
            pending_identify = true;
            char note[96];
            (void)snprintf(note, sizeof(note),
                           "LSS: discover received nonce=0x%08lX delay=%lums",
                           (unsigned long)discover_nonce,
                           (unsigned long)random_delay);
            CAN_Bus_DebugPrintNote(note);
        }
        else if (node_id_assigned)
        {
            CAN_Bus_DebugPrintNote("LSS: discover ignored, node already assigned");
        }
        break;
    case LSS_OP_ASSIGN:
        if (frame->dlc >= 8)
        {
            uint8_t segment = frame->data[1];
            uint8_t length = frame->data[2];
            if (segment == 0U)
            {
                assign_offset = 0U;
            }
            if ((assign_offset + length) <= sizeof(assign_buffer))
            {
                memcpy(&assign_buffer[assign_offset], &frame->data[3], length);
                assign_offset += length;
            }
            if (length < 6U)
            {
                if (assign_offset >= 13U && uid_matches(assign_buffer))
                {
                    uint8_t new_id = assign_buffer[8];
                    memcpy(&base_input_index, &assign_buffer[9], sizeof(base_input_index));
                    memcpy(&base_output_index, &assign_buffer[11], sizeof(base_output_index));
                    node_id = new_id;
                    node_id_assigned = true;
                    EEPROM_SaveNodeId(node_id);
                    CAN_Bus_SetFilters(node_id);
                    PDO_Slave_SetNodeId(node_id);
                    SDO_Slave_SetNodeId(node_id);
                    Heartbeat_Slave_SetNodeId(node_id);
                    char note[96];
                    (void)snprintf(note, sizeof(note),
                                   "LSS: node ID assigned %u inputs@0x%04X outputs@0x%04X",
                                   (unsigned int)node_id,
                                   (unsigned int)base_input_index,
                                   (unsigned int)base_output_index);
                    CAN_Bus_DebugPrintNote(note);
                    send_assign_ack(0x00U);

                }
                else
                {
                	CAN_Bus_DebugPrintNote("LSS: assignment payload ignored (UID mismatch)");
                }
            }
        }
        break;
    default:
        break;
    }
}

uint8_t LSS_Slave_GetNodeId(void)
{
    return node_id;
}

bool LSS_Slave_HasAssignedNodeId(void)
{
    return node_id_assigned;
}
