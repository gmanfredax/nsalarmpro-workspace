/*
 * heartbeat_slave.c
 *
 *  Created on: Oct 12, 2025
 *      Author: gabriele
 */


#include "heartbeat_slave.h"

#include "can_bus_stm32.h"
#include "lss_slave.h"

#include "stm32f1xx_hal.h"

#include <stdio.h>
#include <string.h>

#define HEARTBEAT_BASE 0x700U

static uint8_t node_id = 0xFFU;
static uint16_t voltage_mv = 12000U;
static int16_t temperature_cc = 2500;
static uint8_t state = 0x05U;
static uint8_t error_bits = 0x00U;
static uint32_t last_heartbeat = 0U;
static bool heartbeat_blocked_logged = false;
static bool heartbeat_ready_logged = false;

void Heartbeat_Slave_Init(void)
{
    node_id = 0xFFU;
    last_heartbeat = 0U;
    heartbeat_blocked_logged = false;
    heartbeat_ready_logged = false;
    CAN_Bus_DebugPrintNote("Heartbeat: init, waiting for node ID");
}

void Heartbeat_Slave_SetNodeId(uint8_t id)
{
    node_id = id;
    heartbeat_ready_logged = false;
    if (id == 0xFFU)
    {
        heartbeat_blocked_logged = false;
        CAN_Bus_DebugPrintNote("Heartbeat: disabled until node ID is assigned");
    }
    else
    {
        char note[64];
        (void)snprintf(note, sizeof(note),
                       "Heartbeat: node ID set to %u", (unsigned int)id);
        CAN_Bus_DebugPrintNote(note);
    }
}

void Heartbeat_Slave_UpdateMetrics(uint16_t voltage, int16_t temperature)
{
    voltage_mv = voltage;
    temperature_cc = temperature;
}

void Heartbeat_Slave_Task(uint32_t now_ms)
{
    if (!LSS_Slave_HasAssignedNodeId())
    {
        if (!heartbeat_blocked_logged)
        {
            CAN_Bus_DebugPrintNote("Heartbeat: suppressed until provisioning completes");
            heartbeat_blocked_logged = true;
        }
        heartbeat_ready_logged = false;
        return;
    }

    if (!heartbeat_ready_logged)
    {
        CAN_Bus_DebugPrintNote("Heartbeat: provisioning complete, emitting frames");
        heartbeat_ready_logged = true;
        heartbeat_blocked_logged = false;
    }
    if (node_id == 0xFFU)
    {
        return;
    }
    if ((now_ms - last_heartbeat) < 1000U)
    {
        return;
    }
    last_heartbeat = now_ms;

    can_frame_t frame = {0};
    frame.id = HEARTBEAT_BASE + node_id;
    frame.dlc = 8;
    frame.data[0] = state;
    frame.data[1] = error_bits;
    memcpy(&frame.data[2], &voltage_mv, sizeof(voltage_mv));
    memcpy(&frame.data[4], &temperature_cc, sizeof(temperature_cc));
    CAN_Bus_Send(&frame);
}
