#include "can_bus.h"
#include "stm32f4xx_hal.h"
#include "cmsis_os.h"
#include "config.h"
#include "mqtt_cli.h"
#include <string.h>
#include <stdio.h>

extern CAN_HandleTypeDef hcan1;

static can_node_info_t nodes[CAN_MAX_NODES];
static uint32_t last_heartbeat;

static void can_bus_refresh_online(can_node_info_t *node);
static void publish_can_snapshot(void);

void can_bus_init(void)
{
    memset(nodes, 0, sizeof(nodes));
    HAL_CAN_ActivateNotification(&hcan1, CAN_IT_RX_FIFO0_MSG_PENDING | CAN_IT_BUSOFF);
    HAL_CAN_Start(&hcan1);
    last_heartbeat = xTaskGetTickCount();
}

void can_bus_process(void)
{
    uint32_t now = xTaskGetTickCount();
    if ((now - last_heartbeat) >= pdMS_TO_TICKS(NSAP_CAN_HEARTBEAT_MS))
    {
        can_bus_send_heartbeat();
        last_heartbeat = now;
    }
    bool publish = false;
    for (uint8_t i = 0; i < CAN_MAX_NODES; i++)
    {
        if (nodes[i].node_id != 0 && (now - nodes[i].last_heartbeat) > pdMS_TO_TICKS(3000))
        {
            nodes[i].online = false;
            publish = true;
        }
    }
    if (publish)
    {
        publish_can_snapshot();
    }
}

void can_bus_on_rx(uint32_t id, const uint8_t *data, uint8_t len)
{
    uint8_t node_id = id & 0xFF;
    if (node_id == 0 || len < 2)
    {
        return;
    }
    can_node_info_t *slot = NULL;
    for (uint8_t i = 0; i < CAN_MAX_NODES; i++)
    {
        if (nodes[i].node_id == node_id)
        {
            slot = &nodes[i];
            break;
        }
        if (slot == NULL && nodes[i].node_id == 0)
        {
            slot = &nodes[i];
            nodes[i].node_id = node_id;
        }
    }
    if (slot == NULL)
    {
        return;
    }
    slot->capabilities_zones = data[0];
    slot->capabilities_outputs = data[1];
    if (len >= 4)
    {
        slot->tec = data[2];
        slot->rec = data[3];
    }
    slot->last_heartbeat = xTaskGetTickCount();
    slot->online = true;
    publish_can_snapshot();
}

void can_bus_send_heartbeat(void)
{
    uint8_t payload[2] = {0xAA, 0x55};
    CAN_TxHeaderTypeDef header = {0};
    header.StdId = 0x100;
    header.IDE = CAN_ID_STD;
    header.RTR = CAN_RTR_DATA;
    header.DLC = sizeof(payload);
    uint32_t mailbox;
    HAL_CAN_AddTxMessage(&hcan1, &header, payload, &mailbox);
}

bool can_bus_get_snapshot(can_node_info_t *out_nodes, uint8_t *count)
{
    if (out_nodes == NULL || count == NULL)
    {
        return false;
    }
    uint8_t used = 0;
    for (uint8_t i = 0; i < CAN_MAX_NODES; i++)
    {
        if (nodes[i].node_id != 0)
        {
            out_nodes[used++] = nodes[i];
        }
    }
    *count = used;
    return true;
}

void can_bus_handle_bus_off(void)
{
    HAL_CAN_Stop(&hcan1);
    osDelay(pdMS_TO_TICKS(NSAP_CAN_BUSOFF_TIMEOUT_MS));
    HAL_CAN_Start(&hcan1);
}

static void publish_can_snapshot(void)
{
    char payload[256];
    char *cursor = payload;
    size_t remaining = sizeof(payload);
    int written = snprintf(cursor, remaining, "{\"nodes\":[");
    cursor += written;
    remaining -= written;
    bool first = true;
    for (uint8_t i = 0; i < CAN_MAX_NODES; i++)
    {
        if (nodes[i].node_id == 0)
        {
            continue;
        }
        written = snprintf(cursor, remaining,
                           "%s{\"id\":%u,\"hb\":%lu,\"zones\":%u,\"outs\":%u,\"tec\":%u,\"rec\":%u,\"on\":%s}",
                           first ? "" : ",",
                           nodes[i].node_id,
                           nodes[i].last_heartbeat,
                           nodes[i].capabilities_zones,
                           nodes[i].capabilities_outputs,
                           nodes[i].tec,
                           nodes[i].rec,
                           nodes[i].online ? "true" : "false");
        cursor += written;
        remaining -= written;
        first = false;
    }
    snprintf(cursor, remaining, "]}");
    mqtt_cli_publish_event("telemetry/can", payload, 0, false);
}

static void can_bus_refresh_online(can_node_info_t *node)
{
    (void)node;
}
