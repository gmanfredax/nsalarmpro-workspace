/*
 * can_app.c
 *
 *  Created on: Oct 16, 2025
 *      Author: gabriele
 */

#include "can_app.h"
#include "hw_profile.h"
#include "can_bus_protocol.h"
#include "zone_monitor.h"

#include <string.h>

#ifndef NODE_ID_DEFAULT
#define NODE_ID_DEFAULT 0x00u
#endif

#ifndef FW_VERSION_MAJOR
#define FW_VERSION_MAJOR 1u
#endif

#ifndef FW_VERSION_MINOR
#define FW_VERSION_MINOR 0u
#endif

#define HEARTBEAT_PERIOD_MS    500u
#define INFO_PERIOD_MS         5000u
#define ADDR_REQUEST_PERIOD_MS 1000u

typedef struct {
    CAN_HandleTypeDef *hcan;
    uint8_t node_id;
    uint32_t last_heartbeat_ms;
    uint32_t last_info_ms;
    uint32_t last_inputs;
    uint32_t outputs;
    uint8_t change_counter;
    bool identify_enabled;
    bool assigned;
    uint8_t uid[CAN_PROTO_UID_LENGTH];
    uint32_t last_addr_request_ms;
} can_app_ctx_t;

static can_app_ctx_t s_ctx = {
    .hcan = NULL,
    .node_id = NODE_ID_DEFAULT,
};

static void can_app_send_heartbeat(bool io_report);
static void can_app_send_info(void);
static void can_app_send_scan_response(void);
static void can_app_send_addr_request(void);
static bool can_app_uid_matches(const uint8_t *uid, size_t len);
static void can_app_handle_command(const uint8_t *data, uint8_t len);
static void can_app_send_extended_heartbeat(void);
static void can_app_send_zone_event(const zone_event_t *event);
static uint8_t can_app_scale_to_u8(float value, float scale);
static uint16_t can_app_scale_to_u16(float value, float scale, uint16_t max_value);

static uint32_t millis(void)
{
    return HAL_GetTick();
}

void can_app_init(CAN_HandleTypeDef *handle)
{
    memset(&s_ctx, 0, sizeof(s_ctx));
    s_ctx.hcan = handle;
    s_ctx.node_id = NODE_ID_DEFAULT;
    s_ctx.outputs = 0;
    s_ctx.last_inputs = hw_profile_read_inputs();
    s_ctx.change_counter = 0;
    s_ctx.identify_enabled = false;
    s_ctx.assigned = (NODE_ID_DEFAULT != 0u);
    s_ctx.last_addr_request_ms = 0;

    uint8_t raw_uid[12] = {0};
    hw_profile_get_unique_id(raw_uid, sizeof(raw_uid));
    memset(s_ctx.uid, 0, sizeof(s_ctx.uid));
    for (size_t i = 0; i < sizeof(s_ctx.uid) && i < sizeof(raw_uid); ++i) {
        s_ctx.uid[i] = raw_uid[i];
    }

    hw_profile_write_outputs(0);
    hw_profile_identify(false);

    s_ctx.last_heartbeat_ms = millis();
    s_ctx.last_info_ms = 0;

    if (s_ctx.assigned && s_ctx.node_id != 0u) {
        can_app_send_info();
        can_app_send_heartbeat(true);
    } else {
        can_app_send_addr_request();
    }
}

void can_app_on_timer_tick(void)
{
    hw_profile_tick_10ms();
}

void can_app_periodic(void)
{
    uint32_t now = millis();

    if (!s_ctx.assigned) {
        zone_event_t event = {0};
        while (zone_monitor_pop_event(&event)) {
            /* discard events until node id is assigned */
        }
        if ((now - s_ctx.last_addr_request_ms) >= ADDR_REQUEST_PERIOD_MS) {
            can_app_send_addr_request();
        }
        return;
    }

    uint32_t inputs = hw_profile_read_inputs();
    if (inputs != s_ctx.last_inputs) {
        s_ctx.last_inputs = inputs;
        ++s_ctx.change_counter;
        can_app_send_heartbeat(true);
    }

    if ((now - s_ctx.last_heartbeat_ms) >= HEARTBEAT_PERIOD_MS) {
        can_app_send_heartbeat(false);
    }

    if ((now - s_ctx.last_info_ms) >= INFO_PERIOD_MS) {
        can_app_send_info();
    }

    zone_event_t event = {0};
    while (zone_monitor_pop_event(&event)) {
        can_app_send_zone_event(&event);
    }
}

void can_app_on_message(const CAN_RxHeaderTypeDef *rx_header, const uint8_t *data)
{
    if (!rx_header || rx_header->IDE != CAN_ID_STD || !data) {
        return;
    }

    uint32_t cob_id = rx_header->StdId & 0x7FFu;

    if (cob_id == CAN_PROTO_ID_BROADCAST_SCAN) {
        if (rx_header->DLC >= sizeof(can_proto_scan_t)) {
            const can_proto_scan_t *scan = (const can_proto_scan_t *)data;
            if (scan->msg_type == CAN_PROTO_MSG_SCAN_REQUEST) {
                if (!s_ctx.assigned) {
                    can_app_send_addr_request();
                } else {
                    can_app_send_scan_response();
                    can_app_send_info();
                }
            }
        }
        return;
    }

    if (cob_id == CAN_PROTO_ID_BROADCAST_ADDR_ASSIGN) {
        if (rx_header->DLC >= sizeof(can_proto_addr_assign_t)) {
            const can_proto_addr_assign_t *assign = (const can_proto_addr_assign_t *)data;
            if (can_app_uid_matches(assign->uid, sizeof(assign->uid))) {
                if (assign->node_id == 0u) {
                    s_ctx.node_id = 0u;
                    s_ctx.assigned = false;
                    s_ctx.last_addr_request_ms = 0u;
                    s_ctx.last_info_ms = 0u;
                    s_ctx.last_heartbeat_ms = millis();
                    s_ctx.identify_enabled = false;
                    hw_profile_identify(false);
                    can_app_send_addr_request();
                } else {
                    s_ctx.node_id = assign->node_id;
                    s_ctx.assigned = true;
                    s_ctx.last_info_ms = 0;
                    s_ctx.last_heartbeat_ms = millis() - HEARTBEAT_PERIOD_MS;
                    can_app_send_info();
                    can_app_send_heartbeat(true);
                }
            }
        }
        return;
    }

    if (cob_id == CAN_PROTO_ID_BROADCAST_TEST) {
        if (rx_header->DLC >= sizeof(can_proto_test_toggle_t)) {
            const can_proto_test_toggle_t *test = (const can_proto_test_toggle_t *)data;
            s_ctx.identify_enabled = (test->enable != 0u);
            hw_profile_identify(s_ctx.identify_enabled);
        }
        return;
    }

    if (s_ctx.assigned && s_ctx.node_id != 0u && cob_id == CAN_PROTO_ID_COMMAND(s_ctx.node_id)) {
        can_app_handle_command(data, rx_header->DLC);
        return;
    }
}

static void can_app_queue_tx(uint32_t cob_id, const void *payload, uint8_t len)
{
    if (!s_ctx.hcan) {
        return;
    }

    CAN_TxHeaderTypeDef header = {
        .StdId = cob_id & 0x7FFu,
        .ExtId = 0,
        .RTR = CAN_RTR_DATA,
        .IDE = CAN_ID_STD,
        .DLC = len,
        .TransmitGlobalTime = DISABLE,
    };

    uint8_t data[8] = {0};
    if (payload && len > 0 && len <= sizeof(data)) {
        memcpy(data, payload, len);
    }

    uint32_t mailbox = 0;
    (void)HAL_CAN_AddTxMessage(s_ctx.hcan, &header, data, &mailbox);
}

static void can_app_send_heartbeat(bool io_report)
{
    if (s_ctx.node_id == 0u) {
        return;
    }
    can_proto_heartbeat_t payload = {
        .msg_type = io_report ? CAN_PROTO_MSG_IO_REPORT : CAN_PROTO_MSG_HEARTBEAT,
        .node_state = 0,
        .change_counter = s_ctx.change_counter,
        .reserved = 0,
        .inputs_bitmap = s_ctx.last_inputs,
    };
    if (zone_monitor_vbias_warning()) {
        payload.node_state |= CAN_PROTO_NODE_STATE_WARNING_VBIAS;
    }
    can_app_queue_tx(CAN_PROTO_ID_STATUS(s_ctx.node_id), &payload, sizeof(payload));
    can_app_send_extended_heartbeat();
    s_ctx.last_heartbeat_ms = millis();
}

static void can_app_send_info(void)
{
    if (s_ctx.node_id == 0u) {
        return;
    }
    can_proto_info_t payload = {
        .msg_type = CAN_PROTO_MSG_INFO,
        .protocol = CAN_PROTO_PROTOCOL_VERSION,
        .model = CAN_PROTO_MODEL_IO8R8_V1,
        .firmware = (uint16_t)((FW_VERSION_MAJOR << 8) | (FW_VERSION_MINOR & 0xFFu)),
        .inputs_count = EXP_BOARD_INPUT_COUNT,
        .outputs_count = EXP_BOARD_OUTPUT_COUNT,
    };
    can_app_queue_tx(CAN_PROTO_ID_INFO(s_ctx.node_id), &payload, sizeof(payload));
    s_ctx.last_info_ms = millis();
}

static void can_app_send_scan_response(void)
{
    if (s_ctx.node_id == 0u) {
        return;
    }
    can_proto_scan_t payload = {
        .msg_type = CAN_PROTO_MSG_SCAN_RESPONSE,
        .reserved = {0},
    };
    can_app_queue_tx(CAN_PROTO_ID_BROADCAST_SCAN, &payload, sizeof(payload));
}

static void can_app_send_addr_request(void)
{
    can_proto_addr_request_t payload = {
        .protocol = CAN_PROTO_PROTOCOL_VERSION,
    };
    memcpy(payload.uid, s_ctx.uid, sizeof(payload.uid));
    can_app_queue_tx(CAN_PROTO_ID_BROADCAST_ADDR_REQ, &payload, sizeof(payload));
    s_ctx.last_addr_request_ms = millis();
}

static uint8_t can_app_scale_to_u8(float value, float scale)
{
    float scaled = value * scale;
    if (scaled < 0.0f) {
        scaled = 0.0f;
    }
    uint32_t rounded = (uint32_t)(scaled + 0.5f);
    if (rounded > 255u) {
        rounded = 255u;
    }
    return (uint8_t)rounded;
}

static uint16_t can_app_scale_to_u16(float value, float scale, uint16_t max_value)
{
    float scaled = value * scale;
    if (scaled < 0.0f) {
        scaled = 0.0f;
    }
    uint32_t rounded = (uint32_t)(scaled + 0.5f);
    if (rounded > (uint32_t)max_value) {
        rounded = max_value;
    }
    return (uint16_t)rounded;
}

static void can_app_send_extended_heartbeat(void)
{
    if (s_ctx.node_id == 0u) {
        return;
    }

    uint8_t payload[8] = {0};
    payload[0] = zone_monitor_get_alarm_bitmap();
    payload[1] = zone_monitor_get_short_bitmap();
    payload[2] = zone_monitor_get_open_bitmap();
    payload[3] = zone_monitor_get_tamper_bitmap();
    payload[4] = can_app_scale_to_u8(zone_monitor_get_vdda(), 100.0f);
    payload[5] = can_app_scale_to_u8(zone_monitor_get_vbias(), 10.0f);
    payload[6] = can_app_scale_to_u8(zone_monitor_get_temperature_c() + 40.0f, 1.0f);
    payload[7] = (uint8_t)(((FW_VERSION_MAJOR & 0x0Fu) << 4) | (FW_VERSION_MINOR & 0x0Fu));

    can_app_queue_tx(CAN_PROTO_ID_EXT_HEARTBEAT(s_ctx.node_id), payload, sizeof(payload));
}

static void can_app_send_zone_event(const zone_event_t *event)
{
    if (!event || s_ctx.node_id == 0u) {
        return;
    }

    uint8_t payload[8] = {0};
    payload[0] = event->zone_id & 0x07u;

    uint8_t state_bits = 0u;
    if (event->reported_state == ZONE_STATE_ALARM) {
        state_bits |= 0x01u;
    }
    if (event->physical_state == ZONE_STATE_FAULT_SHORT) {
        state_bits |= 0x02u;
    }
    if (event->physical_state == ZONE_STATE_FAULT_OPEN) {
        state_bits |= 0x04u;
    }
    if (event->physical_state == ZONE_STATE_TAMPER) {
        state_bits |= 0x08u;
    }
    if (event->present) {
        state_bits |= 0x10u;
    }
    if (zone_monitor_contact_is_no()) {
        state_bits |= 0x20u;
    }
    payload[1] = state_bits;

    payload[2] = (uint8_t)(event->raw_adc & 0xFFu);
    payload[3] = (uint8_t)((event->raw_adc >> 8) & 0xFFu);

    uint16_t rloop_scaled = can_app_scale_to_u16(event->rloop_ohm, 0.01f, 0xFFFFu);
    payload[4] = (uint8_t)(rloop_scaled & 0xFFu);
    payload[5] = (uint8_t)((rloop_scaled >> 8) & 0xFFu);

    payload[6] = can_app_scale_to_u8(event->vbias_volt, 10.0f);
    payload[7] = event->sequence;

    can_app_queue_tx(CAN_PROTO_ID_EXT_ZONE_EVENT(s_ctx.node_id), payload, sizeof(payload));
}

static bool can_app_uid_matches(const uint8_t *uid, size_t len)
{
    if (!uid || len != sizeof(s_ctx.uid)) {
        return false;
    }
    return (memcmp(uid, s_ctx.uid, sizeof(s_ctx.uid)) == 0);
}

static void can_app_apply_outputs(uint32_t outputs, uint8_t pwm)
{
    (void)pwm;
    s_ctx.outputs = outputs;
    hw_profile_write_outputs(outputs);
}

static void can_app_handle_command(const uint8_t *data, uint8_t len)
{
    if (!data || len == 0) {
        return;
    }

    switch (data[0]) {
    case CAN_PROTO_MSG_OUTPUT_COMMAND:
        if (len >= sizeof(can_proto_output_cmd_t)) {
            const can_proto_output_cmd_t *cmd = (const can_proto_output_cmd_t *)data;
            can_app_apply_outputs(cmd->outputs_bitmap, cmd->pwm_level);
        }
        break;

    case CAN_PROTO_MSG_IDENTIFY:
        if (len >= sizeof(can_proto_identify_cmd_t)) {
            const can_proto_identify_cmd_t *ident = (const can_proto_identify_cmd_t *)data;
            s_ctx.identify_enabled = ident->enable != 0u;
            hw_profile_identify(s_ctx.identify_enabled);
        }
        break;

    case CAN_PROTO_MSG_TEST_TOGGLE:
        if (len >= sizeof(can_proto_test_toggle_t)) {
            const can_proto_test_toggle_t *test = (const can_proto_test_toggle_t *)data;
            s_ctx.identify_enabled = test->enable != 0u;
            hw_profile_identify(s_ctx.identify_enabled);
        }
        break;

    default:
        break;
    }
}
