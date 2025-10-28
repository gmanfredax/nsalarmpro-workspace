#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"
#include "can_bus_protocol.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CAN_MAX_NODE_ID          (127u)

/**
 * @brief Initialize CAN master subsystem.
 *
 * Safe to call multiple times; initialization runs only once.
 */
esp_err_t can_master_init(void);

/**
 * @brief Request a CAN scan operation.
 *
 * @param[out] started Optional pointer updated to true when a new scan
 *                     started, false otherwise.
 * @return ESP_OK on success, ESP_ERR_NOT_SUPPORTED when CAN is disabled,
 *         or another esp_err_t value on failure.
 */
esp_err_t can_master_request_scan(bool *started);

/**
 * @brief Send the broadcast test toggle command.
 */
esp_err_t can_master_send_test_toggle(bool enable);

/**
 * @brief Command the outputs of a specific CAN expansion node.
 */
esp_err_t can_master_set_node_outputs(uint8_t node_id,
                                      uint32_t outputs_bitmap,
                                      uint8_t flags,
                                      uint8_t pwm_level);

/**
 * @brief Transmit a raw CAN frame with the provided payload.
 */
esp_err_t can_master_send_raw(uint32_t cob_id, const void *payload, uint8_t len);

/**
 * @brief Send an address assignment frame to the specified expansion node UID.
 */
esp_err_t can_master_assign_address(uint8_t node_id, const uint8_t uid[CAN_PROTO_UID_LENGTH]);

typedef struct {
    uint64_t timestamp_ms;
    uint64_t last_activity_ms;
    uint32_t packets_sent;
    uint32_t packets_received;
    uint32_t packets_lost;
    uint32_t tx_errors;
    uint32_t rx_errors;
    uint32_t offline_events;
    uint32_t nodes_known;
    uint32_t nodes_online;
    bool driver_started;
} can_master_bus_telemetry_t;

typedef struct {
    uint8_t node_id;
    bool exists;
    bool online;
    uint64_t last_seen_ms;
    uint64_t last_online_ms;
    uint32_t heartbeat_count;
    uint32_t info_count;
    uint32_t command_count;
    uint32_t command_errors;
    uint32_t offline_events;
} can_master_node_telemetry_t;

esp_err_t can_master_get_bus_telemetry(can_master_bus_telemetry_t *out);
esp_err_t can_master_get_node_telemetry(uint8_t node_id, can_master_node_telemetry_t *out);

#ifdef __cplusplus
}
#endif