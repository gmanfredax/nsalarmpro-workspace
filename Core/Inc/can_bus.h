#ifndef CAN_BUS_H
#define CAN_BUS_H

#include <stdint.h>
#include <stdbool.h>

#define CAN_MAX_NODES 16

typedef struct {
    uint8_t node_id;
    uint32_t last_heartbeat;
    uint8_t capabilities_zones;
    uint8_t capabilities_outputs;
    uint8_t tec;
    uint8_t rec;
    bool online;
} can_node_info_t;

void can_bus_init(void);
void can_bus_process(void);
void can_bus_on_rx(uint32_t id, const uint8_t *data, uint8_t len);
void can_bus_send_heartbeat(void);
bool can_bus_get_snapshot(can_node_info_t *nodes, uint8_t *count);
void can_bus_handle_bus_off(void);

#endif
