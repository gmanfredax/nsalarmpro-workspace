#ifndef NET_LWIP_H
#define NET_LWIP_H

#include <stdbool.h>
#include <stdint.h>

typedef enum {
    NET_STATE_DOWN = 0,
    NET_STATE_DHCP,
    NET_STATE_READY
} net_state_t;

void net_lwip_init(void);
void net_lwip_poll(void);
net_state_t net_lwip_get_state(void);
bool net_lwip_get_ip(char *ip, uint16_t len);
void net_lwip_on_link(bool up);
void net_lwip_on_status(bool up);
void net_lwip_start_udp_discovery(void);
const char *net_lwip_get_device_id(void);
bool net_lwip_time_get(uint64_t *unix_ts);

#endif
