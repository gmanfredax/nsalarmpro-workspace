#include "net_lwip.h"
#include "lwip.h"
#include "lwip/netif.h"
#include "lwip/dhcp.h"
#include "lwip/udp.h"
#include "lwip/apps/mdns.h"
#include "lwip/apps/sntp.h"
#include "lwip/prot/ethernet.h"
#include "ethernetif.h"
#include "config.h"
#include "led_rgb.h"
#include "mqtt_cli.h"
#include "stm32f4xx_hal.h"
#include <string.h>
#include <stdio.h>
#include <stddef.h>

extern struct netif gnetif;

static net_state_t current_state = NET_STATE_DOWN;
static struct udp_pcb *discovery_pcb;
static uint32_t last_discovery_tick;
static char hostname[32];
static char device_id[32];
#define NSAP_SNTP_DEFAULT_SERVER   "pool.ntp.org"

#if LWIP_SNTP
static bool sntp_started;
static bool sntp_synced;
static bool sntp_event_pending;
static uint64_t sntp_epoch_base;
static uint32_t sntp_tick_base;
#endif

static void compute_device_id(void);
static void send_discovery(void);

void net_lwip_init(void)
{
    compute_device_id();
    snprintf(hostname, sizeof(hostname), "%s%s", NSAP_DHCP_HOSTNAME_PREFIX, device_id);
    netif_set_hostname(&gnetif, hostname);
    current_state = NET_STATE_DHCP;
    led_rgb_set_pattern(LED_PATTERN_DHCP);
#if LWIP_SNTP
    sntp_started = false;
    sntp_synced = false;
    sntp_event_pending = false;
    sntp_epoch_base = 0ULL;
    sntp_tick_base = 0U;
#endif
}

const char *net_lwip_get_device_id(void)
{
    return device_id;
}

void net_lwip_poll(void)
{
    ethernetif_input(&gnetif);
    sys_check_timeouts();
#if LWIP_SNTP
    if (sntp_event_pending && sntp_synced && mqtt_cli_is_connected())
    {
        uint32_t now_ms = HAL_GetTick();
        uint32_t elapsed_ms = now_ms - sntp_tick_base;
        uint64_t current_ts = sntp_epoch_base + ((uint64_t)elapsed_ms / 1000ULL);
        char payload[48];
        snprintf(payload, sizeof(payload), "{\"ts\":%llu}", (unsigned long long)current_ts);
        mqtt_cli_publish_event("time_sync", payload, 1, false);
        sntp_event_pending = false;
    }
#endif
    if (discovery_pcb != NULL)
    {
        uint32_t now = HAL_GetTick();
        if ((now - last_discovery_tick) > NSAP_UDP_DISCOVERY_PERIOD)
        {
            send_discovery();
            last_discovery_tick = now;
        }
    }
}

net_state_t net_lwip_get_state(void)
{
    return current_state;
}

bool net_lwip_get_ip(char *ip, uint16_t len)
{
    if (ip == NULL)
    {
        return false;
    }
    ip4_addr_t addr = gnetif.ip_addr.u_addr.ip4;
    snprintf(ip, len, "%u.%u.%u.%u",
             (unsigned)ip4_addr1(&addr),
             (unsigned)ip4_addr2(&addr),
             (unsigned)ip4_addr3(&addr),
             (unsigned)ip4_addr4(&addr));
    return true;
}

void net_lwip_on_link(bool up)
{
    if (up)
    {
        current_state = NET_STATE_DHCP;
        led_rgb_set_pattern(LED_PATTERN_DHCP);
    }
    else
    {
        current_state = NET_STATE_DOWN;
        led_rgb_set_pattern(LED_PATTERN_BOOT);
#if LWIP_SNTP
        if (sntp_started)
        {
            sntp_stop();
            sntp_started = false;
        }
#endif
    }
}

void net_lwip_on_status(bool up)
{
    if (up)
    {
        current_state = NET_STATE_READY;
        led_rgb_set_pattern(LED_PATTERN_HTTP_READY);
#if LWIP_SNTP
        if (!sntp_started)
        {
            sntp_setoperatingmode(SNTP_OPMODE_POLL);
            sntp_setservername(0, NSAP_SNTP_DEFAULT_SERVER);
            sntp_init();
            sntp_started = true;
        }
#endif
    }
}

void net_lwip_start_udp_discovery(void)
{
    if (discovery_pcb != NULL)
    {
        return;
    }
    discovery_pcb = udp_new();
    if (discovery_pcb == NULL)
    {
        return;
    }
    udp_bind(discovery_pcb, IP_ADDR_ANY, 0);
    send_discovery();
    last_discovery_tick = HAL_GetTick();
}

static void compute_device_id(void)
{
    uint8_t mac[6];
    memcpy(mac, gnetif.hwaddr, sizeof(mac));
    uint32_t hash = 0;
    for (size_t i = 0; i < sizeof(mac); i++)
    {
        hash = (hash * 131) + mac[i];
    }
    snprintf(device_id, sizeof(device_id), "nsap-%06X", (unsigned)(hash & 0xFFFFFF));
}

static void send_discovery(void)
{
    if (discovery_pcb == NULL)
    {
        return;
    }
    char message[64];
    snprintf(message, sizeof(message), "NSAlarmPro,%s", device_id);
    struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, strlen(message), PBUF_RAM);
    if (p == NULL)
    {
        return;
    }
    memcpy(p->payload, message, strlen(message));
    ip_addr_t dest;
    IP_ADDR4(&dest, 255, 255, 255, 255);
    udp_sendto(discovery_pcb, p, &dest, NSAP_UDP_DISCOVERY_PORT);
    pbuf_free(p);
}

#if LWIP_SNTP
bool net_lwip_time_get(uint64_t *unix_ts)
{
    if (unix_ts == NULL || !sntp_synced)
    {
        return false;
    }
    uint32_t now_ms = HAL_GetTick();
    uint32_t elapsed_ms = now_ms - sntp_tick_base;
    *unix_ts = sntp_epoch_base + ((uint64_t)elapsed_ms / 1000ULL);
    return true;
}

void sntp_set_system_time(u32_t sec)
{
    sntp_epoch_base = (uint64_t)sec;
    sntp_tick_base = HAL_GetTick();
    if (!sntp_synced)
    {
        sntp_event_pending = true;
    }
    sntp_synced = true;
}
#else
bool net_lwip_time_get(uint64_t *unix_ts)
{
    (void)unix_ts;
    return false;
}
#endif
