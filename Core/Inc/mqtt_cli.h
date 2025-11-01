#ifndef MQTT_CLI_H
#define MQTT_CLI_H

#include <stdbool.h>
#include <stdint.h>
#include "flash_store.h"
#include "tamper_bus.h"

typedef enum {
    MQTT_STATE_DISCONNECTED = 0,
    MQTT_STATE_BOOTSTRAP,
    MQTT_STATE_CLAIMING,
    MQTT_STATE_OPERATIONAL
} mqtt_state_t;

void mqtt_cli_init(void);
void mqtt_cli_set_bootstrap(const char *host, uint16_t port, const char *password);
void mqtt_cli_set_claim(const char *code);
void mqtt_cli_set_credentials(const char *username, const char *password);
void mqtt_cli_set_ca(const uint8_t *pem, uint16_t len);
void mqtt_cli_tick(void);
void mqtt_cli_publish_telemetry(void);
void mqtt_cli_publish_tamper(tamper_state_t state, bool analog, float voltage_v, float short_thr_v, float open_thr_v);
void mqtt_cli_publish_event(const char *name, const char *json, int qos, bool retained);
void mqtt_cli_publish_diag_report(const char *json);
mqtt_state_t mqtt_cli_get_state(void);
bool mqtt_cli_is_connected(void);

#endif
