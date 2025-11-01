#ifndef HTTP_PROV_H
#define HTTP_PROV_H

#include <stdbool.h>
#include <stdint.h>

typedef enum {
    PROV_STATUS_IDLE = 0,
    PROV_STATUS_VALIDATING_CA,
    PROV_STATUS_BOOTSTRAP_CONNECTED,
    PROV_STATUS_CLAIM_WAIT,
    PROV_STATUS_MQTT_CONNECTED,
    PROV_STATUS_DONE,
    PROV_STATUS_ERROR
} provisioning_status_t;

typedef struct {
    provisioning_status_t status;
    char message[64];
} provisioning_progress_t;

void http_prov_init(void);
void http_prov_set_enabled(bool enabled);
bool http_prov_is_enabled(void);
void http_prov_set_progress(provisioning_status_t status, const char *message);
bool http_prov_get_progress(provisioning_progress_t *progress);
void http_prov_stream_tick(void);
void http_prov_factory_reset(void);

#endif
