#ifndef FLASH_STORE_H
#define FLASH_STORE_H

#include <stdint.h>
#include <stdbool.h>
#include "zones.h"

typedef struct {
    uint8_t provisioned;
    uint8_t tamper_digital_fallback;
    uint16_t reserved_flags;
    char mqtt_host[64];
    uint16_t mqtt_port;
    uint16_t reserved_port;
    char mqtt_username[64];
    char mqtt_password[64];
    char claim_code[32];
    uint16_t ca_cert_len;
    uint16_t reserved_ca;
    uint8_t ca_cert[2048];
    float tamper_short_v;
    float tamper_open_v;
    zone_config_t zone_cfg[NSAP_MAX_ZONES];
} flash_store_blob_t;

bool flash_store_load(flash_store_blob_t *blob);
bool flash_store_save(const flash_store_blob_t *blob);
bool flash_store_erase(void);
bool flash_store_selftest(void);

#endif
