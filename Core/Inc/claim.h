#ifndef CLAIM_H
#define CLAIM_H

#include <stdbool.h>
#include <stdint.h>
#include "flash_store.h"

typedef struct {
    char host[64];
    uint16_t port;
    char bootstrap_password[64];
    char claim_code[32];
    char ca_pem[2048];
    uint16_t ca_len;
} claim_context_t;

void claim_init(const claim_context_t *ctx);
bool claim_run(flash_store_blob_t *blob);

#endif
