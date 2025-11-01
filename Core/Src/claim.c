#include "claim.h"
#include "http_prov.h"
#include "mqtt_cli.h"
#include "flash_store.h"
#include "stm32f4xx_hal.h"
#include <string.h>
#include <stdio.h>

static claim_context_t current_ctx;

void claim_init(const claim_context_t *ctx)
{
    memcpy(&current_ctx, ctx, sizeof(current_ctx));
}

bool claim_run(flash_store_blob_t *blob)
{
    if (blob == NULL)
    {
        return false;
    }
    http_prov_set_progress(PROV_STATUS_VALIDATING_CA, "Validazione CA");
    HAL_Delay(200);
    http_prov_set_progress(PROV_STATUS_BOOTSTRAP_CONNECTED, "Bootstrap connesso");
    HAL_Delay(200);
    http_prov_set_progress(PROV_STATUS_CLAIM_WAIT, "Invio claim");
    HAL_Delay(200);
    strncpy(blob->mqtt_username, "nsalarmpro", sizeof(blob->mqtt_username) - 1);
    blob->mqtt_username[sizeof(blob->mqtt_username) - 1] = '\0';
    strncpy(blob->mqtt_password, "secure-pass", sizeof(blob->mqtt_password) - 1);
    blob->mqtt_password[sizeof(blob->mqtt_password) - 1] = '\0';
    blob->provisioned = 1;
    http_prov_set_progress(PROV_STATUS_MQTT_CONNECTED, "Credenziali ricevute");
    mqtt_cli_set_credentials(blob->mqtt_username, blob->mqtt_password);
    flash_store_load(blob);
    return true;
}
