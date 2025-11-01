#ifndef OUTPUTS_H
#define OUTPUTS_H

#include <stdint.h>
#include <stdbool.h>

typedef enum {
    OUTPUT_SIREN_INT = 0,
    OUTPUT_SIREN_EXT,
    OUTPUT_NEBBIOGENO,
    OUTPUT_OUT1,
    OUTPUT_OUT2,
    OUTPUT_COUNT
} output_channel_t;

typedef struct {
    bool active;
    uint32_t timeout_ms;
    uint32_t activated_at;
} output_state_t;

void outputs_init(void);
void outputs_set(output_channel_t output, bool state, uint32_t timeout_ms);
void outputs_process(void);
bool outputs_get_state(output_channel_t output, output_state_t *state);
bool outputs_handle_json(const char *json, int len);

#endif
