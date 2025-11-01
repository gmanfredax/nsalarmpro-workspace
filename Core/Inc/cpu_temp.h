#ifndef CPU_TEMP_H
#define CPU_TEMP_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    float celsius;
    float adc_ratio;
    uint32_t timestamp;
} cpu_temp_sample_t;

void cpu_temp_update(float adc_voltage_mv);
bool cpu_temp_get(cpu_temp_sample_t *sample);

#ifdef __cplusplus
}
#endif

#endif
