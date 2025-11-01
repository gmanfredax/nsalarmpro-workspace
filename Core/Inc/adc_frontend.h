#ifndef ADC_FRONTEND_H
#define ADC_FRONTEND_H

#include <stdint.h>
#include <stdbool.h>
#include "config.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    ADC_CHANNEL_ZONE_BASE = 0,
    ADC_CHANNEL_V12 = 10,
    ADC_CHANNEL_VBAT = 11,
    ADC_CHANNEL_TEMP = 12,
    ADC_CHANNEL_VREF = 13,
    ADC_CHANNEL_TAMPER = 14
} adc_frontend_channel_t;

typedef struct {
    float value_mv;
    float ratio;
    uint16_t raw;
    uint32_t timestamp;
} adc_sample_t;

void adc_frontend_init(void);
void adc_frontend_start(void);
void adc_frontend_poll(void);
bool adc_frontend_get_zone(uint8_t index, adc_sample_t *sample);
bool adc_frontend_get_v12(adc_sample_t *sample);
bool adc_frontend_get_vbat(adc_sample_t *sample);
bool adc_frontend_get_cpu_temp(adc_sample_t *sample);
bool adc_frontend_get_tamper(adc_sample_t *sample);
void adc_frontend_on_dma_half_complete(void);
void adc_frontend_on_dma_complete(void);

#ifdef __cplusplus
}
#endif

#endif
