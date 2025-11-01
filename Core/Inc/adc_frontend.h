#ifndef ADC_FRONTEND_H
#define ADC_FRONTEND_H

#include <stdint.h>
#include <stdbool.h>
#include "config.h"
#include "stm32f4xx_hal.h"

#ifdef __cplusplus
extern "C" {
#endif

#if NSAP_ADC3_AVAILABLE
typedef enum {
    ADC_CHANNEL_ZONE_BASE = 0,
    ADC_CHANNEL_VBAT = NSAP_MAX_ZONES,
    ADC_CHANNEL_TEMP = NSAP_MAX_ZONES + 1,
    ADC_CHANNEL_VREF = NSAP_MAX_ZONES + 2
} adc_frontend_channel_t;
#else
typedef enum {
    ADC_CHANNEL_ZONE_BASE = 0,
    ADC_CHANNEL_TAMPER = NSAP_MAX_ZONES,
    ADC_CHANNEL_VBAT = NSAP_MAX_ZONES + 1,
    ADC_CHANNEL_TEMP = NSAP_MAX_ZONES + 2,
    ADC_CHANNEL_VREF = NSAP_MAX_ZONES + 3
} adc_frontend_channel_t;
#endif

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
void adc_frontend_on_dma_half_complete(ADC_HandleTypeDef *hadc);
void adc_frontend_on_dma_complete(ADC_HandleTypeDef *hadc);

#ifdef __cplusplus
}
#endif

#endif
