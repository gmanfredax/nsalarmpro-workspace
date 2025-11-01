#include "adc_frontend.h"
#include "stm32f4xx_hal.h"
#include "cmsis_os.h"
#include "battery.h"
#include "cpu_temp.h"
#include "tamper_bus.h"
#include <string.h>

extern ADC_HandleTypeDef hadc1;
extern DMA_HandleTypeDef hdma_adc1;

#define ADC_CHANNEL_COUNT 15
#define ADC_DMA_DEPTH     (NSAP_ZONE_OVERSAMPLE)

static uint16_t adc_dma_buffer[ADC_CHANNEL_COUNT * ADC_DMA_DEPTH];
static adc_sample_t zone_samples[NSAP_MAX_ZONES];
static adc_sample_t v12_sample;
static adc_sample_t vbat_sample;
static adc_sample_t temp_sample;
static adc_sample_t tamper_sample;
static uint32_t last_update_tick;

static void adc_process_block(const uint16_t *data);
static float convert_to_voltage(uint16_t raw);
static float ratio_from_voltage(float voltage_mv);

void adc_frontend_init(void)
{
    memset(zone_samples, 0, sizeof(zone_samples));
    memset(&v12_sample, 0, sizeof(v12_sample));
    memset(&vbat_sample, 0, sizeof(vbat_sample));
    memset(&temp_sample, 0, sizeof(temp_sample));
    memset(&tamper_sample, 0, sizeof(tamper_sample));
    last_update_tick = 0;
}

void adc_frontend_start(void)
{
    HAL_ADC_Start_DMA(&hadc1, (uint32_t *)adc_dma_buffer, ADC_CHANNEL_COUNT * ADC_DMA_DEPTH);
}

void adc_frontend_poll(void)
{
    (void)HAL_ADC_PollForConversion(&hadc1, 1);
}

static void adc_process_block(const uint16_t *data)
{
    uint32_t tick = xTaskGetTickCount();
    for (uint8_t zone = 0; zone < NSAP_MAX_ZONES; zone++)
    {
        uint32_t sum = 0;
        for (uint32_t sample = 0; sample < ADC_DMA_DEPTH; sample++)
        {
            sum += data[sample * ADC_CHANNEL_COUNT + zone];
        }
        uint16_t raw = sum / ADC_DMA_DEPTH;
        float voltage_mv = convert_to_voltage(raw);
        zone_samples[zone].raw = raw;
        zone_samples[zone].value_mv = voltage_mv;
        zone_samples[zone].ratio = ratio_from_voltage(voltage_mv);
        zone_samples[zone].timestamp = tick;
    }

    uint32_t sum_v12 = 0;
    uint32_t sum_vbat = 0;
    uint32_t sum_temp = 0;
    uint32_t sum_vref = 0;
    uint32_t sum_tamper = 0;
    for (uint32_t sample = 0; sample < ADC_DMA_DEPTH; sample++)
    {
        const uint16_t *row = &data[sample * ADC_CHANNEL_COUNT];
        sum_v12 += row[10];
        sum_vbat += row[11];
        sum_tamper += row[12];
        sum_temp += row[13];
        sum_vref += row[14];
    }
    float vref_mv = convert_to_voltage(sum_vref / ADC_DMA_DEPTH);
    (void)vref_mv;

    v12_sample.raw = sum_v12 / ADC_DMA_DEPTH;
    v12_sample.value_mv = convert_to_voltage(v12_sample.raw) * NSAP_V12_SCALE_RATIO;
    v12_sample.ratio = v12_sample.value_mv / (NSAP_V12_SCALE_RATIO * 12000.0f);
    v12_sample.timestamp = tick;

    vbat_sample.raw = sum_vbat / ADC_DMA_DEPTH;
    vbat_sample.value_mv = convert_to_voltage(vbat_sample.raw) * NSAP_VBAT_SCALE_RATIO;
    vbat_sample.ratio = vbat_sample.value_mv / (NSAP_VBAT_SCALE_RATIO * 12000.0f);
    vbat_sample.timestamp = tick;
    battery_update(vbat_sample.value_mv / 1000.0f);

    temp_sample.raw = sum_temp / ADC_DMA_DEPTH;
    temp_sample.value_mv = convert_to_voltage(temp_sample.raw);
    temp_sample.ratio = (float)temp_sample.raw / NSAP_ADC_FULL_SCALE;
    temp_sample.timestamp = tick;
    cpu_temp_update(temp_sample.value_mv);

    tamper_sample.raw = sum_tamper / ADC_DMA_DEPTH;
    tamper_sample.value_mv = convert_to_voltage(tamper_sample.raw);
    tamper_sample.ratio = tamper_sample.value_mv / (NSAP_ADC_REFERENCE_VOLT * 1000.0f);
    tamper_sample.timestamp = tick;

    last_update_tick = tick;
}

static float convert_to_voltage(uint16_t raw)
{
    return (raw / NSAP_ADC_FULL_SCALE) * (NSAP_ADC_REFERENCE_VOLT * 1000.0f);
}

static float ratio_from_voltage(float voltage_mv)
{
    float supply = v12_sample.value_mv > 0.0f ? v12_sample.value_mv : 12000.0f;
    return (voltage_mv / supply) * 100.0f;
}

void adc_frontend_on_dma_half_complete(void)
{
    adc_process_block(adc_dma_buffer);
}

void adc_frontend_on_dma_complete(void)
{
    adc_process_block(&adc_dma_buffer[ADC_CHANNEL_COUNT * (ADC_DMA_DEPTH / 2)]);
}

bool adc_frontend_get_zone(uint8_t index, adc_sample_t *sample)
{
    if (index >= NSAP_MAX_ZONES || sample == NULL)
    {
        return false;
    }
    *sample = zone_samples[index];
    return (xTaskGetTickCount() - zone_samples[index].timestamp) < pdMS_TO_TICKS(500);
}

bool adc_frontend_get_v12(adc_sample_t *sample)
{
    if (sample == NULL)
    {
        return false;
    }
    *sample = v12_sample;
    return (xTaskGetTickCount() - v12_sample.timestamp) < pdMS_TO_TICKS(500);
}

bool adc_frontend_get_vbat(adc_sample_t *sample)
{
    if (sample == NULL)
    {
        return false;
    }
    *sample = vbat_sample;
    return (xTaskGetTickCount() - vbat_sample.timestamp) < pdMS_TO_TICKS(500);
}

bool adc_frontend_get_cpu_temp(adc_sample_t *sample)
{
    if (sample == NULL)
    {
        return false;
    }
    *sample = temp_sample;
    return (xTaskGetTickCount() - temp_sample.timestamp) < pdMS_TO_TICKS(500);
}

bool adc_frontend_get_tamper(adc_sample_t *sample)
{
    if (sample == NULL)
    {
        return false;
    }
    *sample = tamper_sample;
    return (xTaskGetTickCount() - tamper_sample.timestamp) < pdMS_TO_TICKS(500);
}
