#include "adc_frontend.h"
#include "stm32f4xx_hal.h"
#include "cmsis_os.h"
#include "FreeRTOS.h"
#include "task.h"
#include "semphr.h"
#include "battery.h"
#include "cpu_temp.h"
#include "tamper_bus.h"
#include <string.h>

extern ADC_HandleTypeDef hadc1;
extern DMA_HandleTypeDef hdma_adc1;
extern void Error_Handler(void);

#if NSAP_ADC3_AVAILABLE
#define ADC_CHANNEL_COUNT (NSAP_MAX_ZONES + 3U)
#else
#define ADC_CHANNEL_COUNT (NSAP_MAX_ZONES + 4U)
#endif
#define ADC_DMA_DEPTH     (NSAP_ZONE_OVERSAMPLE)
#define ADC_AUX_OVERSAMPLE 32U

static uint16_t adc_dma_buffer[ADC_CHANNEL_COUNT * ADC_DMA_DEPTH];
static adc_sample_t zone_samples[NSAP_MAX_ZONES];
static adc_sample_t v12_sample;
static adc_sample_t vbat_sample;
static adc_sample_t temp_sample;
static adc_sample_t tamper_sample;
static uint32_t last_update_tick;

static void adc_process_block(const uint16_t *data);
static bool adc_refresh_aux(void);
#if NSAP_ADC3_AVAILABLE
static SemaphoreHandle_t adc3_mutex;
extern ADC_HandleTypeDef hadc3;
static bool adc3_acquire_samples(uint16_t *v12_raw, uint16_t *tamper_raw);
#endif
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
#if !NSAP_ADC3_AVAILABLE
    v12_sample.value_mv = 0.0f;
    v12_sample.timestamp = 0U;
#endif
#if NSAP_ADC3_AVAILABLE
    if (adc3_mutex == NULL)
    {
        adc3_mutex = xSemaphoreCreateMutex();
    }
    if (adc3_mutex == NULL)
    {
        Error_Handler();
    }
#endif
    (void)adc_refresh_aux();
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

    uint32_t sum_vbat = 0;
    uint32_t sum_temp = 0;
    uint32_t sum_vref = 0;
#if !NSAP_ADC3_AVAILABLE
    uint32_t sum_tamper = 0;
#endif
    for (uint32_t sample = 0; sample < ADC_DMA_DEPTH; sample++)
    {
        const uint16_t *row = &data[sample * ADC_CHANNEL_COUNT];
        sum_vbat += row[ADC_CHANNEL_VBAT];
        sum_temp += row[ADC_CHANNEL_TEMP];
        sum_vref += row[ADC_CHANNEL_VREF];
#if !NSAP_ADC3_AVAILABLE
        sum_tamper += row[ADC_CHANNEL_TAMPER];
#endif
    }
    float vref_mv = convert_to_voltage(sum_vref / ADC_DMA_DEPTH);
    (void)vref_mv;

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

#if !NSAP_ADC3_AVAILABLE
    tamper_sample.raw = sum_tamper / ADC_DMA_DEPTH;
    tamper_sample.value_mv = convert_to_voltage(tamper_sample.raw);
    tamper_sample.ratio = tamper_sample.value_mv / (NSAP_ADC_REFERENCE_VOLT * 1000.0f);
    tamper_sample.timestamp = tick;
#endif
    last_update_tick = tick;
}

static float convert_to_voltage(uint16_t raw)
{
    return (raw / NSAP_ADC_FULL_SCALE) * (NSAP_ADC_REFERENCE_VOLT * 1000.0f);
}

static float ratio_from_voltage(float voltage_mv)
{
    float supply = 12000.0f;
#if NSAP_ADC3_AVAILABLE
    if (v12_sample.value_mv > 0.0f)
    {
        supply = v12_sample.value_mv;
    }
#endif
    return (voltage_mv / supply) * 100.0f;
}

void adc_frontend_on_dma_half_complete(ADC_HandleTypeDef *hadc)
{
    if (hadc->Instance == ADC1)
    {
        adc_process_block(adc_dma_buffer);
    }
}

void adc_frontend_on_dma_complete(ADC_HandleTypeDef *hadc)
{
    if (hadc->Instance == ADC1)
    {
        adc_process_block(&adc_dma_buffer[ADC_CHANNEL_COUNT * (ADC_DMA_DEPTH / 2)]);
    }
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
#if NSAP_ADC3_AVAILABLE
    (void)adc_refresh_aux();
    *sample = v12_sample;
    return (xTaskGetTickCount() - v12_sample.timestamp) < pdMS_TO_TICKS(500);
#else
    *sample = v12_sample;
    return false;
#endif
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
    (void)adc_refresh_aux();
    *sample = tamper_sample;
    if (tamper_sample.timestamp == 0U)
    {
        return false;
    }
    return (xTaskGetTickCount() - tamper_sample.timestamp) < pdMS_TO_TICKS(500);
}

#if NSAP_ADC3_AVAILABLE
static bool adc_refresh_aux(void)
{
    TickType_t now = xTaskGetTickCount();
    if ((now - v12_sample.timestamp) < pdMS_TO_TICKS(200) &&
        (now - tamper_sample.timestamp) < pdMS_TO_TICKS(200))
    {
        return true;
    }

    bool scheduler_started = (xTaskGetSchedulerState() != taskSCHEDULER_NOT_STARTED);
    if (scheduler_started)
    {
        if (adc3_mutex == NULL)
        {
            return false;
        }
        if (xSemaphoreTake(adc3_mutex, pdMS_TO_TICKS(50)) != pdTRUE)
        {
            return false;
        }
    }
    else
    {
        taskENTER_CRITICAL();
    }

    uint16_t raw_v12 = 0;
    uint16_t raw_tamper = 0;
    bool ok = adc3_acquire_samples(&raw_v12, &raw_tamper);

    if (scheduler_started)
    {
        xSemaphoreGive(adc3_mutex);
    }
    else
    {
        taskEXIT_CRITICAL();
    }

    if (!ok)
    {
        return false;
    }

    TickType_t tick = xTaskGetTickCount();
    v12_sample.raw = raw_v12;
    v12_sample.value_mv = convert_to_voltage(v12_sample.raw) * NSAP_V12_SCALE_RATIO;
    v12_sample.ratio = v12_sample.value_mv / (NSAP_V12_SCALE_RATIO * 12000.0f);
    v12_sample.timestamp = tick;

    tamper_sample.raw = raw_tamper;
    tamper_sample.value_mv = convert_to_voltage(tamper_sample.raw);
    tamper_sample.ratio = tamper_sample.value_mv / (NSAP_ADC_REFERENCE_VOLT * 1000.0f);
    tamper_sample.timestamp = tick;

    return true;
}

static bool adc3_acquire_samples(uint16_t *v12_raw, uint16_t *tamper_raw)
{
    if (v12_raw == NULL || tamper_raw == NULL)
    {
        return false;
    }

    uint32_t sum_v12 = 0;
    uint32_t sum_tamper = 0;

    for (uint32_t i = 0; i < ADC_AUX_OVERSAMPLE; i++)
    {
        if (HAL_ADC_Start(&hadc3) != HAL_OK)
        {
            return false;
        }
        if (HAL_ADC_PollForConversion(&hadc3, 10) != HAL_OK)
        {
            HAL_ADC_Stop(&hadc3);
            return false;
        }
        uint32_t v12 = HAL_ADC_GetValue(&hadc3);
        if (HAL_ADC_PollForConversion(&hadc3, 10) != HAL_OK)
        {
            HAL_ADC_Stop(&hadc3);
            return false;
        }
        uint32_t tamper = HAL_ADC_GetValue(&hadc3);
        sum_v12 += v12;
        sum_tamper += tamper;
        HAL_ADC_Stop(&hadc3);
    }

    *v12_raw = sum_v12 / ADC_AUX_OVERSAMPLE;
    *tamper_raw = sum_tamper / ADC_AUX_OVERSAMPLE;
    return true;
}
#else
static bool adc_refresh_aux(void)
{
    (void)last_update_tick;
    return true;
}
#endif
