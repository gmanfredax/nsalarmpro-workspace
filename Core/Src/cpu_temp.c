#include "cpu_temp.h"
#include "cmsis_os.h"

#define V25_MV 760.0f
#define AVG_SLOPE_MV_PER_C 2.5f

static cpu_temp_sample_t last_sample;

void cpu_temp_update(float adc_voltage_mv)
{
    float temperature = ((V25_MV - adc_voltage_mv) / AVG_SLOPE_MV_PER_C) + 25.0f;
    last_sample.celsius = temperature;
    last_sample.adc_ratio = adc_voltage_mv / 3300.0f;
    last_sample.timestamp = xTaskGetTickCount();
}

bool cpu_temp_get(cpu_temp_sample_t *sample)
{
    if (sample == NULL)
    {
        return false;
    }
    *sample = last_sample;
    return (xTaskGetTickCount() - last_sample.timestamp) < pdMS_TO_TICKS(1000);
}
