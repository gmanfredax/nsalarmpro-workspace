/*
 * zone_monitor.h
 *
 *  Created on: Oct 26, 2025
 *      Author: gabriele
 */

#ifndef INC_ZONE_MONITOR_H_
#define INC_ZONE_MONITOR_H_

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "stm32f1xx_hal.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ZONE_MONITOR_ZONE_COUNT 8u

typedef enum {
    ZONE_MODE_EOL1_SERIE = 0,
    ZONE_MODE_EOL2,
    ZONE_MODE_EOL3,
} zone_mode_t;

typedef enum {
    ZONE_CONTACT_NC = 0,
    ZONE_CONTACT_NO,
} zone_contact_t;

typedef enum {
    ZONE_STATE_NORMAL = 0,
    ZONE_STATE_ALARM,
    ZONE_STATE_FAULT_SHORT,
    ZONE_STATE_FAULT_OPEN,
    ZONE_STATE_TAMPER,
} zone_state_t;

typedef struct {
    zone_mode_t mode;
    zone_contact_t contact;
} zone_cfg_t;

typedef struct {
    uint8_t zone_id;
    zone_state_t physical_state;
    zone_state_t reported_state;
    bool present;
    uint16_t raw_adc;
    float rloop_ohm;
    float vbias_volt;
    uint8_t sequence;
} zone_event_t;

void zone_monitor_configure(const zone_cfg_t *cfg);
void zone_monitor_apply_cfg_from_dip(void);
void zone_monitor_init(ADC_HandleTypeDef *hadc);
void zone_monitor_task(uint32_t now_ms);

bool zone_monitor_pop_event(zone_event_t *event_out);

zone_state_t zone_monitor_get_reported_state(uint8_t zone_id);
zone_state_t zone_monitor_get_physical_state(uint8_t zone_id);

uint8_t zone_monitor_get_alarm_bitmap(void);
uint8_t zone_monitor_get_short_bitmap(void);
uint8_t zone_monitor_get_open_bitmap(void);
uint8_t zone_monitor_get_tamper_bitmap(void);
uint8_t zone_monitor_get_present_bitmap(void);
uint8_t zone_monitor_get_legacy_bitmap(void);

float zone_monitor_get_vdda(void);
float zone_monitor_get_vbias(void);
float zone_monitor_get_temperature_c(void);

bool zone_monitor_vbias_warning(void);
bool zone_monitor_contact_is_no(void);
zone_mode_t zone_monitor_get_mode(void);

uint16_t zone_monitor_get_zone_raw(uint8_t zone_id);
float zone_monitor_get_zone_rloop(uint8_t zone_id);

#ifdef __cplusplus
}
#endif

#endif /* INC_ZONE_MONITOR_H_ */
