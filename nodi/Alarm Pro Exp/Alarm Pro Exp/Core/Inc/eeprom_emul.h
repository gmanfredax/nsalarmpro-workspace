/*
 * eeprom_emul.h
 *
 *  Created on: Oct 12, 2025
 *      Author: gabriele
 */

#ifndef INC_EEPROM_EMUL_H_
#define INC_EEPROM_EMUL_H_

#include <stdint.h>
#include <stdbool.h>

#include "sdo_slave.h"
#include "pins.h"

#define EEPROM_NODE_ID_ADDR    ((uint32_t)0x0800F800U)
#define EEPROM_CONFIG_ADDR     ((uint32_t)0x0800FC00U)

typedef struct
{
    uint16_t model;
    uint16_t fw_version;
    uint16_t caps;
    uint8_t inputs;
    uint8_t outputs;
} board_info_t;

bool EEPROM_LoadNodeId(uint8_t *node_id);
bool EEPROM_SaveNodeId(uint8_t node_id);
void EEPROM_LoadBoardInfo(board_info_t *info);
void EEPROM_SaveBoardInfo(const board_info_t *info);
void EEPROM_LoadInputConfig(input_config_t *cfg, uint8_t count);
void EEPROM_LoadOutputConfig(output_config_t *cfg, uint8_t count);
void EEPROM_SaveInputConfig(const input_config_t *cfg, uint8_t count);
void EEPROM_SaveOutputConfig(const output_config_t *cfg, uint8_t count);

#endif /* INC_EEPROM_EMUL_H_ */
