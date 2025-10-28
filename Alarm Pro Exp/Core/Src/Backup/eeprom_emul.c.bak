/*
 * eeprom_emul.c
 *
 *  Created on: Oct 12, 2025
 *      Author: gabriele
 */


#include "eeprom_emul.h"

#include "stm32f1xx_hal_flash.h"
#include "stm32f1xx_hal_flash_ex.h"

#include <string.h>
#include <stddef.h>

#define FLASH_PAGE_SIZE     0x400U

typedef struct __attribute__((packed))
{
    board_info_t board_info;
    input_config_t inputs[INPUT_CHANNEL_COUNT];
    output_config_t outputs[OUTPUT_CHANNEL_COUNT];
    uint32_t crc;
} config_block_t;

static uint32_t crc32_compute(const uint8_t *data, size_t len)
{
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; ++i)
    {
        crc ^= data[i];
        for (uint8_t j = 0; j < 8; ++j)
        {
            if (crc & 1U)
            {
                crc = (crc >> 1U) ^ 0xEDB88320u;
            }
            else
            {
                crc >>= 1U;
            }
        }
    }
    return ~crc;
}

static const config_block_t *config_flash_ptr(void)
{
    return (const config_block_t *)EEPROM_CONFIG_ADDR;
}

static HAL_StatusTypeDef flash_unlock(void)
{
    if (HAL_FLASH_Unlock() != HAL_OK)
    {
        return HAL_ERROR;
    }
    return HAL_OK;
}

static void flash_lock(void)
{
    HAL_FLASH_Lock();
}

static void flash_erase_page(uint32_t address)
{
    FLASH_EraseInitTypeDef erase = {0};
    uint32_t error = 0;
    erase.TypeErase = FLASH_TYPEERASE_PAGES;
    erase.PageAddress = address;
    erase.NbPages = 1;
    HAL_FLASHEx_Erase(&erase, &error);
}

static bool flash_write_block(uint32_t address, const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; i += 2)
    {
        uint16_t halfword = data[i];
        if ((i + 1U) < len)
        {
            halfword |= ((uint16_t)data[i + 1U] << 8U);
        }
        if (HAL_FLASH_Program(FLASH_TYPEPROGRAM_HALFWORD, address + i, halfword) != HAL_OK)
        {
            return false;
        }
    }
    return true;
}

bool EEPROM_LoadNodeId(uint8_t *node_id)
{
    uint32_t value = *(__IO uint32_t *)EEPROM_NODE_ID_ADDR;
    uint8_t raw = (uint8_t)(value & 0xFFU);
    if (raw == 0xFFU)
    {
        *node_id = 0xFFU;
        return false;
    }
    *node_id = raw;
    return true;
}

bool EEPROM_SaveNodeId(uint8_t node_id)
{
    if (flash_unlock() != HAL_OK)
    {
        return false;
    }
    flash_erase_page(EEPROM_NODE_ID_ADDR);
    uint16_t halfword = node_id | ((uint16_t)0xFFU << 8U);
    bool ok = (HAL_FLASH_Program(FLASH_TYPEPROGRAM_HALFWORD, EEPROM_NODE_ID_ADDR, halfword) == HAL_OK);
    flash_lock();
    return ok;
}

void EEPROM_LoadBoardInfo(board_info_t *info)
{
    const config_block_t *cfg = config_flash_ptr();
    uint32_t computed = crc32_compute((const uint8_t *)cfg, sizeof(config_block_t) - sizeof(uint32_t));
    if (cfg->crc != 0xFFFFFFFFU && cfg->crc == computed)
    {
        *info = cfg->board_info;
    }
    else
    {
        info->model = 0x0101U;
        info->fw_version = 0x0001U;
        info->caps = 0x0001U;
        info->inputs = INPUT_CHANNEL_COUNT;
        info->outputs = OUTPUT_CHANNEL_COUNT;
    }
}

void EEPROM_SaveBoardInfo(const board_info_t *info)
{
    config_block_t current;
    EEPROM_LoadInputConfig(current.inputs, INPUT_CHANNEL_COUNT);
    EEPROM_LoadOutputConfig(current.outputs, OUTPUT_CHANNEL_COUNT);
    current.board_info = *info;
    current.crc = 0U;
    current.crc = crc32_compute((const uint8_t *)&current, sizeof(config_block_t) - sizeof(uint32_t));

    if (flash_unlock() != HAL_OK)
    {
        return;
    }
    flash_erase_page(EEPROM_CONFIG_ADDR);
    flash_write_block(EEPROM_CONFIG_ADDR, (const uint8_t *)&current, sizeof(config_block_t));
    flash_lock();
}

static void load_or_default(config_block_t *cfg)
{
    const config_block_t *stored = config_flash_ptr();
    uint32_t computed = crc32_compute((const uint8_t *)stored, sizeof(config_block_t) - sizeof(uint32_t));
    if (stored->crc != 0xFFFFFFFFU && stored->crc == computed)
    {
        *cfg = *stored;
    }
    else
    {
        cfg->board_info.model = 0x0101U;
        cfg->board_info.fw_version = 0x0001U;
        cfg->board_info.caps = 0x0001U;
        cfg->board_info.inputs = INPUT_CHANNEL_COUNT;
        cfg->board_info.outputs = OUTPUT_CHANNEL_COUNT;
        for (uint8_t i = 0; i < INPUT_CHANNEL_COUNT; ++i)
        {
            cfg->inputs[i].type = INPUT_TYPE_NC;
            cfg->inputs[i].debounce_ms = 30U;
            cfg->inputs[i].inverted = false;
        }
        for (uint8_t i = 0; i < OUTPUT_CHANNEL_COUNT; ++i)
        {
            cfg->outputs[i].type = OUTPUT_TYPE_DIGITAL;
            cfg->outputs[i].default_pwm = 0U;
        }
        cfg->crc = crc32_compute((const uint8_t *)cfg, sizeof(config_block_t) - sizeof(uint32_t));
    }
}

void EEPROM_LoadInputConfig(input_config_t *cfg, uint8_t count)
{
    config_block_t block;
    load_or_default(&block);
    for (uint8_t i = 0; i < count && i < INPUT_CHANNEL_COUNT; ++i)
    {
        cfg[i] = block.inputs[i];
    }
}

void EEPROM_LoadOutputConfig(output_config_t *cfg, uint8_t count)
{
    config_block_t block;
    load_or_default(&block);
    for (uint8_t i = 0; i < count && i < OUTPUT_CHANNEL_COUNT; ++i)
    {
        cfg[i] = block.outputs[i];
    }
}

void EEPROM_SaveInputConfig(const input_config_t *cfg, uint8_t count)
{
    config_block_t block;
    load_or_default(&block);
    for (uint8_t i = 0; i < count && i < INPUT_CHANNEL_COUNT; ++i)
    {
        block.inputs[i] = cfg[i];
    }
    block.crc = crc32_compute((const uint8_t *)&block, sizeof(config_block_t) - sizeof(uint32_t));
    if (flash_unlock() != HAL_OK)
    {
        return;
    }
    flash_erase_page(EEPROM_CONFIG_ADDR);
    flash_write_block(EEPROM_CONFIG_ADDR, (const uint8_t *)&block, sizeof(config_block_t));
    flash_lock();
}

void EEPROM_SaveOutputConfig(const output_config_t *cfg, uint8_t count)
{
    config_block_t block;
    load_or_default(&block);
    for (uint8_t i = 0; i < count && i < OUTPUT_CHANNEL_COUNT; ++i)
    {
        block.outputs[i] = cfg[i];
    }
    block.crc = crc32_compute((const uint8_t *)&block, sizeof(config_block_t) - sizeof(uint32_t));
    if (flash_unlock() != HAL_OK)
    {
        return;
    }
    flash_erase_page(EEPROM_CONFIG_ADDR);
    flash_write_block(EEPROM_CONFIG_ADDR, (const uint8_t *)&block, sizeof(config_block_t));
    flash_lock();
}
