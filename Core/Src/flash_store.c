#include "flash_store.h"
#include "stm32f4xx_hal.h"
#include <string.h>
#include <stddef.h>

#define FLASH_STORE_MAGIC          0x4E534150UL
#define FLASH_STORE_VERSION        0x0003U
#define FLASH_STORE_SLOT_COUNT     2U
#define FLASH_STORE_SLOT_SIZE      (NSAP_FLASH_MAX_SIZE / FLASH_STORE_SLOT_COUNT)

typedef struct
{
    uint32_t magic;
    uint16_t version;
    uint16_t reserved;
    uint32_t length;
    uint32_t crc32;
    uint32_t sequence;
} flash_store_header_t;

static flash_store_blob_t ram_shadow;
static int active_slot = -1;
static uint32_t active_sequence = 0U;
static bool shadow_valid = false;
static bool initialised = false;

static uint32_t flash_store_crc32(const uint8_t *data, size_t length);
static uint32_t flash_store_get_slot_address(uint32_t slot);
static bool flash_store_read_slot(uint32_t slot, flash_store_blob_t *blob, flash_store_header_t *header);
static bool flash_store_validate(const flash_store_header_t *header, const flash_store_blob_t *blob);
static bool flash_store_program(uint32_t address, const uint8_t *data, size_t length);
static uint32_t flash_store_get_sector(uint32_t address);
static bool flash_store_erase_slot(uint32_t slot);
static void flash_store_scan(void);
static void flash_store_initialise(void);

static uint32_t flash_store_crc32(const uint8_t *data, size_t length)
{
    uint32_t crc = 0xFFFFFFFFUL;
    for (size_t i = 0U; i < length; i++)
    {
        uint32_t byte = data[i];
        crc ^= byte;
        for (uint8_t bit = 0U; bit < 8U; bit++)
        {
            uint32_t mask = -(crc & 1UL);
            crc = (crc >> 1U) ^ (0xEDB88320UL & mask);
        }
    }
    return ~crc;
}

static uint32_t flash_store_get_slot_address(uint32_t slot)
{
    return NSAP_FLASH_BASE_ADDR + (slot * FLASH_STORE_SLOT_SIZE);
}

static bool flash_store_read_slot(uint32_t slot, flash_store_blob_t *blob, flash_store_header_t *header)
{
    if (slot >= FLASH_STORE_SLOT_COUNT)
    {
        return false;
    }

    const flash_store_header_t *flash_header = (const flash_store_header_t *)flash_store_get_slot_address(slot);
    const flash_store_blob_t *flash_blob = (const flash_store_blob_t *)(flash_store_get_slot_address(slot) + sizeof(flash_store_header_t));

    if (header != NULL)
    {
        memcpy(header, flash_header, sizeof(flash_store_header_t));
    }
    if (blob != NULL)
    {
        memcpy(blob, flash_blob, sizeof(flash_store_blob_t));
    }

    return true;
}

static bool flash_store_validate(const flash_store_header_t *header, const flash_store_blob_t *blob)
{
    if (header == NULL || blob == NULL)
    {
        return false;
    }

    if (header->magic != FLASH_STORE_MAGIC)
    {
        return false;
    }
    if (header->version != FLASH_STORE_VERSION)
    {
        return false;
    }
    if (header->length != sizeof(flash_store_blob_t))
    {
        return false;
    }
    if (header->crc32 != flash_store_crc32((const uint8_t *)blob, sizeof(flash_store_blob_t)))
    {
        return false;
    }

    return true;
}

static uint32_t flash_store_get_sector(uint32_t address)
{
    if (address < 0x08004000UL)
    {
        return FLASH_SECTOR_0;
    }
    if (address < 0x08008000UL)
    {
        return FLASH_SECTOR_1;
    }
    if (address < 0x0800C000UL)
    {
        return FLASH_SECTOR_2;
    }
    if (address < 0x08010000UL)
    {
        return FLASH_SECTOR_3;
    }
    if (address < 0x08020000UL)
    {
        return FLASH_SECTOR_4;
    }
    if (address < 0x08040000UL)
    {
        return FLASH_SECTOR_5;
    }
    if (address < 0x08060000UL)
    {
        return FLASH_SECTOR_6;
    }
    if (address < 0x08080000UL)
    {
        return FLASH_SECTOR_7;
    }
    if (address < 0x080A0000UL)
    {
        return FLASH_SECTOR_8;
    }
    if (address < 0x080C0000UL)
    {
        return FLASH_SECTOR_9;
    }
    if (address < 0x080E0000UL)
    {
        return FLASH_SECTOR_10;
    }
    return FLASH_SECTOR_11;
}

static bool flash_store_erase_slot(uint32_t slot)
{
    uint32_t base = flash_store_get_slot_address(slot);
    uint32_t end = base + FLASH_STORE_SLOT_SIZE - 1U;
    uint32_t start_sector = flash_store_get_sector(base);
    uint32_t end_sector = flash_store_get_sector(end);
    FLASH_EraseInitTypeDef erase = {0};
    uint32_t sector_error = 0U;

    erase.TypeErase = FLASH_TYPEERASE_SECTORS;
    erase.VoltageRange = FLASH_VOLTAGE_RANGE_3;
    erase.Sector = start_sector;
    erase.NbSectors = (end_sector - start_sector) + 1U;

    if (HAL_FLASHEx_Erase(&erase, &sector_error) != HAL_OK)
    {
        return false;
    }
    return true;
}

static bool flash_store_program(uint32_t address, const uint8_t *data, size_t length)
{
    size_t offset = 0U;
    while (offset < length)
    {
        uint32_t word = 0xFFFFFFFFUL;
        size_t remaining = length - offset;
        size_t copy_len = (remaining >= sizeof(uint32_t)) ? sizeof(uint32_t) : remaining;
        memcpy(&word, data + offset, copy_len);
        if (HAL_FLASH_Program(FLASH_TYPEPROGRAM_WORD, address + offset, word) != HAL_OK)
        {
            return false;
        }
        offset += sizeof(uint32_t);
    }
    return true;
}

static void flash_store_scan(void)
{
    flash_store_blob_t candidate_blob;
    flash_store_header_t candidate_header;
    shadow_valid = false;
    active_slot = -1;
    active_sequence = 0U;

    for (uint32_t slot = 0U; slot < FLASH_STORE_SLOT_COUNT; slot++)
    {
        if (!flash_store_read_slot(slot, &candidate_blob, &candidate_header))
        {
            continue;
        }
        if (!flash_store_validate(&candidate_header, &candidate_blob))
        {
            continue;
        }
        if (!shadow_valid || candidate_header.sequence > active_sequence)
        {
            ram_shadow = candidate_blob;
            active_slot = (int)slot;
            active_sequence = candidate_header.sequence;
            shadow_valid = true;
        }
    }
}

static void flash_store_initialise(void)
{
    if (!initialised)
    {
        flash_store_scan();
        initialised = true;
    }
}

bool flash_store_load(flash_store_blob_t *blob)
{
    if (blob == NULL)
    {
        return false;
    }

    flash_store_initialise();
    if (!shadow_valid)
    {
        return false;
    }

    memcpy(blob, &ram_shadow, sizeof(flash_store_blob_t));
    return true;
}

bool flash_store_save(const flash_store_blob_t *blob)
{
    if (blob == NULL)
    {
        return false;
    }

    flash_store_initialise();

    flash_store_header_t header;
    header.magic = FLASH_STORE_MAGIC;
    header.version = FLASH_STORE_VERSION;
    header.reserved = 0U;
    header.length = sizeof(flash_store_blob_t);
    header.crc32 = flash_store_crc32((const uint8_t *)blob, sizeof(flash_store_blob_t));
    header.sequence = shadow_valid ? (active_sequence + 1U) : 1U;

    uint32_t target_slot = (shadow_valid && active_slot == 0) ? 1U : 0U;
    uint32_t base_address = flash_store_get_slot_address(target_slot);

    if (HAL_FLASH_Unlock() != HAL_OK)
    {
        return false;
    }
    __HAL_FLASH_CLEAR_FLAG(FLASH_FLAG_EOP | FLASH_FLAG_OPERR | FLASH_FLAG_WRPERR |
                           FLASH_FLAG_PGAERR | FLASH_FLAG_PGPERR | FLASH_FLAG_PGSERR);

    bool success = flash_store_erase_slot(target_slot);
    if (success)
    {
        success = flash_store_program(base_address, (const uint8_t *)&header, sizeof(header));
    }
    if (success)
    {
        success = flash_store_program(base_address + sizeof(header), (const uint8_t *)blob, sizeof(flash_store_blob_t));
    }

    HAL_FLASH_Lock();

    if (!success)
    {
        return false;
    }

    flash_store_blob_t verify_blob;
    flash_store_header_t verify_header;
    if (!flash_store_read_slot(target_slot, &verify_blob, &verify_header))
    {
        return false;
    }
    if (!flash_store_validate(&verify_header, &verify_blob))
    {
        return false;
    }

    ram_shadow = verify_blob;
    active_slot = (int)target_slot;
    active_sequence = verify_header.sequence;
    shadow_valid = true;
    initialised = true;

    return true;
}

bool flash_store_erase(void)
{
    flash_store_initialise();

    if (HAL_FLASH_Unlock() != HAL_OK)
    {
        return false;
    }
    __HAL_FLASH_CLEAR_FLAG(FLASH_FLAG_EOP | FLASH_FLAG_OPERR | FLASH_FLAG_WRPERR |
                           FLASH_FLAG_PGAERR | FLASH_FLAG_PGPERR | FLASH_FLAG_PGSERR);

    bool success = true;
    for (uint32_t slot = 0U; slot < FLASH_STORE_SLOT_COUNT; slot++)
    {
        if (!flash_store_erase_slot(slot))
        {
            success = false;
            break;
        }
    }

    HAL_FLASH_Lock();

    if (success)
    {
        memset(&ram_shadow, 0, sizeof(ram_shadow));
        shadow_valid = false;
        active_slot = -1;
        active_sequence = 0U;
    }

    return success;
}

bool flash_store_selftest(void)
{
    flash_store_initialise();

    if (!shadow_valid || active_slot < 0)
    {
        return false;
    }

    flash_store_blob_t verify_blob;
    flash_store_header_t verify_header;
    if (!flash_store_read_slot((uint32_t)active_slot, &verify_blob, &verify_header))
    {
        return false;
    }

    return flash_store_validate(&verify_header, &verify_blob);
}
