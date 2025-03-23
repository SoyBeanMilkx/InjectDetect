#ifndef CHECK_ENV_CRC32_H
#define CHECK_ENV_CRC32_H

#include <stdio.h>
#include <stdint.h>


#ifdef __cplusplus
extern "C" {
#endif

void generate_crc32_table();
uint32_t crc32(const uint8_t *data, size_t length);

#ifdef __cplusplus
}
#endif

#endif
