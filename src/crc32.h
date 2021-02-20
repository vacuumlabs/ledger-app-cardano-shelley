#ifndef H_CARDANO_APP_CRC32
#define H_CARDANO_APP_CRC32

#include "common.h"

uint32_t crc32(const uint8_t* inBuffer, size_t inSize);


#ifdef DEVEL
void run_crc32_test();
#endif

#endif // H_CARDANO_APP_CRC32
