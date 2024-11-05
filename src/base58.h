#ifndef H_CARDANO_APP_BASE58
#define H_CARDANO_APP_BASE58

#include <stdint.h>
#include <stddef.h>

size_t base58_encode(const uint8_t* inBuffer, size_t inSize, char* outStr, size_t outMaxSize);

#ifdef DEVEL
void run_base58_test();
#endif  // DEVEL

#endif  // H_CARDANO_APP_BASE58
