#ifndef H_CARDANO_APP_GET_VERSION
#define H_CARDANO_APP_GET_VERSION

#include "handlers.h"
#include "common.h"

// Must be in format x.y.z
#ifndef APPVERSION
#error "Missing -DAPPVERSION=x.y.z in Makefile"
#endif  // APPVERSION
uint16_t getVersion_handleAPDU(uint8_t p1, uint8_t p2, size_t wireDataSize);

#endif  // H_CARDANO_APP_GET_VERSION
