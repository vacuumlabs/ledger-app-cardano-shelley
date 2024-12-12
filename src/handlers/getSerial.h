#ifndef H_CARDANO_APP_GET_SERIAL
#define H_CARDANO_APP_GET_SERIAL

#include "handlers.h"

uint16_t getSerial_handleAPDU(uint8_t p1, uint8_t p2, size_t wireDataSize);

#endif  // H_CARDANO_APP_GET_SERIAL
