#pragma once

#include <stdint.h>

// Error codes for swap, to be moved in SDK?
#define ERROR_INTERNAL                0x00
#define ERROR_WRONG_AMOUNT            0x01
#define ERROR_WRONG_DESTINATION       0x02
#define ERROR_WRONG_FEES              0x03
#define ERROR_WRONG_METHOD            0x04
#define ERROR_CROSSCHAIN_WRONG_MODE   0x05
#define ERROR_CROSSCHAIN_WRONG_METHOD 0x06
#define ERROR_CROSSCHAIN_WRONG_HASH   0x07
#define ERROR_GENERIC                 0xFF

// App codes for detail.
#define APP_CODE_DEFAULT 0x00
#define APP_CODE_BAD_INS 0x01

typedef struct {
    const char *str1;
    const char *str2;
} swap_error_t;

void send_swap_error(uint8_t error_code, uint8_t app_code, swap_error_t *error_ctx);
