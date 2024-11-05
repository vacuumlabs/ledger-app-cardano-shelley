#include "common.h"
#include "handlers.h"

#include "getSerial.h"
#include "uiHelpers.h"

// required by os_serial
#define SERIAL_LENGTH 7

void getSerial_handleAPDU(uint8_t p1,
                          uint8_t p2,
                          const uint8_t* wireDataBuffer MARK_UNUSED,
                          size_t wireDataSize,
                          bool isNewCall MARK_UNUSED) {
    VALIDATE(p1 == P1_UNUSED, ERR_INVALID_REQUEST_PARAMETERS);
    VALIDATE(p2 == P2_UNUSED, ERR_INVALID_REQUEST_PARAMETERS);
    VALIDATE(wireDataSize == 0, ERR_INVALID_REQUEST_PARAMETERS);

    STATIC_ASSERT(sizeof(uint8_t) == sizeof(unsigned char), "bad unsigned char size");
    STATIC_ASSERT(sizeof(size_t) >= sizeof(unsigned int), "bad unsigned int size");

    uint8_t response[SERIAL_LENGTH] = {0};
    size_t len = os_serial(response, SERIAL_LENGTH);
    ASSERT(len == SERIAL_LENGTH);

    io_send_buf(SUCCESS, response, SERIAL_LENGTH);
    ui_idle();
}
