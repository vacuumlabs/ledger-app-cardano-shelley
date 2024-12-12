#include "common.h"
#include "handlers.h"

#include "uiHelpers.h"
#include "getVersion.h"

enum {
    FLAG_DEVEL = 1 << 0,
    //	FLAG_HEADLESS =  1 << 1,
    FLAG_APP_XS = 1 << 2,
};

uint16_t getVersion_handleAPDU(uint8_t p1, uint8_t p2, size_t wireDataSize) {
    // Check that we have format "x.y.z"
    STATIC_ASSERT(SIZEOF(APPVERSION) == 5 + 1, "bad APPVERSION length");
    STATIC_ASSERT(MAJOR_VERSION >= 0 && MAJOR_VERSION <= 9,
                  "MAJOR version must be between 0 and 9!");
    STATIC_ASSERT(MINOR_VERSION >= 0 && MINOR_VERSION <= 9,
                  "MINOR version must be between 0 and 9!");
    STATIC_ASSERT(PATCH_VERSION >= 0 && PATCH_VERSION <= 9,
                  "PATCH version must be between 0 and 9!");

    VALIDATE(p1 == P1_UNUSED, ERR_INVALID_REQUEST_PARAMETERS);
    VALIDATE(p2 == P2_UNUSED, ERR_INVALID_REQUEST_PARAMETERS);
    VALIDATE(wireDataSize == 0, ERR_INVALID_DATA);

    struct {
        uint8_t major;
        uint8_t minor;
        uint8_t patch;
        uint8_t flags;
    } response = {
        .major = MAJOR_VERSION,
        .minor = MINOR_VERSION,
        .patch = PATCH_VERSION,
        .flags = 0,  // see below
    };

#ifdef DEVEL
    response.flags |= FLAG_DEVEL;
#endif  // DEVEL
#ifdef APP_XS
    response.flags |= FLAG_APP_XS;
#endif  // APP_XS

    io_send_buf(SUCCESS, (uint8_t*) &response, sizeof(response));
    ui_idle();
    return ERR_NO_RESPONSE;
}
