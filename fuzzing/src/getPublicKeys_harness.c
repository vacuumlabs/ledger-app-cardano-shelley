#include <cx.h>
#include <getPublicKeys.h>
#include <os_io.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

uint8_t G_io_apdu_buffer[IO_APDU_BUFFER_SIZE];

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    UX_INIT();

    uint8_t *input = NULL;
    bool is_first = true;

    while (size > 5) {
        io_state = IO_EXPECT_NONE;
        uint8_t ins = data[0];
        uint8_t p1 = data[1];
        uint8_t p2 = data[2];
        uint8_t lc = data[3];

        data += sizeof(uint8_t) * 4;
        size -= sizeof(uint8_t) * 4;

        if (size < lc) {
            return 0;
        }

        uint8_t *input = malloc(lc);
        if (input == NULL) {
            return 0;
        }

        memcpy(input, data, lc);

        data += lc;
        size -= lc;

        BEGIN_TRY {
            TRY {
                getPublicKeys_handleAPDU(p1, p2, input, lc, is_first);
            }
            CATCH_ALL {
            }
            FINALLY {
            }
        }
        END_TRY;

        is_first = false;
        free(input);
    }
    return 0;
}
