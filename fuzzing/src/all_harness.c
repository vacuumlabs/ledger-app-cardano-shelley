#include <cx.h>
#include <handlers.h>
#include <os_io.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <state.h>
#include <parser.h>

uint8_t G_io_apdu_buffer[IO_APDU_BUFFER_SIZE];

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    uint8_t *input = NULL;
    bool is_first = true;
    command_t cmd = {0};

    while (size > 5) {
        io_state = IO_EXPECT_NONE;
        cmd.ins = data[0];
        cmd.p1 = data[1];
        cmd.p2 = data[2];
        cmd.lc = data[3];

        data += sizeof(uint8_t) * 4;
        size -= sizeof(uint8_t) * 4;

        if (size < cmd.lc) {
            return 0;
        }

        cmd.data = malloc(cmd.lc);
        if (input == NULL) {
            return 0;
        }

        memcpy(input, data, cmd.lc);

        data += cmd.lc;
        size -= cmd.lc;

        BEGIN_TRY {
            TRY {
                handleApdu(&cmd, is_first);
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
