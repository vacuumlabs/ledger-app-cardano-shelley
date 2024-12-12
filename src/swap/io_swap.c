#include <stddef.h>
#include <stdint.h>

#include "os_io.h"
#include "swap.h"
#include "io_swap.h"
#include "common.h"

#ifdef HAVE_SWAP

static void set_error(const char *str, uint32_t *tx) {
    uint32_t len = 0;
    if (str) {
        PRINTF("SWAP Error message: %s\n", str);
        // Do we have enough space to add a separator (and the status_word)?
        if ((*tx + 1 + 2) < sizeof(G_io_apdu_buffer)) {
            G_io_apdu_buffer[*tx] = '#';
            *tx += 1;
        }
        // Do we have enough space to add at least one character (and the status_word)?
        if ((*tx + 1 + 2) < sizeof(G_io_apdu_buffer)) {
            // If the string is too long, truncate it
            len = MIN(strlen((const char *) str), sizeof(G_io_apdu_buffer) - *tx - 2);
            memmove(G_io_apdu_buffer + *tx, str, len);
            *tx += len;
            if (len < strlen((const char *) str)) {
                PRINTF("Truncated %s to %d bytes\n", str, len);
                G_io_apdu_buffer[*tx - 1] = '*';
            }
        }
    }
}

__attribute__((noreturn)) void send_swap_error(uint8_t error_code,
                                               uint8_t app_code,
                                               swap_error_t *error_ctx) {
    uint32_t tx = 0;
    PRINTF("send_swap_error: error_code=0x%02x, app_code=0x%02x\n", error_code, app_code);
    // Set RAPDU error codes
    G_io_apdu_buffer[tx++] = error_code;
    G_io_apdu_buffer[tx++] = app_code;
    // Set RAPDU error message
    if (error_ctx) {
        set_error(error_ctx->str1, &tx);
        set_error(error_ctx->str2, &tx);
    }

    // Set RAPDU status word, with previous check we are sure there is at least 2 bytes left
    U2BE_ENCODE(G_io_apdu_buffer, tx, ERR_SWAP_FAIL);
    tx += 2;
    // Send RAPDU
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, tx);
    // In case of success, the apdu is sent immediately and eth exits
    // Reaching this code means we encountered an error
    swap_finalize_exchange_sign_transaction(false);
    // unreachable
    os_sched_exit(0);
}

#endif  // HAVE_SWAP
