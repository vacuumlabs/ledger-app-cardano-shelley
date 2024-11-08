/*******************************************************************************
 *
 *  (c) 2016 Ledger
 *  (c) 2018 Nebulous
 *  (c) 2019 VacuumLabs
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ********************************************************************************/

// For a nice primer on writing/understanding Ledger NANO S apps
// see https://github.com/LedgerHQ/ledger-app-sia/

#include <stdint.h>
#include <stdbool.h>
#include "os_io_seproxyhal.h"
#include "parser.h"
#include "os.h"
#include "getVersion.h"
#include "getSerial.h"
#include "runTests.h"
#include "handlers.h"
#include "state.h"
#include "common.h"
#include "menu.h"
#include "assert.h"
#include "swap.h"
#include "io_swap.h"

#ifdef HAVE_BAGL
#include "uiScreens_bagl.h"
#elif defined(HAVE_NBGL)
#include "uiScreens_nbgl.h"
#endif

void app_exit(void);

static const int INS_NONE = -1;

bool device_is_unlocked() {
    return os_global_pin_is_validated() == BOLOS_UX_OK;  // Seems to work for api 9/10
}

void io_send_buf(uint16_t code, uint8_t* buffer, size_t tx) {
    // Note(ppershing): we do both checks due to potential overflows
    ASSERT(tx < sizeof(G_io_apdu_buffer));
    ASSERT(tx + 2u < sizeof(G_io_apdu_buffer));

    memmove(G_io_apdu_buffer, buffer, tx);
    U2BE_ENCODE(G_io_apdu_buffer, tx, code);
    tx += 2;
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, tx);

    // From now on we can receive new APDU
    io_state = IO_EXPECT_IO;
}

// This is the main loop that reads and writes APDUs. It receives request
// APDUs from the computer, looks up the corresponding command handler, and
// calls it on the APDU payload. Then it loops around and calls io_exchange
// again. The handler may set the 'flags' and 'tx' variables, which affect the
// subsequent io_exchange call. The handler may also throw an exception, which
// will be caught, converted to an error code, appended to the response APDU,
// and sent in the next io_exchange call.
void app_main(void) {
    volatile uint32_t rx = 0;
    volatile uint8_t flags = 0;
    command_t cmd = {0};
    uint16_t sw = ERR_NOT_IMPLEMENTED;
    bool isNewCall = false;

#ifdef HAVE_SWAP
    if (!G_called_from_swap)
#endif
    {
        ui_idle();
#ifdef HAVE_NBGL
        ui_idle_flow();
#endif  // HAVE_NBGL
    }
    io_state = IO_EXPECT_IO;
    currentInstruction = INS_NONE;

    for (;;) {
        BEGIN_TRY {
            TRY {
                ASSERT(rx < sizeof(G_io_apdu_buffer));
                rx = io_exchange(CHANNEL_APDU | flags, (uint16_t) rx);
                flags = 0;

                // We should be awaiting APDU
                ASSERT(io_state == IO_EXPECT_IO);
                io_state = IO_EXPECT_NONE;

                VALIDATE(device_is_unlocked(), ERR_DEVICE_LOCKED);

                if (apdu_parser(&cmd, G_io_apdu_buffer, rx) == false) {
                    PRINTF("=> BAD LENGTH: %d\n", rx);
                    sw = ERR_MALFORMED_REQUEST_HEADER;
                } else {
                    VALIDATE(cmd.cla == CLA, ERR_BAD_CLA);
                    TRACE("=> CLA=%02x, INS=%02x, P1=%02x, P2=%02x, LC=%02x, CDATA=%.*h",
                          cmd.cla,
                          cmd.ins,
                          cmd.p1,
                          cmd.p2,
                          cmd.lc,
                          cmd.lc,
                          cmd.data);

                    isNewCall = false;
                    if (currentInstruction == INS_NONE) {
                        explicit_bzero(&instructionState, SIZEOF(instructionState));
                        isNewCall = true;
                        currentInstruction = cmd.ins;
                    } else {
                        VALIDATE(cmd.ins == currentInstruction, ERR_STILL_IN_CALL);
                    }

                    sw = handleApdu(&cmd, isNewCall);
                    flags = IO_ASYNCH_REPLY;
                }
                if (sw != ERR_NO_RESPONSE) {
                    THROW(sw);
                }
            }
            CATCH(EXCEPTION_IO_RESET) {
                // reset IO and UX before continuing
                CLOSE_TRY;
                app_exit();
            }
            CATCH(ERR_ASSERT) {
// Note(ppershing): assertions should not auto-respond
#ifdef RESET_ON_CRASH
                // Reset device
                io_seproxyhal_se_reset();
#endif
            }
            CATCH_OTHER(e) {
#ifdef HAVE_SWAP
                if (G_called_from_swap) {
                    if (e == ERR_UNKNOWN_INS) {
                        send_swap_error(ERROR_GENERIC, APP_CODE_BAD_INS, NULL);
                    } else {
                        send_swap_error(ERROR_GENERIC, APP_CODE_DEFAULT, NULL);
                    }
                    // unreachable
                    os_sched_exit(0);
                } else
#endif
                {
                    if (e >= _ERR_AUTORESPOND_START && e < _ERR_AUTORESPOND_END) {
                        io_send_buf(e, NULL, 0);
                        flags = IO_ASYNCH_REPLY;
#ifdef HAVE_NBGL
                        if (e != ERR_REJECTED_BY_USER) {
                            ui_idle();
                            display_error();
                        }
#else
                        ui_idle();
#endif
                    } else {
                        PRINTF("Uncaught error 0x%x", (unsigned) e);
#ifdef RESET_ON_CRASH
                        // Reset device
                        io_seproxyhal_se_reset();
#endif
                    }
                }
            }
            FINALLY {
            }
        }
        END_TRY;
    }
}
