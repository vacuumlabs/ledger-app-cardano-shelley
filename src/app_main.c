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

#include "handlers.h"
#include "state.h"
#include "errors.h"
#include "assert.h"
#include "cardano_io.h"

#ifdef HAVE_BAGL
#include "uiScreens_bagl.h"
#elif defined(HAVE_NBGL)
#include "uiScreens_nbgl.h"
#endif

static const int INS_NONE = -1;

static const uint8_t CLA = 0xD7;

// This is the main loop that reads and writes APDUs. It receives request
// APDUs from the computer, looks up the corresponding command handler, and
// calls it on the APDU payload. Then it loops around and calls io_exchange
// again. The handler may set the 'flags' and 'tx' variables, which affect the
// subsequent io_exchange call. The handler may also throw an exception, which
// will be caught, converted to an error code, appended to the response APDU,
// and sent in the next io_exchange call.
void app_main()
{
	ui_idle();

	#ifdef HAVE_NBGL
	ui_idle_flow();
	#endif // HAVE_NBGL

	io_state = IO_EXPECT_IO;

	volatile size_t rx = 0;
	volatile size_t tx = 0;
	volatile uint8_t flags = 0;

	// Exchange APDUs until EXCEPTION_IO_RESET is thrown.
	for (;;) {
		// The Ledger SDK implements a form of exception handling. In addition
		// to explicit THROWs in user code, syscalls (prefixed with os_ or
		// cx_) may also throw exceptions.
		//
		// In sia_main, this TRY block serves to catch any thrown exceptions
		// and convert them to response codes, which are then sent in APDUs.
		// However, EXCEPTION_IO_RESET will be re-thrown and caught by the
		// "true" main function defined in the SDK.
		BEGIN_TRY {
			TRY {
				rx = tx;
				tx = 0; // ensure no race in CATCH_OTHER if io_exchange throws an error
				ASSERT((unsigned int) rx < sizeof(G_io_apdu_buffer));
				rx = (unsigned int) io_exchange((uint8_t) (CHANNEL_APDU | flags), (uint16_t) rx);
				flags = 0;

				// We should be awaiting APDU
				ASSERT(io_state == IO_EXPECT_IO);
				io_state = IO_EXPECT_NONE;

				// No APDU received; trigger a reset.
				if (rx == 0)
				{
					THROW(EXCEPTION_IO_RESET);
				}

				VALIDATE(device_is_unlocked(), ERR_DEVICE_LOCKED);

				// Note(ppershing): unsafe to access before checks
				// Warning(ppershing): in case of unlikely change of APDU format
				// make sure you read wider values as big endian
				struct {
					uint8_t cla;
					uint8_t ins;
					uint8_t p1;
					uint8_t p2;
					uint8_t lc;
				}* header = (void*) G_io_apdu_buffer;

				VALIDATE(rx >= SIZEOF(*header), ERR_MALFORMED_REQUEST_HEADER);

				// check that data is safe to access
				VALIDATE(rx == header->lc + SIZEOF(*header), ERR_MALFORMED_REQUEST_HEADER);

				uint8_t* data = G_io_apdu_buffer + SIZEOF(*header);

				VALIDATE(header->cla == CLA, ERR_BAD_CLA);

				TRACE("APDU: ins = %d,   p1 = %d,    p2 = %d", header->ins, header->p1, header->p2);

				// Lookup and call the requested command handler.
				handler_fn_t* handlerFn = lookupHandler(header->ins);

				VALIDATE(handlerFn != NULL, ERR_UNKNOWN_INS);

				bool isNewCall = false;
				if (currentInstruction == INS_NONE)
				{
					explicit_bzero(&instructionState, SIZEOF(instructionState));
					isNewCall = true;
					currentInstruction = header->ins;
				} else
				{
					VALIDATE(header->ins == currentInstruction, ERR_STILL_IN_CALL);
				}

				// Note: handlerFn is responsible for calling io_send
				// either during its call or subsequent UI actions
				handlerFn(header->p1,
				          header->p2,
				          data,
				          header->lc,
				          isNewCall);
				flags = IO_ASYNCH_REPLY;
			}
			CATCH(EXCEPTION_IO_RESET)
			{
				THROW(EXCEPTION_IO_RESET);
			}
			CATCH(ERR_ASSERT)
			{
				// Note(ppershing): assertions should not auto-respond
				#ifdef RESET_ON_CRASH
				// Reset device
				io_seproxyhal_se_reset();
				#endif
			}
			CATCH_OTHER(e)
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
			FINALLY {
			}
		}
		END_TRY;
	}
}
