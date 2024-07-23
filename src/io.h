#ifndef H_CARDANO_APP_IO
#define H_CARDANO_APP_IO

#include <stdint.h>
#include <stdbool.h>
#include <os_io_seproxyhal.h>
#include <ux.h>
#include "ui.h"

enum  {
	P1_UNUSED = 0,
	P2_UNUSED = 0
};

enum {
	ITEM_INCLUDED_NO = 1,
	ITEM_INCLUDED_YES = 2
};

// `io_send_*` are helper functions for sending response APDUs.
// Note that the IO_RETURN_AFTER_TX flag is set so that the function
// does not receive next APDU.
// 'tx' is the conventional name for the size of the response APDU,

void _io_send_G_io_apdu_buffer(uint16_t code, uint16_t tx);

// Normal code should use just this helper function
void io_send_buf(uint16_t code, uint8_t* buffer, size_t bufferSize);

// Asserts that the response fits into response buffer
void CHECK_RESPONSE_SIZE(unsigned int tx);

// This was added for sanity checking -- our program should always be awaiting on something
// and it should be exactly the expected handler
typedef enum {
	// We are doing IO, display handlers should not fire
	IO_EXPECT_IO = 42, // Note: random constants
	// We are displaying things, IO handlers should not fire
	IO_EXPECT_UI = 47,
	// We should not be handling events
	IO_EXPECT_NONE = 49,
} io_state_t;

extern io_state_t io_state;

// Everything below this point is Ledger magic
#ifdef HAVE_BAGL
void io_seproxyhal_display(const bagl_element_t* element);
#endif
#ifndef FUZZING
unsigned char io_event(unsigned char channel);

bool device_is_unlocked();

typedef void timeout_callback_fn_t(bool ux_allowed);
void set_timer(int ms, timeout_callback_fn_t* cb);
void clear_timer();
#endif

#ifdef HAVE_NBGL
void set_app_callback(callback_t cb);
void reset_app_callback(void);
#endif // HAVE_NBGL

#endif // H_CARDANO_APP_IO
