#include "common.h"
#include "ui.h"
#include "os_io_seproxyhal.h"
#include "ui_callback.h"

#ifdef HAVE_NBGL
callback_t app_callback;
callback_t _callback;

void set_app_callback(callback_t cb) {
    app_callback = cb;
}

void reset_app_callback(void) {
    app_callback = NULL;
}

void app_ticker_event_callback(void) {
    if (app_callback) {
        _callback = app_callback;
        reset_app_callback();
        _callback();
    }
}
#endif

#ifdef HAVE_BAGL
timeout_callback_fn_t* timeout_cb;

void clear_timer() {
    timeout_cb = NULL;
}

void set_timer(int ms, timeout_callback_fn_t* cb) {
    // if TRACE() is enabled, set_timer must be called
    // before ui_ methods, because it causes Ledger Nano S
    // to freeze in debug mode
    // TRACE();
    ASSERT(timeout_cb == NULL);
    ASSERT(ms >= 0);
    timeout_cb = cb;
    UX_CALLBACK_SET_INTERVAL((unsigned) ms);
}

void app_ticker_event_callback(void) {
#ifndef FUZZING
    uint32_t UX_ALLOWED =
        (G_ux_params.len != BOLOS_UX_IGNORE && G_ux_params.len != BOLOS_UX_CONTINUE);
#else
    uint32_t UX_ALLOWED = 0;
#endif
    if (timeout_cb) {
        timeout_callback_fn_t* callback = timeout_cb;
        timeout_cb = NULL; /* clear first if cb() throws */
        callback(UX_ALLOWED);
    }
}
#endif
