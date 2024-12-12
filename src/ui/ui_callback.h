#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "os_io_seproxyhal.h"
#include "ux.h"
#include "ui.h"

#ifdef HAVE_NBGL
extern callback_t app_callback;
extern callback_t _callback;

void set_app_callback(callback_t cb);
void reset_app_callback(void);
#endif  // HAVE_NBGL

#ifdef HAVE_BAGL
typedef void timeout_callback_fn_t(bool ux_allowed);
extern timeout_callback_fn_t* timeout_cb;
void set_timer(int ms, timeout_callback_fn_t* cb);
void clear_timer();
#endif
