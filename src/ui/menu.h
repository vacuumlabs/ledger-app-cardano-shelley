#ifndef H_CARDANO_APP_MENU
#define H_CARDANO_APP_MENU

#include "os_io_seproxyhal.h"
#include "ux.h"

#if defined(TARGET_NANOS)
extern const ux_menu_entry_t menu_main[5];
void h_expert_update();
#elif defined(TARGET_NANOX) || defined(TARGET_NANOS2)
extern const ux_flow_step_t* const ux_idle_flow[];
#endif

#endif  // H_CARDANO_APP_MENU
