#include "bolos_target.h"  // we need target definitions
#if defined(TARGET_NANOX) || defined(TARGET_NANOS2)

#include "os_io_seproxyhal.h"
#include "menu.h"
#include "getVersion.h"
#include "glyphs.h"
#include "app_mode.h"

char expertModeString[9];
static void h_expert_toggle();
void h_expert_update();

// Helper macro for better astyle formatting of UX_FLOW definitions
#define LINES(...) \
    { __VA_ARGS__ }

UX_STEP_NOCB(ux_idle_flow_1_step,
             pbb,
#if defined(DEVEL) || defined(HEADLESS)
             LINES(&C_icon_app, "Warning:", "DEVEL version!")
#else
             LINES(&C_icon_app, "Cardano", "is ready")
#endif
);

UX_STEP_CB_INIT(ux_idle_flow_2_step,
                bn,
                h_expert_update(),
                h_expert_toggle(),
                LINES("Expert mode:", expertModeString));

UX_STEP_NOCB(ux_idle_flow_3_step, bn, LINES("Version", APPVERSION));

UX_STEP_CB(ux_idle_flow_4_step, pb, os_sched_exit(-1), LINES(&C_icon_dashboard_x, "Quit"));

UX_FLOW(ux_idle_flow,
        &ux_idle_flow_1_step,
        &ux_idle_flow_2_step,
        &ux_idle_flow_3_step,
        &ux_idle_flow_4_step);

static void h_expert_toggle() {
    app_mode_set_expert(!app_mode_expert());
    ux_flow_init(0, ux_idle_flow, &ux_idle_flow_2_step);
}

void h_expert_update() {
    snprintf(expertModeString, SIZEOF(expertModeString), "disabled");
    if (app_mode_expert()) {
        snprintf(expertModeString, SIZEOF(expertModeString), "enabled");
    }
}

#endif
