#include "state.h"
#include "securityPolicy.h"
#include "uiHelpers.h"
#include "getPublicKeys.h"
#include "getPublicKeys_ui.h"

#ifdef HAVE_BAGL
#include "uiScreens_bagl.h"
#elif defined(HAVE_NBGL)
#include "nbgl_use_case.h"
#include "uiScreens_nbgl.h"
#endif

static int16_t RESPONSE_READY_MAGIC = 23456;

static ins_get_keys_context_t* ctx = &(instructionState.getKeysContext);

// ============================== derivation and UI state machine for one key
// ==============================

#ifdef HAVE_NBGL
static void getPublicKeys_respondOneKey_ui_cb(void) {
    char line1[30] = {0};
    char pathStr[MAX(160, BIP44_PATH_STRING_SIZE_MAX + 1)] = {0};
    ui_getPublicKeyPathScreen(line1, SIZEOF(line1), pathStr, SIZEOF(pathStr), &ctx->pathSpec);
    fill_and_display_if_required(line1,
                                 pathStr,
                                 getPublicKeys_respondOneKey_ui_runStep,
                                 respond_with_user_reject);
}
#endif  // HAVE_NBGL

void getPublicKeys_respondOneKey_ui_runStep() {
    TRACE("UI step %d", ctx->ui_step);
    ui_callback_fn_t* this_fn = getPublicKeys_respondOneKey_ui_runStep;

    UI_STEP_BEGIN(ctx->ui_step, this_fn);
    UI_STEP(GET_KEY_UI_STEP_WARNING) {
        ui_displayUnusualWarning(this_fn);
    }
    UI_STEP(GET_KEY_UI_STEP_PROMPT) {
#ifdef HAVE_BAGL
        UI_STEP_JUMP(GET_KEY_UI_STEP_DISPLAY)
#elif defined(HAVE_NBGL)
        display_prompt("Export public key", "", this_fn, respond_with_user_reject);
#endif  // HAVE_BAGL
    }
    UI_STEP(GET_KEY_UI_STEP_DISPLAY) {
#ifdef HAVE_BAGL
        ui_displayGetPublicKeyPathScreen(&ctx->pathSpec, this_fn);
#elif defined(HAVE_NBGL)
        set_light_confirmation(true);
        bool showAccountDescription = (bip44_classifyPath(&ctx->pathSpec) == PATH_ORDINARY_ACCOUNT);
        if (showAccountDescription) {
            char line1[30];
            char line2[30];
            ui_getAccountScreen(line1, SIZEOF(line1), line2, SIZEOF(line2), &ctx->pathSpec);
            fill_and_display_if_required(line1,
                                         line2,
                                         getPublicKeys_respondOneKey_ui_cb,
                                         respond_with_user_reject);
        } else {
            getPublicKeys_respondOneKey_ui_cb();
        }
#endif  // HAVE_BAGL
    }
    UI_STEP(GET_KEY_UI_STEP_CONFIRM) {
#ifdef HAVE_BAGL
        ui_displayPrompt("Confirm export", "public key?", this_fn, respond_with_user_reject);
#elif defined(HAVE_NBGL)
        display_confirmation_no_approved_status("Confirm\npublic key export",
                                                "",
                                                "Public key\nrejected",
                                                this_fn,
                                                respond_with_user_reject);
#endif  // HAVE_BAGL
    }
    UI_STEP(GET_KEY_UI_STEP_RESPOND) {
        ASSERT(ctx->responseReadyMagic == RESPONSE_READY_MAGIC);

        io_send_buf(SUCCESS, (uint8_t*) &ctx->extPubKey, SIZEOF(ctx->extPubKey));
        ctx->responseReadyMagic = 0;  // just for safety
#ifdef HAVE_BAGL
        ui_displayBusy();  // needs to happen after I/O
#endif                     // HAVE_BAGL

        ctx->currentPath++;
        TRACE("Current path: %u / %u", ctx->currentPath, ctx->numPaths);

        if (ctx->currentPath == ctx->numPaths) {
#ifdef HAVE_NBGL
            if (!ctx->silent_export) {
                display_status("Public key\nexported");
            }
#endif  // HAVE_NBGL
            keys_advanceStage();
        } else if (ctx->currentPath == 1) {
#ifdef HAVE_NBGL
            nbgl_useCaseSpinner("Processing");
#endif
            keys_advanceStage();
        }
    }
    UI_STEP_END(UI_STEP_NONE);
}

// ============================== INIT ==============================

void getPublicKeys_handleInit_ui_runStep() {
    TRACE("UI step %d", ctx->ui_step);
    ui_callback_fn_t* this_fn = getPublicKeys_handleInit_ui_runStep;

    UI_STEP_BEGIN(ctx->ui_step, this_fn);
    UI_STEP(HANDLE_INIT_UI_STEP_CONFIRM) {
        char secondLine[100] = {0};
        explicit_bzero(secondLine, SIZEOF(secondLine));
        STATIC_ASSERT(sizeof(ctx->numPaths) <= sizeof(unsigned), "oversized type for %u");
        STATIC_ASSERT(!IS_SIGNED(ctx->numPaths), "signed type for %u");
#ifdef HAVE_BAGL
        snprintf(secondLine, SIZEOF(secondLine), "%u public keys?", ctx->numPaths);
#elif defined(HAVE_NBGL)
        snprintf(secondLine,
                 SIZEOF(secondLine),
                 "Allow the Cardano app to\nexport your %u public keys?",
                 ctx->numPaths);
#endif  // HAVE_BAGL
        // make sure all the information is displayed to the user
        ASSERT(strlen(secondLine) + 1 < SIZEOF(secondLine));

#ifdef HAVE_BAGL
        ui_displayPrompt("Confirm export", secondLine, this_fn, respond_with_user_reject);

#elif defined(HAVE_NBGL)
        display_choice("Export Public key ?", secondLine, this_fn, respond_with_user_reject);
#endif  // HAVE_BAGL
    }
    UI_STEP(HANDLE_INIT_UI_STEP_RESPOND) {
        ctx->ui_step = UI_STEP_NONE;  // we are finished with this UI state machine

        runGetOnePublicKeyUIFlow();  // run another UI state machine

        // This return statement is needed to bail out from this UI state machine
        // which would otherwise be in conflict with the (async) UI state
        // machine triggered by promptAndRespondOneKey.

        // Those two machines share the ctx->ui_state variable.
        // Without the return statement, UI_STEP_END would overwrite it.

        // WARNING: This works under the assumption that HANDLE_INIT_UI_STEP_RESPOND
        // is a terminal state of this UI state machine!
        return;
    }
    UI_STEP_END(UI_STEP_NONE);
}
