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

// ctx->ui_state is shared between the intertwined UI state machines below
// it should be set to this value at the beginning and after a UI state machine is finished
static int UI_STEP_NONE = 0;

static void advanceStage()
{
	TRACE("Advancing from stage: %d", ctx->stage);

	switch (ctx->stage) {

	case GET_KEYS_STAGE_INIT:
		ctx->stage = GET_KEYS_STAGE_GET_KEYS;

		if (ctx->numPaths > 1) {
			// there are more paths to be received
			// so we don't want to advance beyond GET_KEYS_STAGE_GET_KEYS
			break;
		}

	// intentional fallthrough

	case GET_KEYS_STAGE_GET_KEYS:
		ASSERT(ctx->currentPath == ctx->numPaths);
		ctx->stage = GET_KEYS_STAGE_NONE;
		ui_idle(); // we are done with this key export
		break;

	case SIGN_STAGE_NONE:
	default:
		ASSERT(false);
	}
}

// ============================== derivation and UI state machine for one key ==============================

#ifdef HAVE_NBGL
static void getPublicKeys_respondOneKey_ui_cb(void) {
    char line1[30] = {0};
    char pathStr[MAX(160,BIP44_PATH_STRING_SIZE_MAX + 1)] = {0};
    ui_getPublicKeyPathScreen(
            line1, SIZEOF(line1),
            pathStr, SIZEOF(pathStr),
            &ctx->pathSpec
            );
    fill_and_display_if_required(line1, pathStr, getPublicKeys_respondOneKey_ui_runStep, respond_with_user_reject);
}
#endif // HAVE_NBGL

void getPublicKeys_respondOneKey_ui_runStep()
{
	TRACE("UI step %d", ctx->ui_step);
	ui_callback_fn_t* this_fn = getPublicKeys_respondOneKey_ui_runStep;

	UI_STEP_BEGIN(ctx->ui_step, this_fn);
	UI_STEP(GET_KEY_UI_STEP_WARNING) {
#ifdef HAVE_BAGL
		ui_displayPaginatedText(
		        "Unusual request",
		        "Proceed with care",
		        this_fn
		);
#elif defined(HAVE_NBGL)
        set_light_confirmation(true);
        display_warning(
                "Unusual request",
                this_fn, 
                respond_with_user_reject
        );
#endif // HAVE_BAGL
	}
    UI_STEP(GET_KEY_UI_STEP_PROMPT) {
#ifdef HAVE_BAGL
        UI_STEP_JUMP(GET_KEY_UI_STEP_DISPLAY)
#elif defined(HAVE_NBGL)
        display_prompt(
                "Export public key",
                "",
                this_fn, 
                respond_with_user_reject
        );
#endif // HAVE_BAGL
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
            ui_getAccountScreeen(
                    line1,
                    SIZEOF(line1),
                    line2,
                    SIZEOF(line2),
                    &ctx->pathSpec
            );
            fill_and_display_if_required(line1, line2, getPublicKeys_respondOneKey_ui_cb, respond_with_user_reject);
        }
        else {
            getPublicKeys_respondOneKey_ui_cb();
        }
#endif // HAVE_BAGL
	}
	UI_STEP(GET_KEY_UI_STEP_CONFIRM) {
#ifdef HAVE_BAGL
		ui_displayPrompt(
		        "Confirm export",
		        "public key?",
		        this_fn,
		        respond_with_user_reject
		);
#elif defined(HAVE_NBGL)
        display_confirmation(
                "Confirm\npublic key export",
                "",
                "PUBLIC KEY\nEXPORTED",
                "Public key\nrejected",
                this_fn, 
                respond_with_user_reject
        );
#endif // HAVE_BAGL
	}
	UI_STEP(GET_KEY_UI_STEP_RESPOND) {
		ASSERT(ctx->responseReadyMagic == RESPONSE_READY_MAGIC);

		io_send_buf(SUCCESS, (uint8_t*) &ctx->extPubKey, SIZEOF(ctx->extPubKey));
		ctx->responseReadyMagic = 0; // just for safety
#ifdef HAVE_BAGL
		ui_displayBusy(); // needs to happen after I/O
#endif // HAVE_BAGL

		ctx->currentPath++;
		TRACE("Current path: %u / %u", ctx->currentPath, ctx->numPaths);

		if (ctx->currentPath == 1 || ctx->currentPath == ctx->numPaths)
			advanceStage();
	}
	UI_STEP_END(UI_STEP_NONE);
}

// ============================== INIT ==============================

void getPublicKeys_handleInit_ui_runStep()
{
	TRACE("UI step %d", ctx->ui_step);
	ui_callback_fn_t* this_fn = getPublicKeys_handleInit_ui_runStep;

	UI_STEP_BEGIN(ctx->ui_step, this_fn);
	UI_STEP(HANDLE_INIT_UI_STEP_CONFIRM) {
		char secondLine[100] = {0};
		explicit_bzero(secondLine, SIZEOF(secondLine));
		STATIC_ASSERT(sizeof(ctx->numPaths) <= sizeof(unsigned), "oversized type for %u");
		STATIC_ASSERT(!IS_SIGNED(ctx->numPaths), "signed type for %u");
		snprintf(secondLine, SIZEOF(secondLine), "%u public keys?", ctx->numPaths);
		// make sure all the information is displayed to the user
		ASSERT(strlen(secondLine) + 1 < SIZEOF(secondLine));

#ifdef HAVE_BAGL
		ui_displayPrompt(
		        "Confirm export",
		        secondLine,
		        this_fn,
		        respond_with_user_reject
		);

#elif defined(HAVE_NBGL)
        set_light_confirmation(true);
        display_prompt(
                "Review export",
		        secondLine,
                this_fn, 
                respond_with_user_reject
        );
#endif // HAVE_BAGL
	}
	UI_STEP(HANDLE_INIT_UI_STEP_RESPOND) {
		ctx->ui_step = UI_STEP_NONE; // we are finished with this UI state machine

		runGetOnePublicKeyUIFlow(); // run another UI state machine

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
