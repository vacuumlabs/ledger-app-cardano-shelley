#include "messageSigning.h"
#include "securityPolicy.h"
#include "signCVote.h"
#include "signTxUtils.h"
#include "state.h"
#include "signCVote_ui.h"

#ifdef HAVE_BAGL
#include "uiScreens_bagl.h"
#elif defined(HAVE_NBGL)
#include "uiScreens_nbgl.h"
#include "nbgl_use_case.h"
#endif


static ins_sign_cvote_context_t* ctx = &(instructionState.signCVoteContext);

// ============================== INIT ==============================

void handleInit_ui_runStep()
{
	ui_callback_fn_t* this_fn = handleInit_ui_runStep;

	UI_STEP_BEGIN(ctx->ui_step, this_fn);

	UI_STEP(HANDLE_INIT_CONFIRM_START) {
#ifdef HAVE_BAGL
		ui_displayPrompt(
		        "Start new",
		        "vote? (CIP-36)",
		        this_fn,
		        respond_with_user_reject
		);
#elif defined(HAVE_NBGL)
        set_light_confirmation(true);
        display_prompt("Start new\nvote? (CIP-36)", "", this_fn, respond_with_user_reject);
#endif // HAVE_BAGL
	}
	UI_STEP(HANDLE_INIT_VOTE_PLAN_ID) {
#ifdef HAVE_BAGL
		ui_displayHexBufferScreen(
		        "Vote plan id",
		        ctx->votePlanId, SIZEOF(ctx->votePlanId),
		        this_fn
		);
#elif defined(HAVE_NBGL)
        char bufferHex[2 * 32 + 1] = {0};
        ui_getHexBufferScreen(bufferHex, SIZEOF(bufferHex), ctx->votePlanId, SIZEOF(ctx->votePlanId));
        fill_and_display_if_required("Vote plan id", bufferHex, this_fn, respond_with_user_reject);
#endif // HAVE_BAGL
	}
	UI_STEP(HANDLE_INIT_PROPOSAL_INDEX) {
#ifdef HAVE_BAGL
		ui_displayUint64Screen(
		        "Proposal index",
		        ctx->proposalIndex,
		        this_fn
		);
#elif defined(HAVE_NBGL)
        char line[30];
		ui_getUint64Screen(
                line,
                SIZEOF(line),
		        ctx->proposalIndex
		);
        fill_and_display_if_required("Proposal index", line, this_fn, respond_with_user_reject);
#endif // HAVE_BAGL
	}
	UI_STEP(HANDLE_INIT_PAYLOAD_TYPE_TAG) {
#ifdef HAVE_BAGL
		ui_displayUint64Screen(
		        "Payload type tag",
		        ctx->payloadTypeTag,
		        this_fn
		);
#elif defined(HAVE_NBGL)
        char line[30];
		ui_getUint64Screen(
                line,
                SIZEOF(line),
		        ctx->payloadTypeTag
		);
        fill_and_display_if_required("Payload type tag", line, this_fn, respond_with_user_reject);
#endif // HAVE_BAGL
	}
	UI_STEP(HANDLE_INIT_RESPOND) {
		respondSuccessEmptyMsg();
		vote_advanceStage();
	}
	UI_STEP_END(HANDLE_INIT_INVALID);
}

// ============================== CONFIRM ==============================

void handleConfirm_ui_runStep()
{
	TRACE("UI step %d", ctx->ui_step);
	TRACE_STACK_USAGE();
	ui_callback_fn_t* this_fn = handleConfirm_ui_runStep;

	UI_STEP_BEGIN(ctx->ui_step, this_fn);

	UI_STEP(HANDLE_CONFIRM_STEP_FINAL_CONFIRM) {
#ifdef HAVE_BAGL
		ui_displayPrompt(
		        "Confirm",
		        "vote?",
		        this_fn,
		        respond_with_user_reject
		);
#elif defined(HAVE_NBGL)
        display_confirmation("Confirm\nvote", "", "VOTE\nCONFIRMED", "Vote\nrejected", this_fn, respond_with_user_reject);
#endif // HAVE_BAGL
	}
	UI_STEP(HANDLE_CONFIRM_STEP_RESPOND) {
		io_send_buf(SUCCESS, ctx->votecastHash, SIZEOF(ctx->votecastHash));
#ifdef HAVE_BAGL
		ui_displayBusy(); // displays dots, called only after I/O to avoid freezing
#endif // HAVE_BAGL

		vote_advanceStage();
	}
	UI_STEP_END(HANDLE_CONFIRM_STEP_INVALID);
}

// ============================== WITNESS ==============================

static void _wipeWitnessSignature()
{
	// safer not to keep the signature in memory
	explicit_bzero(ctx->witnessData.signature, SIZEOF(ctx->witnessData.signature));
	respond_with_user_reject();
}

void handleWitness_ui_runStep()
{
	TRACE("UI step %d", ctx->ui_step);
	TRACE_STACK_USAGE();
	ui_callback_fn_t* this_fn = handleWitness_ui_runStep;

	UI_STEP_BEGIN(ctx->ui_step, this_fn);

	UI_STEP(HANDLE_WITNESS_STEP_WARNING) {
#ifdef HAVE_BAGL
		ui_displayPaginatedText(
		        "WARNING:",
		        "unusual witness requested",
		        this_fn
		);
#elif defined(HAVE_NBGL)
        set_light_confirmation(true);
        display_warning("Unusual\nwitness requested", this_fn, respond_with_user_reject);
#endif // HAVE_BAGL
	}
	UI_STEP(HANDLE_WITNESS_STEP_PROMPT) {
#ifdef HAVE_BAGL
        UI_STEP_JUMP(HANDLE_WITNESS_STEP_DISPLAY)
#elif defined(HAVE_NBGL)
        set_light_confirmation(true);
        display_prompt("Review witness", "", this_fn, respond_with_user_reject);
#endif // HAVE_BAGL
	}
	UI_STEP(HANDLE_WITNESS_STEP_DISPLAY) {
#ifdef HAVE_BAGL
		ui_displayPathScreen("Witness path", &ctx->witnessData.path, this_fn);
#elif defined(HAVE_NBGL)
        char pathStr[BIP44_PATH_STRING_SIZE_MAX + 1] = {0};
        ui_getPathScreen(pathStr, SIZEOF(pathStr), &ctx->witnessData.path);
        fill_and_display_if_required("Witness path", pathStr, this_fn, respond_with_user_reject);
#endif // HAVE_BAGL
	}
	UI_STEP(HANDLE_WITNESS_STEP_CONFIRM) {
#ifdef HAVE_BAGL
		ui_displayPrompt(
		        "Sign using",
		        "this witness?",
		        this_fn,
		        _wipeWitnessSignature
		);
#elif defined(HAVE_NBGL)
        display_confirmation("Sign\nusing witness", "", "WITNESS\nCONFIRMED", "Witness\nrejected", this_fn, _wipeWitnessSignature);
#endif // HAVE_BAGL
	}
	UI_STEP(HANDLE_WITNESS_STEP_RESPOND) {
		TRACE("Sending witness data");
		TRACE_BUFFER(ctx->witnessData.signature, SIZEOF(ctx->witnessData.signature));
		io_send_buf(SUCCESS, ctx->witnessData.signature, SIZEOF(ctx->witnessData.signature));
#ifdef HAVE_BAGL
		ui_displayBusy(); // displays dots, called only after I/O to avoid freezing
#endif // HAVE_BAGL

		vote_advanceStage();
	}
	UI_STEP_END(HANDLE_WITNESS_STEP_INVALID);
}

