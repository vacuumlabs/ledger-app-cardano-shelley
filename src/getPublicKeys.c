#include "state.h"
#include "securityPolicy.h"
#include "uiHelpers.h"
#include "uiScreens.h"
#include "getPublicKeys.h"

static int16_t RESPONSE_READY_MAGIC = 23456;

static ins_get_keys_context_t* ctx = &(instructionState.getKeysContext);

static inline void CHECK_STAGE(get_keys_stage_t expected)
{
	TRACE("Checking stage... current one is %d, expected %d", ctx->stage, expected);
	VALIDATE(ctx->stage == expected, ERR_INVALID_STATE);
}

// read a path from view into ctx->pathSpec
static void parsePath(read_view_t* view)
{
	view_skipBytes(view, bip44_parseFromWire(&ctx->pathSpec, VIEW_REMAINING_TO_TUPLE_BUF_SIZE(view)));
	BIP44_PRINTF(&ctx->pathSpec);
}

// ============================== derivation and UI state machine for one key ==============================

enum {
	GET_KEY_UI_STEP_WARNING = 200,
	GET_KEY_UI_STEP_DISPLAY,
	GET_KEY_UI_STEP_CONFIRM,
	GET_KEY_UI_STEP_RESPOND,
	GET_KEY_UI_STEP_INVALID,
} ;

static void getPublicKeys_getOneKey_ui_runStep()
{
	TRACE("UI step %d", ctx->ui_step);
	ui_callback_fn_t* this_fn = getPublicKeys_getOneKey_ui_runStep;

	UI_STEP_BEGIN(ctx->ui_step);
	UI_STEP(GET_KEY_UI_STEP_WARNING) {
		ui_displayPaginatedText(
		        "Unusual request",
		        "Proceed with care",
		        this_fn
		);
	}
	UI_STEP(GET_KEY_UI_STEP_DISPLAY) {
		ui_displayAccountScreen("Export public key", &ctx->pathSpec, this_fn);
	}
	UI_STEP(GET_KEY_UI_STEP_CONFIRM) {
		ui_displayPrompt(
		        "Confirm export",
		        "public key?",
		        this_fn,
		        respond_with_user_reject
		);
	}
	UI_STEP(GET_KEY_UI_STEP_RESPOND) {
		ASSERT(ctx->responseReadyMagic == RESPONSE_READY_MAGIC);

		io_send_buf(SUCCESS, (uint8_t*) &ctx->extPubKey, SIZEOF(ctx->extPubKey));
		ctx->responseReadyMagic = 0; // just for safety

		if (ctx->remainingPaths > 0) {
			ui_displayBusy(); // waiting for another APDU
		} else {
			ui_idle(); // we are done, display the main app screen
		}
	}
	UI_STEP_END(GET_KEY_UI_STEP_INVALID);
}

// derive the key described by ctx->pathSpec and run the ui state machine accordingly
// if isSingleKeyExport is true, more restrictive security policy is applied
static void returnOneKey(bool isSingleKeyExport)
{
	ctx->responseReadyMagic = 0;

	// Check security policy
	security_policy_t policy = (isSingleKeyExport) ?
	                           policyForGetExtendedPublicKey(&ctx->pathSpec) :
	                           policyForGetExtendedPublicKeyBulkExport(&ctx->pathSpec);
	TRACE("Policy: %d", (int) policy);
	ENSURE_NOT_DENIED(policy);

	{
		// Calculation
		deriveExtendedPublicKey(
		        & ctx->pathSpec,
		        & ctx->extPubKey
		);
		ctx->responseReadyMagic = RESPONSE_READY_MAGIC;
	}

	switch (policy) {
#	define  CASE(policy, step) case policy: {ctx->ui_step = step; break;}
		CASE(POLICY_PROMPT_WARN_UNUSUAL,    GET_KEY_UI_STEP_WARNING);
		CASE(POLICY_PROMPT_BEFORE_RESPONSE, GET_KEY_UI_STEP_DISPLAY);
		CASE(POLICY_ALLOW_WITHOUT_PROMPT,   GET_KEY_UI_STEP_RESPOND);
#	undef   CASE
	default:
		ASSERT(false);
	}
	getPublicKeys_getOneKey_ui_runStep();
}

// ============================== INIT ==============================

enum {
	HANDLE_INIT_UI_STEP_CONFIRM = 100,
	HANDLE_INIT_UI_STEP_RESPOND,
	HANDLE_INIT_UI_STEP_INVALID,
} ;

static void getPublicKeys_handleInit_ui_runStep()
{
	TRACE("UI step %d", ctx->ui_step);
	ui_callback_fn_t* this_fn = getPublicKeys_handleInit_ui_runStep;

	UI_STEP_BEGIN(ctx->ui_step);
	UI_STEP(HANDLE_INIT_UI_STEP_CONFIRM) {
		char secondLine[100];
		explicit_bzero(secondLine, SIZEOF(secondLine));
		snprintf(secondLine, SIZEOF(secondLine), "%u public keys?", ctx->remainingPaths);
		ASSERT(strlen(secondLine) < SIZEOF(secondLine));

		ui_displayPrompt(
		        "Confirm export",
		        secondLine,
		        this_fn,
		        respond_with_user_reject
		);
	}
	UI_STEP(HANDLE_INIT_UI_STEP_RESPOND) {
		ASSERT(ctx->remainingPaths > 0);
		returnOneKey(false); // runs another UI state machine

		ctx->stage = GET_KEYS_STAGE_GET_KEYS;
	}
	UI_STEP_END(HANDLE_INIT_UI_STEP_INVALID);
}

static void getPublicKeys_handleInitAPDU(uint8_t* wireDataBuffer, size_t wireDataSize)
{
	{
		CHECK_STAGE(GET_KEYS_STAGE_INIT);

		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}
	{
		// parse data

		TRACE_BUFFER(wireDataBuffer, wireDataSize);
		read_view_t view = make_read_view(wireDataBuffer, wireDataBuffer + wireDataSize);

		parsePath(&view);

		size_t remaining = view_remainingSize(&view);
		switch (remaining) {
		case 0: {
			TRACE();
			ctx->remainingPaths = 0;
			break;
		}
		case 4: {
			// read the number of remaining keys
			uint32_t remainingPaths = parse_u4be(&view);
			ASSERT(view_remainingSize(&view) == 0);
			TRACE("num keys: %d", remainingPaths);
			VALIDATE(remainingPaths <= MAX_PUBLIC_KEYS, ERR_INVALID_DATA);

			ASSERT_TYPE(ctx->remainingPaths, uint16_t);
			ASSERT(remainingPaths <= UINT16_MAX);
			ctx->remainingPaths = (uint16_t) remainingPaths;
			break;
		}
		default: {
			THROW(ERR_INVALID_DATA);
		}
		}
	}

	if (ctx->remainingPaths == 0) {
		// no more keys follow, we are done
		returnOneKey(true);
		return;
	}

	// we ask for confirmation for export of the given number of public keys
	security_policy_t policy = policyForGetPublicKeysInit(ctx->remainingPaths);
	TRACE("Policy: %d", (int) policy);
	ENSURE_NOT_DENIED(policy);
	{
		// select UI steps
		switch (policy) {
#	define  CASE(POLICY, UI_STEP) case POLICY: {ctx->ui_step=UI_STEP; break;}
			CASE(POLICY_PROMPT_BEFORE_RESPONSE, HANDLE_INIT_UI_STEP_CONFIRM);
			CASE(POLICY_ALLOW_WITHOUT_PROMPT,   HANDLE_INIT_UI_STEP_RESPOND);
#	undef   CASE
		default:
			THROW(ERR_NOT_IMPLEMENTED);
		}
	}

	getPublicKeys_handleInit_ui_runStep();
}


// ============================== GET KEY HANDLER ==============================


void getPublicKeys_handleGetNextKeyAPDU(
        uint8_t *wireDataBuffer,
        size_t wireDataSize
)
{
	CHECK_STAGE(GET_KEYS_STAGE_GET_KEYS);

	ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);

	VALIDATE(ctx->remainingPaths >= 1, ERR_INVALID_STATE);
	ctx->remainingPaths--;

	read_view_t view = make_read_view(wireDataBuffer, wireDataBuffer + wireDataSize);
	parsePath(&view);
	VALIDATE(view_remainingSize(&view) == 0, ERR_INVALID_DATA);

	returnOneKey(false);
}

// ============================== MAIN HANDLER ==============================

typedef void subhandler_fn_t(uint8_t* dataBuffer, size_t dataSize);

static subhandler_fn_t* lookup_subhandler(uint8_t p1)
{
	switch(p1) {
#	define  CASE(P1, HANDLER) case P1: return HANDLER;
#	define  DEFAULT(HANDLER)  default: return HANDLER;
		CASE(0x00, getPublicKeys_handleInitAPDU);
		CASE(0x01, getPublicKeys_handleGetNextKeyAPDU);
		DEFAULT(NULL)
#	undef   CASE
#	undef   DEFAULT
	}
}

void getPublicKeys_handleAPDU(
        uint8_t p1,
        uint8_t p2,
        uint8_t* wireDataBuffer,
        size_t wireDataSize,
        bool isNewCall
)
{
	if (isNewCall) {
		explicit_bzero(ctx, SIZEOF(*ctx));
		ctx->stage = GET_KEYS_STAGE_INIT;
	}
	VALIDATE(p2 == P2_UNUSED, ERR_INVALID_REQUEST_PARAMETERS);

	subhandler_fn_t* subhandler = lookup_subhandler(p1);
	VALIDATE(subhandler != NULL, ERR_INVALID_REQUEST_PARAMETERS);
	subhandler(wireDataBuffer, wireDataSize);
}
