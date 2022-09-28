#include "state.h"
#include "securityPolicy.h"
#include "uiHelpers.h"
#include "uiScreens.h"
#include "getPublicKeys.h"

static int16_t RESPONSE_READY_MAGIC = 23456;

static ins_get_keys_context_t* ctx = &(instructionState.getKeysContext);

// ctx->ui_state is shared between the intertwined UI state machines below
// it should be set to this value at the beginning and after a UI state machine is finished
static int UI_STEP_NONE = 0;

// this is supposed to be called at the beginning of each APDU handler
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
	PRINTF("\n");
}

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

enum {
	GET_KEY_UI_STEP_WARNING = 200,
	GET_KEY_UI_STEP_DISPLAY,
	GET_KEY_UI_STEP_CONFIRM,
	GET_KEY_UI_STEP_RESPOND,
} ;

static void getPublicKeys_respondOneKey_ui_runStep()
{
	TRACE("UI step %d", ctx->ui_step);
	ui_callback_fn_t* this_fn = getPublicKeys_respondOneKey_ui_runStep;

	UI_STEP_BEGIN(ctx->ui_step, this_fn);
	UI_STEP(GET_KEY_UI_STEP_WARNING) {
		ui_displayPaginatedText(
		        "Unusual request",
		        "Proceed with care",
		        this_fn
		);
	}
	UI_STEP(GET_KEY_UI_STEP_DISPLAY) {
		ui_displayGetPublicKeyPathScreen(&ctx->pathSpec, this_fn);
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
		ui_displayBusy(); // displays dots, called only after I/O to avoid freezing

		ctx->currentPath++;
		TRACE("Current path: %u / %u", ctx->currentPath, ctx->numPaths);

		if (ctx->currentPath == 1 || ctx->currentPath == ctx->numPaths)
			advanceStage();
	}
	UI_STEP_END(UI_STEP_NONE);
}

// derive the key described by ctx->pathSpec and run the ui state machine accordingly
static void runGetOnePublicKeyUIFlow()
{
	ASSERT(ctx->ui_step == UI_STEP_NONE); // make sure no ui state machine is running

	ctx->responseReadyMagic = 0;

	// Check security policy
	security_policy_t policy = (ctx->numPaths == 1) ?
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
#define  CASE(policy, step) case policy: {ctx->ui_step = step; break;}
		CASE(POLICY_PROMPT_WARN_UNUSUAL,    GET_KEY_UI_STEP_WARNING);
		CASE(POLICY_PROMPT_BEFORE_RESPONSE, GET_KEY_UI_STEP_DISPLAY);
		CASE(POLICY_ALLOW_WITHOUT_PROMPT,   GET_KEY_UI_STEP_RESPOND);
#undef   CASE
	default:
		THROW(ERR_NOT_IMPLEMENTED);
	}

	getPublicKeys_respondOneKey_ui_runStep();
}

// ============================== INIT ==============================

enum {
	HANDLE_INIT_UI_STEP_CONFIRM = 100,
	HANDLE_INIT_UI_STEP_RESPOND, // WARNING: this must be the last valid step, see below
} ;

static void getPublicKeys_handleInit_ui_runStep()
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

		ui_displayPrompt(
		        "Confirm export",
		        secondLine,
		        this_fn,
		        respond_with_user_reject
		);
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

static void getPublicKeys_handleInitAPDU(const uint8_t* wireDataBuffer, size_t wireDataSize)
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
			// number of remaining paths not given, we default to 0
			TRACE();
			ctx->numPaths = 1;
			break;
		}
		case 4: {
			// read the number of remaining paths
			uint32_t remainingPaths = parse_u4be(&view);
			VALIDATE(remainingPaths < MAX_PUBLIC_KEYS, ERR_INVALID_DATA);
			ASSERT_TYPE(ctx->numPaths, uint16_t);
			ASSERT(remainingPaths < UINT16_MAX);

			ctx->numPaths = (uint16_t) (remainingPaths + 1);

			VALIDATE(view_remainingSize(&view) == 0, ERR_INVALID_DATA);

			break;
		}
		default: {
			THROW(ERR_INVALID_DATA);
		}
		}

		ASSERT(ctx->numPaths > 0);
		ctx->currentPath = 0;
	}

	// we ask for confirmation for export of the given number of public keys
	security_policy_t policy = policyForGetPublicKeysInit(ctx->numPaths);
	TRACE("Policy: %d", (int) policy);
	ENSURE_NOT_DENIED(policy);
	{
		// select UI steps
		switch (policy) {
#define  CASE(POLICY, UI_STEP) case POLICY: {ctx->ui_step=UI_STEP; break;}
			CASE(POLICY_PROMPT_BEFORE_RESPONSE, HANDLE_INIT_UI_STEP_CONFIRM);
			CASE(POLICY_ALLOW_WITHOUT_PROMPT,   HANDLE_INIT_UI_STEP_RESPOND);
#undef   CASE
		default:
			THROW(ERR_NOT_IMPLEMENTED);
		}
	}

	// this UI machine is responsible for returning a key and advancing state
	getPublicKeys_handleInit_ui_runStep();
}


// ============================== GET KEY HANDLER ==============================


void getPublicKeys_handleGetNextKeyAPDU(
        const uint8_t* wireDataBuffer,
        size_t wireDataSize
)
{
	CHECK_STAGE(GET_KEYS_STAGE_GET_KEYS);

	ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);

	VALIDATE(ctx->currentPath < ctx->numPaths, ERR_INVALID_STATE);

	read_view_t view = make_read_view(wireDataBuffer, wireDataBuffer + wireDataSize);
	parsePath(&view);
	VALIDATE(view_remainingSize(&view) == 0, ERR_INVALID_DATA);

	runGetOnePublicKeyUIFlow();
}

// ============================== MAIN HANDLER ==============================

typedef void subhandler_fn_t(const uint8_t* dataBuffer, size_t dataSize);

static subhandler_fn_t* lookup_subhandler(uint8_t p1)
{
	switch (p1) {
#define  CASE(P1, HANDLER) case P1: return HANDLER;
#define  DEFAULT(HANDLER)  default: return HANDLER;
		CASE(0x00, getPublicKeys_handleInitAPDU);
		CASE(0x01, getPublicKeys_handleGetNextKeyAPDU);
		DEFAULT(NULL)
#undef   CASE
#undef   DEFAULT
	}
}

void getPublicKeys_handleAPDU(
        uint8_t p1,
        uint8_t p2,
        const uint8_t* wireDataBuffer,
        size_t wireDataSize,
        bool isNewCall
)
{
	ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);

	if (isNewCall) {
		explicit_bzero(ctx, SIZEOF(*ctx));
		ctx->stage = GET_KEYS_STAGE_INIT;
		ctx->ui_step = UI_STEP_NONE;
	}
	VALIDATE(p2 == P2_UNUSED, ERR_INVALID_REQUEST_PARAMETERS);

	subhandler_fn_t* subhandler = lookup_subhandler(p1);
	VALIDATE(subhandler != NULL, ERR_INVALID_REQUEST_PARAMETERS);
	subhandler(wireDataBuffer, wireDataSize);
}
