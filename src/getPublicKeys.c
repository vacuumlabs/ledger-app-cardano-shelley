#include "state.h"
#include "securityPolicy.h"
#include "uiHelpers.h"
#include "getPublicKeys.h"
#include "getPublicKeys_ui.h"

#ifdef HAVE_BAGL
#include "uiScreens_bagl.h"
#elif defined(HAVE_NBGL)
#include "uiScreens_nbgl.h"
#endif

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

// ============================== derivation and UI state machine for one key ==============================

// derive the key described by ctx->pathSpec and run the ui state machine accordingly
void runGetOnePublicKeyUIFlow()
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
