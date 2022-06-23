#include "deriveAddress.h"
#include "state.h"
#include "securityPolicy.h"
#include "uiHelpers.h"
#include "uiScreens.h"
#include "addressUtilsByron.h"
#include "addressUtilsShelley.h"
#include "base58.h"
#include "bech32.h"
#include "bufView.h"

static uint16_t RESPONSE_READY_MAGIC = 11223;

static ins_derive_address_context_t* ctx = &(instructionState.deriveAddressContext);

enum {
	P1_RETURN  = 0x01,
	P1_DISPLAY = 0x02,
};

static void prepareResponse()
{
	ctx->address.size = deriveAddress(
	                            &ctx->addressParams,
	                            ctx->address.buffer, SIZEOF(ctx->address.buffer)
	                    );
	ctx->responseReadyMagic = RESPONSE_READY_MAGIC;
}


static void deriveAddress_return_ui_runStep();
enum {
	RETURN_UI_STEP_WARNING = 100,
	RETURN_UI_STEP_BEGIN,
	RETURN_UI_STEP_SPENDING_PATH,
	RETURN_UI_STEP_STAKING_INFO,
	RETURN_UI_STEP_CONFIRM,
	RETURN_UI_STEP_RESPOND,
	RETURN_UI_STEP_INVALID,
};

static void deriveAddress_handleReturn()
{
	// Check security policy
	security_policy_t policy = policyForReturnDeriveAddress(&ctx->addressParams);
	TRACE("Policy: %d", (int) policy);
	ENSURE_NOT_DENIED(policy);

	prepareResponse();

	switch (policy) {
#define  CASE(POLICY, STEP) case POLICY: {ctx->ui_step=STEP; break;}
		CASE(POLICY_PROMPT_WARN_UNUSUAL,    RETURN_UI_STEP_WARNING);
		CASE(POLICY_PROMPT_BEFORE_RESPONSE, RETURN_UI_STEP_BEGIN);
		CASE(POLICY_ALLOW_WITHOUT_PROMPT,   RETURN_UI_STEP_RESPOND);
#undef   CASE
	default:
		THROW(ERR_NOT_IMPLEMENTED);
	}
	deriveAddress_return_ui_runStep();
}

static void deriveAddress_return_ui_runStep()
{
	TRACE("step %d\n", ctx->ui_step);
	ASSERT(ctx->responseReadyMagic == RESPONSE_READY_MAGIC);
	ui_callback_fn_t* this_fn = deriveAddress_return_ui_runStep;

	UI_STEP_BEGIN(ctx->ui_step, this_fn);

	UI_STEP(RETURN_UI_STEP_WARNING) {
		ui_displayPaginatedText(
		        "Unusual request",
		        "Proceed with care",
		        this_fn
		);
	}
	UI_STEP(RETURN_UI_STEP_BEGIN) {
		ui_displayPaginatedText("Export", "address", this_fn);
	}
	UI_STEP(RETURN_UI_STEP_SPENDING_PATH) {
		if (determineSpendingChoice(ctx->addressParams.type) == SPENDING_NONE) {
			// reward address
			UI_STEP_JUMP(RETURN_UI_STEP_STAKING_INFO);
		}
		ui_displaySpendingInfoScreen(&ctx->addressParams, this_fn);
	}
	UI_STEP(RETURN_UI_STEP_STAKING_INFO) {
		ui_displayStakingInfoScreen(&ctx->addressParams, this_fn);
	}
	UI_STEP(RETURN_UI_STEP_CONFIRM) {
		ui_displayPrompt(
		        "Confirm",
		        "export address?",
		        this_fn,
		        respond_with_user_reject
		);
	}
	UI_STEP(RETURN_UI_STEP_RESPOND) {
		ctx->responseReadyMagic = 0;
		ASSERT(ctx->address.size <= SIZEOF(ctx->address.buffer));

		io_send_buf(SUCCESS, ctx->address.buffer, ctx->address.size);
		ui_idle();
	}
	UI_STEP_END(RETURN_UI_STEP_INVALID);
}


static void deriveAddress_display_ui_runStep();
enum {
	DISPLAY_UI_STEP_WARNING = 200,
	DISPLAY_UI_STEP_INSTRUCTIONS,
	DISPLAY_UI_STEP_SPENDING_INFO,
	DISPLAY_UI_STEP_STAKING_INFO,
	DISPLAY_UI_STEP_ADDRESS,
	DISPLAY_UI_STEP_CONFIRM,
	DISPLAY_UI_STEP_RESPOND,
	DISPLAY_UI_STEP_INVALID
};


static void deriveAddress_handleDisplay()
{
	// Check security policy
	security_policy_t policy = policyForShowDeriveAddress(&ctx->addressParams);
	TRACE("Policy: %d", (int) policy);
	ENSURE_NOT_DENIED(policy);

	prepareResponse();

	switch (policy) {
#define  CASE(policy, step) case policy: {ctx->ui_step=step; break;}
		CASE(POLICY_PROMPT_WARN_UNUSUAL,  DISPLAY_UI_STEP_WARNING);
		CASE(POLICY_SHOW_BEFORE_RESPONSE, DISPLAY_UI_STEP_INSTRUCTIONS);
#undef   CASE
	default:
		THROW(ERR_NOT_IMPLEMENTED);
	}
	deriveAddress_display_ui_runStep();
}

static void deriveAddress_display_ui_runStep()
{
	ASSERT(ctx->responseReadyMagic == RESPONSE_READY_MAGIC);
	ui_callback_fn_t* this_fn = deriveAddress_display_ui_runStep;

	UI_STEP_BEGIN(ctx->ui_step, this_fn);

	UI_STEP(DISPLAY_UI_STEP_WARNING) {
		ui_displayPaginatedText(
		        "Unusual request",
		        "Proceed with care",
		        this_fn
		);
	}
	UI_STEP(DISPLAY_UI_STEP_INSTRUCTIONS) {
		ui_displayPaginatedText(
		        "Verify address",
		        "Make sure it agrees with your computer",
		        this_fn
		);
	}
	UI_STEP(DISPLAY_UI_STEP_SPENDING_INFO) {
		if (determineSpendingChoice(ctx->addressParams.type) == SPENDING_NONE) {
			// reward address
			UI_STEP_JUMP(DISPLAY_UI_STEP_STAKING_INFO);
		}
		ui_displaySpendingInfoScreen(&ctx->addressParams, this_fn);
	}
	UI_STEP(DISPLAY_UI_STEP_STAKING_INFO) {
		ui_displayStakingInfoScreen(&ctx->addressParams, this_fn);
	}
	UI_STEP(DISPLAY_UI_STEP_ADDRESS) {
		ASSERT(ctx->address.size <= SIZEOF(ctx->address.buffer));
		ui_displayAddressScreen(
		        "Address",
		        ctx->address.buffer, ctx->address.size,
		        this_fn
		);
	}
	UI_STEP(DISPLAY_UI_STEP_CONFIRM) {
		ui_displayPrompt(
		        "Confirm",
		        "address?",
		        this_fn,
		        respond_with_user_reject
		);
	}
	UI_STEP(DISPLAY_UI_STEP_RESPOND) {
		io_send_buf(SUCCESS, NULL, 0);
		ui_idle();
	}
	UI_STEP_END(DISPLAY_UI_STEP_INVALID);
}

void deriveAddress_handleAPDU(
        uint8_t p1,
        uint8_t p2,
        const uint8_t *wireDataBuffer,
        size_t wireDataSize,
        bool isNewCall
)
{
	VALIDATE(p2 == P2_UNUSED, ERR_INVALID_REQUEST_PARAMETERS);
	TRACE_BUFFER(wireDataBuffer, wireDataSize);

	// Initialize state
	if (isNewCall) {
		explicit_bzero(ctx, SIZEOF(*ctx));
	}
	ctx->responseReadyMagic = 0;

	read_view_t view = make_read_view(wireDataBuffer, wireDataBuffer + wireDataSize);

	view_parseAddressParams(&view, &ctx->addressParams);

	VALIDATE(view_remainingSize(&view) == 0, ERR_INVALID_DATA);

	switch (p1) {
#define  CASE(P1, HANDLER_FN) case P1: {HANDLER_FN(); break;}
		CASE(P1_RETURN,  deriveAddress_handleReturn);
		CASE(P1_DISPLAY, deriveAddress_handleDisplay);
#undef   CASE
	default:
		THROW(ERR_INVALID_REQUEST_PARAMETERS);
	}
}
