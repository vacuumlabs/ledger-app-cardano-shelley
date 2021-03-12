#include "common.h"

#include "signOpCert.h"
#include "keyDerivation.h"
#include "endian.h"
#include "state.h"
#include "uiHelpers.h"
#include "uiScreens.h"
#include "securityPolicy.h"
#include "messageSigning.h"
#include "textUtils.h"

static ins_sign_op_cert_context_t* ctx = &(instructionState.signOpCertContext);


static int16_t RESPONSE_READY_MAGIC = 31678;

// forward declaration
static void signOpCert_ui_runStep();
enum {
	UI_STEP_WARNING = 100,
	UI_STEP_CONFIRM_START,
	UI_STEP_DISPLAY_POOL_COLD_KEY_PATH,
	UI_STEP_DISPLAY_POOL_ID,
	UI_STEP_DISPLAY_KES_PUBLIC_KEY,
	UI_STEP_DISPLAY_KES_PERIOD,
	UI_STEP_DISPLAY_ISSUE_COUNTER,
	UI_STEP_CONFIRM,
	UI_STEP_RESPOND,
	UI_STEP_INVALID,
};

void signOpCert_handleAPDU(
        uint8_t p1,
        uint8_t p2,
        uint8_t *wireDataBuffer,
        size_t wireDataSize,
        bool isNewCall
)
{
	// Initialize state
	if (isNewCall) {
		explicit_bzero(ctx, SIZEOF(*ctx));
	}
	ctx->responseReadyMagic = 0;

	// Validate params
	VALIDATE(p1 == P1_UNUSED, ERR_INVALID_REQUEST_PARAMETERS);
	VALIDATE(p2 == P2_UNUSED, ERR_INVALID_REQUEST_PARAMETERS);

	{
		TRACE_BUFFER(wireDataBuffer, wireDataSize);
		read_view_t view = make_read_view(wireDataBuffer, wireDataBuffer + wireDataSize);

		STATIC_ASSERT(SIZEOF(ctx->kesPublicKey) == KES_PUBLIC_KEY_LENGTH, "wrong KES public key size");
		VALIDATE(view_remainingSize(&view) >= KES_PUBLIC_KEY_LENGTH, ERR_INVALID_DATA);
		view_memmove(ctx->kesPublicKey, &view, KES_PUBLIC_KEY_LENGTH);
		TRACE("KES key:");
		TRACE_BUFFER(ctx->kesPublicKey, KES_PUBLIC_KEY_LENGTH);

		VALIDATE(view_remainingSize(&view) >= 8, ERR_INVALID_DATA);
		ctx->kesPeriod = parse_u8be(&view);
		TRACE("KES period:");
		TRACE_UINT64(ctx->kesPeriod);

		VALIDATE(view_remainingSize(&view) >= 8, ERR_INVALID_DATA);
		ctx->issueCounter = parse_u8be(&view);
		TRACE("Issue counter:");
		TRACE_UINT64(ctx->issueCounter);

		view_skipBytes(&view, bip44_parseFromWire(&ctx->poolColdKeyPathSpec, VIEW_REMAINING_TO_TUPLE_BUF_SIZE(&view)));

		ASSERT(view_remainingSize(&view) == 0);
	}

	// Check security policy
	security_policy_t policy = policyForSignOpCert(&ctx->poolColdKeyPathSpec);
	ENSURE_NOT_DENIED(policy);

	{
		uint8_t opCertBodyBuffer[OP_CERT_BODY_LENGTH];
		write_view_t opCertBodyBufferView = make_write_view(opCertBodyBuffer, opCertBodyBuffer + OP_CERT_BODY_LENGTH);

		view_appendData(&opCertBodyBufferView, (const uint8_t*) &ctx->kesPublicKey, SIZEOF(ctx->kesPublicKey));
		{
			uint8_t chunk[8];
			u8be_write(chunk, ctx->issueCounter);
			view_appendData(&opCertBodyBufferView, chunk, SIZEOF(chunk));
		}
		{
			uint8_t chunk[8];
			u8be_write(chunk, ctx->kesPeriod);
			view_appendData(&opCertBodyBufferView, chunk, SIZEOF(chunk));
		}

		ASSERT(view_processedSize(&opCertBodyBufferView) == OP_CERT_BODY_LENGTH);
		TRACE_BUFFER(opCertBodyBuffer, SIZEOF(opCertBodyBuffer));

		getOpCertSignature(
		        &ctx->poolColdKeyPathSpec,
		        opCertBodyBuffer,
		        OP_CERT_BODY_LENGTH,
		        ctx->signature,
		        SIZEOF(ctx->signature)
		);
	}
	ctx->responseReadyMagic = RESPONSE_READY_MAGIC;

	switch (policy) {
#	define  CASE(policy, step) case policy: {ctx->ui_step = step; break;}
		CASE(POLICY_PROMPT_WARN_UNUSUAL,    UI_STEP_WARNING);
		CASE(POLICY_PROMPT_BEFORE_RESPONSE, UI_STEP_CONFIRM_START);
		CASE(POLICY_ALLOW_WITHOUT_PROMPT,   UI_STEP_RESPOND);
#	undef   CASE
	default:
		THROW(ERR_NOT_IMPLEMENTED);
	}
	signOpCert_ui_runStep();
}

static void signOpCert_ui_runStep()
{
	ui_callback_fn_t* this_fn = signOpCert_ui_runStep;

	UI_STEP_BEGIN(ctx->ui_step, this_fn);

	UI_STEP(UI_STEP_WARNING) {
		ui_displayPaginatedText(
		        "Unusual request",
		        "Proceed with care",
		        this_fn
		);
	}
	UI_STEP(UI_STEP_CONFIRM_START) {
		ui_displayPrompt(
		        "Start new",
		        "operational certificate?",
		        this_fn,
		        respond_with_user_reject
		);
	}
	UI_STEP(UI_STEP_DISPLAY_POOL_COLD_KEY_PATH) {
		ui_displayPathScreen("Pool cold key path", &ctx->poolColdKeyPathSpec, this_fn);
	}
	UI_STEP(UI_STEP_DISPLAY_POOL_ID) {
		uint8_t poolKeyHash[POOL_KEY_HASH_LENGTH];
		bip44_pathToKeyHash(&ctx->poolColdKeyPathSpec, poolKeyHash, SIZEOF(poolKeyHash));

		ui_displayBech32Screen(
		        "Pool ID",
		        "pool_vk",
		        poolKeyHash, SIZEOF(poolKeyHash),
		        this_fn
		);
	}
	UI_STEP(UI_STEP_DISPLAY_KES_PUBLIC_KEY) {
		ui_displayBech32Screen(
		        "KES public key",
		        "kes_vk",
		        ctx->kesPublicKey, SIZEOF(ctx->kesPublicKey),
		        this_fn
		);
	}
	UI_STEP(UI_STEP_DISPLAY_KES_PERIOD) {
		char kesPeriodString[50];
		str_formatUint64(ctx->kesPeriod, kesPeriodString, SIZEOF(kesPeriodString));
		ui_displayPaginatedText(
		        "KES period",
		        kesPeriodString,
		        this_fn
		);
	}
	UI_STEP(UI_STEP_DISPLAY_ISSUE_COUNTER) {
		char issueCounterString[50];
		str_formatUint64(ctx->issueCounter, issueCounterString, SIZEOF(issueCounterString));
		ui_displayPaginatedText(
		        "Issue counter",
		        issueCounterString,
		        this_fn
		);
	}
	UI_STEP(UI_STEP_CONFIRM) {
		ui_displayPrompt(
		        "Confirm",
		        "operational certificate?",
		        this_fn,
		        respond_with_user_reject
		);
	}
	UI_STEP(UI_STEP_RESPOND) {
		ASSERT(ctx->responseReadyMagic == RESPONSE_READY_MAGIC);

		io_send_buf(SUCCESS, (uint8_t*) &ctx->signature, SIZEOF(ctx->signature));
		ui_idle();

	}
	UI_STEP_END(UI_STEP_INVALID);
}
