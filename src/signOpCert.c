#include "common.h"

#include "signOpCert.h"
#include "keyDerivation.h"
#include "endian.h"
#include "state.h"
#include "uiHelpers.h"
#include "securityPolicy.h"
#include "messageSigning.h"
#include "textUtils.h"

#ifdef HAVE_BAGL
#include "uiScreens_bagl.h"
#elif defined(HAVE_NBGL)
#include "uiScreens_nbgl.h"
#endif

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
        const uint8_t* wireDataBuffer,
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
		view_parseBuffer(ctx->kesPublicKey, &view, KES_PUBLIC_KEY_LENGTH);
		TRACE("KES key:");
		TRACE_BUFFER(ctx->kesPublicKey, KES_PUBLIC_KEY_LENGTH);

		ctx->kesPeriod = parse_u8be(&view);
		TRACE("KES period:");
		TRACE_UINT64(ctx->kesPeriod);

		ctx->issueCounter = parse_u8be(&view);
		TRACE("Issue counter:");
		TRACE_UINT64(ctx->issueCounter);

		view_skipBytes(&view, bip44_parseFromWire(&ctx->poolColdKeyPathSpec, VIEW_REMAINING_TO_TUPLE_BUF_SIZE(&view)));

		VALIDATE(view_remainingSize(&view) == 0, ERR_INVALID_DATA);
	}

	// Check security policy
	security_policy_t policy = policyForSignOpCert(&ctx->poolColdKeyPathSpec);
	ENSURE_NOT_DENIED(policy);

	{
		uint8_t opCertBodyBuffer[OP_CERT_BODY_LENGTH] = {0};
		write_view_t opCertBodyBufferView = make_write_view(opCertBodyBuffer, opCertBodyBuffer + OP_CERT_BODY_LENGTH);

		view_appendBuffer(&opCertBodyBufferView, (const uint8_t*) &ctx->kesPublicKey, SIZEOF(ctx->kesPublicKey));
		{
			uint8_t chunk[8] = {0};
			u8be_write(chunk, ctx->issueCounter);
			#ifdef FUZZING
			view_appendBuffer(&opCertBodyBufferView, chunk, 8);
			#else
			view_appendBuffer(&opCertBodyBufferView, chunk, SIZEOF(chunk));
			#endif
		}
		{
			uint8_t chunk[8] = {0};
			u8be_write(chunk, ctx->kesPeriod);
			#ifdef FUZZING
			view_appendBuffer(&opCertBodyBufferView, chunk, 8);
			#else
			view_appendBuffer(&opCertBodyBufferView, chunk, SIZEOF(chunk));
			#endif
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
#define  CASE(policy, step) case policy: {ctx->ui_step = step; break;}
		CASE(POLICY_PROMPT_WARN_UNUSUAL,    UI_STEP_WARNING);
		CASE(POLICY_PROMPT_BEFORE_RESPONSE, UI_STEP_CONFIRM_START);
		CASE(POLICY_ALLOW_WITHOUT_PROMPT,   UI_STEP_RESPOND);
#undef   CASE
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
		ui_displayUnusualWarning(this_fn);
	}
	UI_STEP(UI_STEP_CONFIRM_START) {
		#ifdef HAVE_BAGL
		ui_displayPrompt(
		        "Start new",
		        "operational certificate?",
		        this_fn,
		        respond_with_user_reject
		);
		#elif defined(HAVE_NBGL)
		display_prompt(
		        "Start new\noperational certificate?",
		        "",
		        this_fn,
		        respond_with_user_reject
		);
		#endif // HAVE_BAGL
	}
	UI_STEP(UI_STEP_DISPLAY_POOL_COLD_KEY_PATH) {
		#ifdef HAVE_BAGL
		ui_displayPathScreen("Pool cold key path", &ctx->poolColdKeyPathSpec, this_fn);
		#elif defined(HAVE_NBGL)
		char pathStr[BIP44_PATH_STRING_SIZE_MAX + 1] = {0};
		ui_getPathScreen(pathStr, SIZEOF(pathStr), &ctx->poolColdKeyPathSpec);
		fill_and_display_if_required("Pool cold key path", pathStr, this_fn, respond_with_user_reject);
		#endif // HAVE_BAGL
	}
	UI_STEP(UI_STEP_DISPLAY_POOL_ID) {
		uint8_t poolKeyHash[POOL_KEY_HASH_LENGTH] = {0};
		bip44_pathToKeyHash(&ctx->poolColdKeyPathSpec, poolKeyHash, SIZEOF(poolKeyHash));

		#ifdef HAVE_BAGL
		ui_displayBech32Screen(
		        "Pool ID",
		        "pool",
		        poolKeyHash, SIZEOF(poolKeyHash),
		        this_fn
		);
		#elif defined(HAVE_NBGL)
		char encodedStr[BECH32_STRING_SIZE_MAX] = {0};
		ui_getBech32Screen(encodedStr, SIZEOF(encodedStr), "pool", poolKeyHash, SIZEOF(poolKeyHash));
		fill_and_display_if_required("Pool ID", encodedStr, this_fn, respond_with_user_reject);
		#endif // HAVE_BAGL
	}
	UI_STEP(UI_STEP_DISPLAY_KES_PUBLIC_KEY) {
		#ifdef HAVE_BAGL
		ui_displayBech32Screen(
		        "KES public key",
		        "kes_vk",
		        ctx->kesPublicKey, SIZEOF(ctx->kesPublicKey),
		        this_fn
		);
		#elif defined(HAVE_NBGL)
		char encodedStr[BECH32_STRING_SIZE_MAX] = {0};
		ui_getBech32Screen(encodedStr, SIZEOF(encodedStr), "kes_vk", ctx->kesPublicKey, SIZEOF(ctx->kesPublicKey));
		fill_and_display_if_required("KES public key", encodedStr, this_fn, respond_with_user_reject);
		#endif // HAVE_BAGL
	}
	UI_STEP(UI_STEP_DISPLAY_KES_PERIOD) {
		char kesPeriodString[50] = {0};
		explicit_bzero(kesPeriodString, SIZEOF(kesPeriodString));
		str_formatUint64(ctx->kesPeriod, kesPeriodString, SIZEOF(kesPeriodString));
		#ifdef HAVE_BAGL
		ui_displayPaginatedText(
		        "KES period",
		        kesPeriodString,
		        this_fn
		);
		#elif defined(HAVE_NBGL)
		fill_and_display_if_required("KES period", kesPeriodString, this_fn, respond_with_user_reject);
		#endif // HAVE_BAGL
	}
	UI_STEP(UI_STEP_DISPLAY_ISSUE_COUNTER) {
		char issueCounterString[50] = {0};
		explicit_bzero(issueCounterString, SIZEOF(issueCounterString));
		str_formatUint64(ctx->issueCounter, issueCounterString, SIZEOF(issueCounterString));
		#ifdef HAVE_BAGL
		ui_displayPaginatedText(
		        "Issue counter",
		        issueCounterString,
		        this_fn
		);
		#elif defined(HAVE_NBGL)
		fill_and_display_if_required("Issue counter", issueCounterString, this_fn, respond_with_user_reject);
		#endif // HAVE_BAGL
	}
	UI_STEP(UI_STEP_CONFIRM) {
		#ifdef HAVE_BAGL
		ui_displayPrompt(
		        "Confirm",
		        "operational certificate?",
		        this_fn,
		        respond_with_user_reject
		);
		#elif defined(HAVE_NBGL)
		display_confirmation("Confirm\n operation certificate", "", "OP CERTIFICATE\nCONFIRMED", "Op certificate\nrejected", this_fn, respond_with_user_reject);
		#endif // HAVE_BAGL
	}
	UI_STEP(UI_STEP_RESPOND) {
		ASSERT(ctx->responseReadyMagic == RESPONSE_READY_MAGIC);

		io_send_buf(SUCCESS, (uint8_t*) &ctx->signature, SIZEOF(ctx->signature));
		ui_idle();

	}
	UI_STEP_END(UI_STEP_INVALID);
}
