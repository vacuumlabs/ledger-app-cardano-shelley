#include "cardano.h"
#include "securityPolicy.h"
#include "signTx.h"
#include "signTxUtils.h"
#include "state.h"
#include "uiHelpers.h"
#include "uiScreens.h"

static ins_sign_tx_context_t* ctx = &(instructionState.signTxContext);
static ins_sign_tx_body_context_t* txBodyCtx = &(instructionState.signTxContext.txPartCtx.body_ctx);

static sign_tx_certificate_data_t* certificate = &instructionState.signTxContext.txPartCtx.body_ctx.stageData.certificate;

// ============================== registration ==============================

enum {
	HANDLE_CERTIFICATE_REGISTRATION_STEP_DISPLAY_OPERATION = 610,
	HANDLE_CERTIFICATE_REGISTRATION_STEP_DISPLAY_STAKE_CREDENTIAL,
	HANDLE_CERTIFICATE_REGISTRATION_STEP_CONFIRM,
	HANDLE_CERTIFICATE_REGISTRATION_STEP_RESPOND,
	HANDLE_CERTIFICATE_REGISTRATION_STEP_INVALID,
};

static void signTx_handleCertificateRegistration_ui_runStep()
{
	ASSERT(certificate->type == CERTIFICATE_TYPE_STAKE_REGISTRATION);

	TRACE("UI step %d", ctx->ui_step);
	ui_callback_fn_t* this_fn = signTx_handleCertificateRegistration_ui_runStep;

	UI_STEP_BEGIN(ctx->ui_step, this_fn);

	UI_STEP(HANDLE_CERTIFICATE_REGISTRATION_STEP_DISPLAY_OPERATION) {
		ui_displayPaginatedText(
		        "Register",
		        "staking key",
		        this_fn
		);
	}
	UI_STEP(HANDLE_CERTIFICATE_REGISTRATION_STEP_DISPLAY_STAKE_CREDENTIAL) {
		ui_displayStakeCredentialScreen(&certificate->stakeCredential, this_fn);
	}
	UI_STEP(HANDLE_CERTIFICATE_REGISTRATION_STEP_CONFIRM) {
		ui_displayPrompt(
		        "Confirm",
		        "registration",
		        this_fn,
		        respond_with_user_reject
		);
	}
	UI_STEP(HANDLE_CERTIFICATE_REGISTRATION_STEP_RESPOND) {
		respondSuccessEmptyMsg();

		advanceCertificatesStateIfAppropriate();
	}
	UI_STEP_END(HANDLE_CERTIFICATE_REGISTRATION_STEP_INVALID);
}

void handleCertificateRegistration(read_view_t* view)
{
	{
		parseStakeCredential(view, &certificate->stakeCredential);

		VALIDATE(view_remainingSize(view) == 0, ERR_INVALID_DATA);
	}

	security_policy_t policy = policyForSignTxCertificateStaking(
	                                   ctx->commonTxData.txSigningMode,
	                                   certificate->type,
	                                   &certificate->stakeCredential
	                           );
	TRACE("Policy: %d", (int) policy);
	ENSURE_NOT_DENIED(policy);

	{
		TRACE("Adding certificate (type %d) to tx hash", certificate->type);

		txHashBuilder_addCertificate_staking(
		        &txBodyCtx->txHashBuilder,
		        certificate->type,
		        &certificate->stakeCredential
		);
	}

	switch (policy) {
#define  CASE(POLICY, UI_STEP) case POLICY: {ctx->ui_step=UI_STEP; break;}
		CASE(POLICY_PROMPT_BEFORE_RESPONSE, HANDLE_CERTIFICATE_REGISTRATION_STEP_DISPLAY_OPERATION);
		CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_CERTIFICATE_REGISTRATION_STEP_RESPOND);
#undef   CASE
	default:
		THROW(ERR_NOT_IMPLEMENTED);
	}

	signTx_handleCertificateRegistration_ui_runStep();
}

// ============================== deregistration ==============================

enum {
	HANDLE_CERTIFICATE_DEREGISTRATION_STEP_DISPLAY_OPERATION = 620,
	HANDLE_CERTIFICATE_DEREGISTRATION_STEP_DISPLAY_STAKE_CREDENTIAL,
	HANDLE_CERTIFICATE_DEREGISTRATION_STEP_CONFIRM,
	HANDLE_CERTIFICATE_DEREGISTRATION_STEP_RESPOND,
	HANDLE_CERTIFICATE_DEREGISTRATION_STEP_INVALID,
};

static void signTx_handleCertificateDeregistration_ui_runStep()
{
	ASSERT(certificate->type == CERTIFICATE_TYPE_STAKE_DEREGISTRATION);

	TRACE("UI step %d", ctx->ui_step);
	ui_callback_fn_t* this_fn = signTx_handleCertificateDeregistration_ui_runStep;

	UI_STEP_BEGIN(ctx->ui_step, this_fn);

	UI_STEP(HANDLE_CERTIFICATE_DEREGISTRATION_STEP_DISPLAY_OPERATION) {
		ui_displayPaginatedText(
		        "Deregister",
		        "staking key",
		        this_fn
		);
	}
	UI_STEP(HANDLE_CERTIFICATE_DEREGISTRATION_STEP_DISPLAY_STAKE_CREDENTIAL) {
		ui_displayStakeCredentialScreen(&certificate->stakeCredential, this_fn);
	}
	UI_STEP(HANDLE_CERTIFICATE_DEREGISTRATION_STEP_CONFIRM) {
		ui_displayPrompt(
		        "Confirm",
		        "deregistration",
		        this_fn,
		        respond_with_user_reject
		);
	}
	UI_STEP(HANDLE_CERTIFICATE_DEREGISTRATION_STEP_RESPOND) {
		respondSuccessEmptyMsg();

		advanceCertificatesStateIfAppropriate();
	}
	UI_STEP_END(HANDLE_CERTIFICATE_DEREGISTRATION_STEP_INVALID);
}

void handleCertificateDeregistration(read_view_t* view)
{
	{
		parseStakeCredential(view, &certificate->stakeCredential);

		VALIDATE(view_remainingSize(view) == 0, ERR_INVALID_DATA);
	}

	security_policy_t policy = policyForSignTxCertificateStaking(
	                                   ctx->commonTxData.txSigningMode,
	                                   certificate->type,
	                                   &certificate->stakeCredential
	                           );
	TRACE("Policy: %d", (int) policy);
	ENSURE_NOT_DENIED(policy);

	{
		TRACE("Adding certificate (type %d) to tx hash", certificate->type);

		txHashBuilder_addCertificate_staking(
		        &txBodyCtx->txHashBuilder,
		        certificate->type,
		        &certificate->stakeCredential
		);
	}

	switch (policy) {
#define  CASE(POLICY, UI_STEP) case POLICY: {ctx->ui_step=UI_STEP; break;}
		CASE(POLICY_PROMPT_BEFORE_RESPONSE, HANDLE_CERTIFICATE_DEREGISTRATION_STEP_DISPLAY_OPERATION);
		CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_CERTIFICATE_DEREGISTRATION_STEP_RESPOND);
#undef   CASE
	default:
		THROW(ERR_NOT_IMPLEMENTED);
	}

	signTx_handleCertificateDeregistration_ui_runStep();
}

// ============================== delegation ==============================

enum {
	HANDLE_CERTIFICATE_DELEGATION_STEP_DISPLAY_OPERATION = 630,
	HANDLE_CERTIFICATE_DELEGATION_STEP_DISPLAY_STAKE_CREDENTIAL,
	HANDLE_CERTIFICATE_DELEGATION_STEP_CONFIRM,
	HANDLE_CERTIFICATE_DELEGATION_STEP_RESPOND,
	HANDLE_CERTIFICATE_DELEGATION_STEP_INVALID,
};

static void signTx_handleCertificateDelegation_ui_runStep()
{
	ASSERT(certificate->type == CERTIFICATE_TYPE_STAKE_DELEGATION);

	TRACE("UI step %d", ctx->ui_step);
	ui_callback_fn_t* this_fn = signTx_handleCertificateDelegation_ui_runStep;

	UI_STEP_BEGIN(ctx->ui_step, this_fn);

	UI_STEP(HANDLE_CERTIFICATE_DELEGATION_STEP_DISPLAY_OPERATION) {
		ui_displayBech32Screen(
		        "Delegate stake to",
		        "pool",
		        certificate->poolKeyHash, SIZEOF(certificate->poolKeyHash),
		        this_fn
		);
	}
	UI_STEP(HANDLE_CERTIFICATE_DELEGATION_STEP_DISPLAY_STAKE_CREDENTIAL) {
		ui_displayStakeCredentialScreen(&certificate->stakeCredential, this_fn);
	}
	UI_STEP(HANDLE_CERTIFICATE_DELEGATION_STEP_CONFIRM) {
		ui_displayPrompt(
		        "Confirm",
		        "delegation",
		        this_fn,
		        respond_with_user_reject
		);
	}
	UI_STEP(HANDLE_CERTIFICATE_DELEGATION_STEP_RESPOND) {
		respondSuccessEmptyMsg();

		advanceCertificatesStateIfAppropriate();
	}
	UI_STEP_END(HANDLE_CERTIFICATE_DELEGATION_STEP_INVALID);
}

void handleCertificateDelegation(read_view_t* view)
{
	{
		parseStakeCredential(view, &certificate->stakeCredential);
		STATIC_ASSERT(SIZEOF(certificate->poolKeyHash) == POOL_KEY_HASH_LENGTH, "wrong poolKeyHash size");
		view_copyWireToBuffer(certificate->poolKeyHash, view, POOL_KEY_HASH_LENGTH);

		VALIDATE(view_remainingSize(view) == 0, ERR_INVALID_DATA);
	}

	security_policy_t policy = policyForSignTxCertificateStaking(
	                                   ctx->commonTxData.txSigningMode,
	                                   certificate->type,
	                                   &certificate->stakeCredential
	                           );
	TRACE("Policy: %d", (int) policy);
	ENSURE_NOT_DENIED(policy);

	{
		TRACE("Adding certificate (type %d) to tx hash", &certificate->type);

		txHashBuilder_addCertificate_delegation(
		        &txBodyCtx->txHashBuilder,
		        &certificate->stakeCredential,
		        certificate->poolKeyHash, SIZEOF(certificate->poolKeyHash)
		);
	}

	switch (policy) {
#define  CASE(POLICY, UI_STEP) case POLICY: {ctx->ui_step=UI_STEP; break;}
		CASE(POLICY_PROMPT_BEFORE_RESPONSE, HANDLE_CERTIFICATE_DELEGATION_STEP_DISPLAY_OPERATION);
		CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_CERTIFICATE_DELEGATION_STEP_RESPOND);
#undef   CASE
	default:
		THROW(ERR_NOT_IMPLEMENTED);
	}

	signTx_handleCertificateDelegation_ui_runStep();
}

// ============================== pool retirement ==============================

enum {
	HANDLE_CERTIFICATE_POOL_RETIREMENT_STEP_DISPLAY_OPERATION = 650,
	HANDLE_CERTIFICATE_POOL_RETIREMENT_STEP_DISPLAY_EPOCH,
	HANDLE_CERTIFICATE_POOL_RETIREMENT_STEP_CONFIRM,
	HANDLE_CERTIFICATE_POOL_RETIREMENT_STEP_RESPOND,
	HANDLE_CERTIFICATE_POOL_RETIREMENT_STEP_INVALID,
};

static void signTx_handleCertificatePoolRetirement_ui_runStep()
{
	TRACE("UI step %d", ctx->ui_step);
	ASSERT(certificate->type == CERTIFICATE_TYPE_STAKE_POOL_RETIREMENT);

	ui_callback_fn_t* this_fn = signTx_handleCertificatePoolRetirement_ui_runStep;

	UI_STEP_BEGIN(ctx->ui_step, this_fn);

	UI_STEP(HANDLE_CERTIFICATE_POOL_RETIREMENT_STEP_DISPLAY_OPERATION) {
		ui_displayBech32Screen(
		        "Retire stake pool",
		        "pool",
		        certificate->poolKeyHash, SIZEOF(certificate->poolKeyHash),
		        this_fn
		);
	}
	UI_STEP(HANDLE_CERTIFICATE_POOL_RETIREMENT_STEP_DISPLAY_EPOCH) {
		ui_displayUint64Screen(
		        "at the end of epoch",
		        certificate->epoch,
		        this_fn
		);
	}
	UI_STEP(HANDLE_CERTIFICATE_POOL_RETIREMENT_STEP_CONFIRM) {
		ui_displayPrompt(
		        "Confirm",
		        "pool retirement",
		        this_fn,
		        respond_with_user_reject
		);
	}
	UI_STEP(HANDLE_CERTIFICATE_POOL_RETIREMENT_STEP_RESPOND) {
		respondSuccessEmptyMsg();

		advanceCertificatesStateIfAppropriate();
	}
	UI_STEP_END(HANDLE_CERTIFICATE_POOL_RETIREMENT_STEP_INVALID);
}

void handleCertificatePoolRetirement(read_view_t* view)
{
	{
		parsePathSpec(view, &certificate->poolIdPath);
		certificate->epoch = parse_u8be(view);

		VALIDATE(view_remainingSize(view) == 0, ERR_INVALID_DATA);
	}

	security_policy_t policy = policyForSignTxCertificateStakePoolRetirement(
	                                   ctx->commonTxData.txSigningMode,
	                                   &certificate->poolIdPath,
	                                   certificate->epoch
	                           );
	TRACE("Policy: %d", (int) policy);
	ENSURE_NOT_DENIED(policy);

	{
		TRACE("Adding certificate (type %d) to tx hash", certificate->type);

		bip44_pathToKeyHash(
		        &certificate->poolIdPath,
		        certificate->poolKeyHash, SIZEOF(certificate->poolKeyHash)
		);
		txHashBuilder_addCertificate_poolRetirement(
		        &txBodyCtx->txHashBuilder,
		        certificate->poolKeyHash, SIZEOF(certificate->poolKeyHash),
		        certificate->epoch
		);
	}

	switch (policy) {
#define  CASE(POLICY, UI_STEP) case POLICY: {ctx->ui_step=UI_STEP; break;}
		CASE(POLICY_PROMPT_BEFORE_RESPONSE, HANDLE_CERTIFICATE_POOL_RETIREMENT_STEP_DISPLAY_OPERATION);
		CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_CERTIFICATE_POOL_RETIREMENT_STEP_RESPOND);
#undef   CASE
	default:
		THROW(ERR_NOT_IMPLEMENTED);
	}

	signTx_handleCertificatePoolRetirement_ui_runStep();
}
