#include "signTx.h"
#include "signTxCertificate.h"
#include "state.h"
#include "bech32.h"
#include "cardano.h"
#include "addressUtilsByron.h"
#include "addressUtilsShelley.h"
#include "uiHelpers.h"
#include "signTxUtils.h"
#include "uiScreens.h"
#include "txHashBuilder.h"
#include "textUtils.h"
#include "hexUtils.h"
#include "utils.h"
#include "messageSigning.h"
#include "bufView.h"
#include "securityPolicy.h"

static ins_sign_tx_context_t* ctx = &(instructionState.signTxContext);
static ins_sign_tx_body_context_t* txBodyCtx = &(instructionState.signTxContext.txPartCtx.body_ctx);
static ins_sign_tx_aux_data_context_t* txAuxDataCtx = &(instructionState.signTxContext.txPartCtx.aux_data_ctx);
static ins_sign_tx_witness_context_t* txWitnessCtx = &(instructionState.signTxContext.txPartCtx.witnesses_ctx);

// TODO - maybe add an enum to the global context which would specify the active tx part?
static inline void initTxBodyCtx()
{
	explicit_bzero(&ctx->txPartCtx, SIZEOF(ctx->txPartCtx));

	{
		// initialization
		txBodyCtx->currentInput = 0;
		txBodyCtx->currentOutput = 0;
		txBodyCtx->currentCertificate = 0;
		txBodyCtx->currentWithdrawal = 0;
		txBodyCtx->feeReceived = false;
		txBodyCtx->ttlReceived = false;
		txBodyCtx->validityIntervalStartReceived = false;
		txBodyCtx->mintReceived = false;
	}
}

static inline void initTxAuxDataCtx()
{
	explicit_bzero(&ctx->txPartCtx, SIZEOF(ctx->txPartCtx));
	{
		txAuxDataCtx->auxDataReceived = false;
		txAuxDataCtx->auxDataType = false;
	}
}

static inline void initTxWitnessCtx()
{
	explicit_bzero(&ctx->txPartCtx, SIZEOF(ctx->txPartCtx));
	{
		txWitnessCtx->currentWitness = 0;
	}
}

// advances the stage of the main state machine
static inline void advanceStage()
{
	TRACE("Advancing sign tx stage from: %d", ctx->stage);

	switch (ctx->stage) {

	case SIGN_STAGE_INIT:
		ctx->stage = SIGN_STAGE_AUX_DATA;
		initTxAuxDataCtx();

		if (ctx->includeAuxData) {
			// wait for aux data APDU(s)
			txAuxDataCtx->auxDataReceived = false;
			break;
		}

	// intentional fallthrough

	case SIGN_STAGE_AUX_DATA:
		if (ctx->includeAuxData) {
			ASSERT(txAuxDataCtx->auxDataReceived);
		}

		ctx->stage = SIGN_STAGE_BODY_INPUTS;
		initTxBodyCtx();

		{
			// Note: make sure that everything in ctx is initialized properly
			txHashBuilder_init(
			        &txBodyCtx->txHashBuilder,
			        ctx->numInputs,
			        ctx->numOutputs,
			        ctx->includeTtl,
			        ctx->numCertificates,
			        ctx->numWithdrawals,
			        ctx->includeAuxData,
			        ctx->includeValidityIntervalStart,
			        ctx->includeMint
			);
			txHashBuilder_enterInputs(&txBodyCtx->txHashBuilder);
		}
		break;

	case SIGN_STAGE_BODY_INPUTS:
		// we should have received all inputs
		ASSERT(txBodyCtx->currentInput == ctx->numInputs);
		txHashBuilder_enterOutputs(&txBodyCtx->txHashBuilder);
		signTxOutput_init();
		ctx->stage = SIGN_STAGE_BODY_OUTPUTS;

		if (ctx->numOutputs > 0) {
			// wait for output APDUs
			break;
		}

	// intentional fallthrough

	case SIGN_STAGE_BODY_OUTPUTS:
		// we should have received all outputs
		ASSERT(txBodyCtx->currentOutput == ctx->numOutputs);
		ctx->stage = SIGN_STAGE_BODY_FEE;
		break;

	case SIGN_STAGE_BODY_FEE:
		ASSERT(txBodyCtx->feeReceived);

		ctx->stage = SIGN_STAGE_BODY_TTL;

		if (ctx->includeTtl) {
			// wait for TTL APDU
			break;
		}

	// intentional fallthrough

	case SIGN_STAGE_BODY_TTL:
		if (ctx->includeTtl) {
			ASSERT(txBodyCtx->ttlReceived);
		}

		ctx->stage = SIGN_STAGE_BODY_CERTIFICATES;

		if (ctx->numCertificates > 0) {
			txHashBuilder_enterCertificates(&txBodyCtx->txHashBuilder);
			break;
		}

	// intentional fallthrough

	case SIGN_STAGE_BODY_CERTIFICATES:
		// we should have received all certificates
		ASSERT(txBodyCtx->currentCertificate == ctx->numCertificates);

		ctx->stage = SIGN_STAGE_BODY_WITHDRAWALS;

		if (ctx->numWithdrawals > 0) {
			txHashBuilder_enterWithdrawals(&txBodyCtx->txHashBuilder);
			break;
		}

	// intentional fallthrough

	case SIGN_STAGE_BODY_WITHDRAWALS:
		// we should have received all withdrawals
		ASSERT(txBodyCtx->currentWithdrawal == ctx->numWithdrawals);

		if (ctx->includeAuxData) {
			ASSERT(txAuxDataCtx->auxDataReceived);

			// add auxiliary data to tx
			TRACE("Adding auxiliary data hash to tx hash");
			txHashBuilder_addAuxData(
			        &txBodyCtx->txHashBuilder,
			        ctx->auxDataHash, SIZEOF(ctx->auxDataHash)
			);
		}

		ctx->stage = SIGN_STAGE_BODY_VALIDITY_INTERVAL;
		if (ctx->includeValidityIntervalStart) {
			// wait for Validity interval start APDU
			break;
		}

	// intentional fallthrough

	case SIGN_STAGE_BODY_VALIDITY_INTERVAL:
		if (ctx->includeValidityIntervalStart) {
			ASSERT(txBodyCtx->validityIntervalStartReceived);
		}
		ctx->stage = SIGN_STAGE_BODY_MINT;
		if (ctx->includeMint) {
			txHashBuilder_enterMint(&txBodyCtx->txHashBuilder);
			signTxMint_init();
			// wait for mint APDU
			break;
		}

	// intentional fallthrough

	case SIGN_STAGE_BODY_MINT:
		if (ctx->includeMint) {
			ASSERT(txBodyCtx->mintReceived);
		}
		ctx->stage = SIGN_STAGE_CONFIRM;
		break;

	case SIGN_STAGE_CONFIRM:
		ctx->stage = SIGN_STAGE_WITNESSES;
		initTxWitnessCtx();

		break;

	case SIGN_STAGE_WITNESSES:
		ctx->stage = SIGN_STAGE_NONE;
		ui_idle(); // we are done with this tx
		break;

	case SIGN_STAGE_NONE:
		THROW(ERR_INVALID_STATE);

	default:
		ASSERT(false);
	}

	TRACE("Advancing sign tx stage to: %d", ctx->stage);
}

// should be called from the main state machine when a pool registration certificate
// sub-machine is finished, or when other type of certificate is processed
void advanceCertificatesStateIfAppropriate()
{
	TRACE("%u", ctx->stage);

	switch (ctx->stage) {

	case SIGN_STAGE_BODY_CERTIFICATES:
		ASSERT(txBodyCtx->currentCertificate < ctx->numCertificates);

		// Advance stage to the next certificate
		ASSERT(txBodyCtx->currentCertificate < ctx->numCertificates);
		txBodyCtx->currentCertificate++;

		if (txBodyCtx->currentCertificate == ctx->numCertificates) {
			advanceStage();
		}
		break;

	default:
		ASSERT(ctx->stage == SIGN_STAGE_BODY_CERTIFICATES_POOL_SUBMACHINE);
	}
}

// State sub-machines, e.g. the one in signTxPoolRegistration, might finish
// with a UI handler. The callbacks (resulting from user interaction) are run
// only after all APDU handlers have returned, thus the sub-machine cannot
// notify the main state machine of state changes resulting from user interaction
// (unless it is allowed to directly mess with the state of the main machine).
//
// Consequently, we only find out that a state sub-machine is finished
// when the following APDU of the main state machine arrives, and we need to
// update the state before dealing with the APDU.
static inline void checkForFinishedSubmachines()
{
	TRACE("Checking for finished submachines; stage = %d", ctx->stage);

	switch (ctx->stage) {
	case SIGN_STAGE_BODY_OUTPUTS_SUBMACHINE:
		if (signTxOutput_isFinished()) {
			TRACE();
			ASSERT(txBodyCtx->currentOutput < ctx->numOutputs);
			ctx->stage = SIGN_STAGE_BODY_OUTPUTS;

			txBodyCtx->currentOutput++;
			if (txBodyCtx->currentOutput == ctx->numOutputs) {
				advanceStage();
			}
		}
		break;

	case SIGN_STAGE_BODY_CERTIFICATES_POOL_SUBMACHINE:
		if (signTxPoolRegistration_isFinished()) {
			TRACE();
			ASSERT(txBodyCtx->currentCertificate < ctx->numCertificates);
			ctx->stage = SIGN_STAGE_BODY_CERTIFICATES;

			advanceCertificatesStateIfAppropriate();
		}
		break;

	case SIGN_STAGE_AUX_DATA_CATALYST_REGISTRATION_SUBMACHINE:
		if (signTxCatalystRegistration_isFinished()) {
			TRACE();
			ctx->stage = SIGN_STAGE_AUX_DATA;
			txAuxDataCtx->auxDataReceived = true;

			STATIC_ASSERT(SIZEOF(ctx->auxDataHash) == AUX_DATA_HASH_LENGTH, "Wrong auxiliary data hash length");
			STATIC_ASSERT(SIZEOF(txAuxDataCtx->stageContext.catalyst_registration_subctx.auxDataHash) == AUX_DATA_HASH_LENGTH, "Wrong auxiliary data hash length");
			memmove(ctx->auxDataHash, txAuxDataCtx->stageContext.catalyst_registration_subctx.auxDataHash, AUX_DATA_HASH_LENGTH);

			advanceStage();
		}
		break;

	case SIGN_STAGE_BODY_MINT_SUBMACHINE:
		if (signTxMint_isFinished()) {
			TRACE();
			ctx->stage = SIGN_STAGE_BODY_MINT;
			txBodyCtx->mintReceived = true;
			advanceStage();
		}
	default:
		break; // nothing to do otherwise
	}
}

// this is supposed to be called at the beginning of each APDU handler
static inline void CHECK_STAGE(sign_tx_stage_t expected)
{
	TRACE("Checking stage... current one is %d, expected %d", ctx->stage, expected);
	VALIDATE(ctx->stage == expected, ERR_INVALID_STATE);
}


// ============================== INIT ==============================

enum {
	HANDLE_INIT_STEP_DISPLAY_DETAILS = 100,
	HANDLE_INIT_STEP_CONFIRM,
	HANDLE_INIT_STEP_RESPOND,
	HANDLE_INIT_STEP_INVALID,
} ;

static void signTx_handleInit_ui_runStep()
{
	TRACE("UI step %d", ctx->ui_step);
	TRACE_STACK_USAGE();
	ui_callback_fn_t* this_fn = signTx_handleInit_ui_runStep;

	UI_STEP_BEGIN(ctx->ui_step, this_fn);

	UI_STEP(HANDLE_INIT_STEP_DISPLAY_DETAILS) {
		char* header =
		        (ctx->commonTxData.txSigningMode == SIGN_TX_SIGNINGMODE_SCRIPT_TX) ?
		        "New script transaction" :
		        "New transaction";

		if (is_tx_network_verifiable(ctx->commonTxData.txSigningMode, ctx->numOutputs, ctx->numWithdrawals)) {
			ui_displayNetworkParamsScreen(
			        header,
			        ctx->commonTxData.networkId, ctx->commonTxData.protocolMagic,
			        this_fn
			);
		} else {
			// technically, no withdrawals/pool reg. certificate as well, but the UI message would be too long
			ui_displayPaginatedText(
			        header,
			        "no outputs, cannot verify network id",
			        this_fn
			);
		}
	}

	UI_STEP(HANDLE_INIT_STEP_CONFIRM) {
		ui_displayPrompt(
		        "Start new",
		        "transaction?",
		        this_fn,
		        respond_with_user_reject
		);
	}

	UI_STEP(HANDLE_INIT_STEP_RESPOND) {
		respondSuccessEmptyMsg();
		advanceStage();
	}
	UI_STEP_END(HANDLE_INIT_STEP_INVALID);
}

__noinline_due_to_stack__
static void signTx_handleInitAPDU(uint8_t p2, uint8_t* wireDataBuffer, size_t wireDataSize)
{
	TRACE_STACK_USAGE();
	{
		// sanity checks
		CHECK_STAGE(SIGN_STAGE_INIT);

		VALIDATE(p2 == P2_UNUSED, ERR_INVALID_REQUEST_PARAMETERS);
		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}

	{
		// parse data

		TRACE_BUFFER(wireDataBuffer, wireDataSize);

		struct {
			uint8_t networkId;
			uint8_t protocolMagic[4];

			uint8_t includeTtl;
			uint8_t includeAuxData;
			uint8_t includeValidityIntervalStart;
			uint8_t includeMint;
			uint8_t txSigningMode;

			uint8_t numInputs[4];
			uint8_t numOutputs[4];
			uint8_t numCertificates[4];
			uint8_t numWithdrawals[4];
			uint8_t numWitnesses[4];
		}* wireHeader = (void*) wireDataBuffer;

		VALIDATE(SIZEOF(*wireHeader) == wireDataSize, ERR_INVALID_DATA);

		ASSERT_TYPE(ctx->commonTxData.networkId, uint8_t);
		ctx->commonTxData.networkId = wireHeader->networkId;
		TRACE("network id %d", ctx->commonTxData.networkId);
		VALIDATE(isValidNetworkId(ctx->commonTxData.networkId), ERR_INVALID_DATA);

		ASSERT_TYPE(ctx->commonTxData.protocolMagic, uint32_t);
		ctx->commonTxData.protocolMagic = u4be_read(wireHeader->protocolMagic);
		TRACE("protocol magic %d", ctx->commonTxData.protocolMagic);

		ctx->includeTtl = signTx_parseIncluded(wireHeader->includeTtl);
		TRACE("Include ttl %d", ctx->includeTtl);

		ctx->includeAuxData = signTx_parseIncluded(wireHeader->includeAuxData);
		TRACE("Include auxiliary data %d", ctx->includeAuxData);

		ctx->includeValidityIntervalStart = signTx_parseIncluded(wireHeader->includeValidityIntervalStart);
		TRACE("Include validity interval start %d", ctx->includeValidityIntervalStart);

		ctx->includeMint = signTx_parseIncluded(wireHeader->includeMint);
		TRACE("Include mint %d", ctx->includeMint);

		ctx->commonTxData.txSigningMode = wireHeader->txSigningMode;
		TRACE("Signing mode %d", (int) ctx->commonTxData.txSigningMode);
		switch (ctx->commonTxData.txSigningMode) {
		case SIGN_TX_SIGNINGMODE_ORDINARY_TX:
		case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OWNER:
		case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OPERATOR:
		case SIGN_TX_SIGNINGMODE_SCRIPT_TX:
			// these signing modes are allowed
			break;

		default:
			THROW(ERR_INVALID_DATA);
		}

		ASSERT_TYPE(ctx->numInputs, uint16_t);
		ASSERT_TYPE(ctx->numOutputs, uint16_t);
		ASSERT_TYPE(ctx->numCertificates, uint16_t);
		ASSERT_TYPE(ctx->numWithdrawals, uint16_t);
		ASSERT_TYPE(ctx->numWitnesses, uint16_t);
		ctx->numInputs            = (uint16_t) u4be_read(wireHeader->numInputs);
		ctx->numOutputs           = (uint16_t) u4be_read(wireHeader->numOutputs);
		ctx->numCertificates      = (uint16_t) u4be_read(wireHeader->numCertificates);
		ctx->numWithdrawals       = (uint16_t) u4be_read(wireHeader->numWithdrawals);
		ctx->numWitnesses         = (uint16_t) u4be_read(wireHeader->numWitnesses);

		TRACE(
		        "num inputs, outputs, certificates, withdrawals, witnesses: %d %d %d %d %d",
		        ctx->numInputs, ctx->numOutputs, ctx->numCertificates, ctx->numWithdrawals, ctx->numWitnesses
		);
		VALIDATE(ctx->numInputs <= SIGN_MAX_INPUTS, ERR_INVALID_DATA);
		VALIDATE(ctx->numOutputs <= SIGN_MAX_OUTPUTS, ERR_INVALID_DATA);
		VALIDATE(ctx->numCertificates <= SIGN_MAX_CERTIFICATES, ERR_INVALID_DATA);
		VALIDATE(ctx->numWithdrawals <= SIGN_MAX_REWARD_WITHDRAWALS, ERR_INVALID_DATA);

		switch (ctx->commonTxData.txSigningMode) {

		case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OPERATOR:
		case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OWNER:
			// necessary to avoid intermingling witnesses from several certs
			VALIDATE(ctx->numCertificates == 1, ERR_INVALID_DATA);

			// witnesses for owners and withdrawals are the same
			// we forbid withdrawals so that users cannot be tricked into witnessing
			// something unintentionally (e.g. an owner given by the staking key hash)
			VALIDATE(ctx->numWithdrawals == 0, ERR_INVALID_DATA);

			// mint must not be combined with pool registration certificates
			VALIDATE(ctx->includeMint == false, ERR_INVALID_DATA);
			break;

		case SIGN_TX_SIGNINGMODE_ORDINARY_TX:
		case SIGN_TX_SIGNINGMODE_SCRIPT_TX:
			// no additional validation
			break;

		default:
			ASSERT(false);
		}

		// Current code design assumes at least one input.
		// If this is to be relaxed, stage switching logic needs to be re-visited.
		// However, an input is needed for certificate replay protection (enforced by node),
		// so double-check this protection is no longer necessary before allowing no inputs.
		VALIDATE(ctx->numInputs > 0, ERR_INVALID_DATA);
	}

	security_policy_t policy = policyForSignTxInit(
	                                   ctx->commonTxData.txSigningMode,
	                                   ctx->commonTxData.networkId,
	                                   ctx->commonTxData.protocolMagic,
	                                   ctx->numOutputs,
	                                   ctx->numWithdrawals
	                           );
	TRACE("Policy: %d", (int) policy);
	ENSURE_NOT_DENIED(policy);
	{
		// select UI steps
		switch (policy) {
#	define  CASE(POLICY, UI_STEP) case POLICY: {ctx->ui_step=UI_STEP; break;}
			CASE(POLICY_PROMPT_WARN_UNUSUAL,    HANDLE_INIT_STEP_DISPLAY_DETAILS);
			CASE(POLICY_PROMPT_BEFORE_RESPONSE, HANDLE_INIT_STEP_CONFIRM);
			CASE(POLICY_ALLOW_WITHOUT_PROMPT,   HANDLE_INIT_STEP_RESPOND);
#	undef   CASE
		default:
			THROW(ERR_NOT_IMPLEMENTED);
		}
	}

	signTx_handleInit_ui_runStep();
}

// ============================== AUXILIARY DATA ==============================

enum {
	HANDLE_AUX_DATA_ARBITRARY_HASH_STEP_DISPLAY = 800,
	HANDLE_AUX_DATA_ARBITRARY_HASH_STEP_RESPOND,
	HANDLE_AUX_DATA_ARBITRARY_HASH_STEP_INVALID,
};

static void signTx_handleAuxDataArbitraryHash_ui_runStep()
{
	TRACE("UI step %d", ctx->ui_step);
	TRACE_STACK_USAGE();
	ui_callback_fn_t* this_fn = signTx_handleAuxDataArbitraryHash_ui_runStep;

	UI_STEP_BEGIN(ctx->ui_step, this_fn);

	UI_STEP(HANDLE_AUX_DATA_ARBITRARY_HASH_STEP_DISPLAY) {
		ui_displayHexBufferScreen(
		        "Auxiliary data hash",
		        ctx->auxDataHash,
		        SIZEOF(ctx->auxDataHash),
		        this_fn
		);
	}
	UI_STEP(HANDLE_AUX_DATA_ARBITRARY_HASH_STEP_RESPOND) {
		respondSuccessEmptyMsg();
		advanceStage();
	}
	UI_STEP_END(HANDLE_AUX_DATA_ARBITRARY_HASH_STEP_INVALID);
}


enum {
	HANDLE_AUX_DATA_CATALYST_REGISTRATION_STEP_DISPLAY = 850,
	HANDLE_AUX_DATA_CATALYST_REGISTRATION_STEP_RESPOND,
	HANDLE_AUX_DATA_CATALYST_REGISTRATION_STEP_INVALID,
};
static void signTx_handleAuxDataCatalystRegistration_ui_runStep()
{
	TRACE("UI step %d", ctx->ui_step);
	TRACE_STACK_USAGE();
	ui_callback_fn_t* this_fn = signTx_handleAuxDataCatalystRegistration_ui_runStep;

	UI_STEP_BEGIN(ctx->ui_step, this_fn);

	UI_STEP(HANDLE_AUX_DATA_CATALYST_REGISTRATION_STEP_DISPLAY) {
		ui_displayPrompt(
		        "Register Catalyst",
		        "voting key?",
		        this_fn,
		        respond_with_user_reject
		);
	}
	UI_STEP(HANDLE_AUX_DATA_CATALYST_REGISTRATION_STEP_RESPOND) {
		respondSuccessEmptyMsg();
		signTxCatalystRegistration_init();
		ctx->stage = SIGN_STAGE_AUX_DATA_CATALYST_REGISTRATION_SUBMACHINE;
	}
	UI_STEP_END(HANDLE_AUX_DATA_CATALYST_REGISTRATION_STEP_INVALID);
}

__noinline_due_to_stack__
static void signTx_handleAuxDataAPDU(uint8_t p2, uint8_t* wireDataBuffer, size_t wireDataSize)
{
	{
		TRACE_STACK_USAGE();
		ASSERT(ctx->includeAuxData == true);

		// delegate to state sub-machine for stake pool registration certificate data
		if (signTxCatalystRegistration_isValidInstruction(p2)) {
			TRACE();
			CHECK_STAGE(SIGN_STAGE_AUX_DATA_CATALYST_REGISTRATION_SUBMACHINE);

			TRACE_STACK_USAGE();

			signTxCatalystRegistration_handleAPDU(p2, wireDataBuffer, wireDataSize);
			return;
		} else {
			CHECK_STAGE(SIGN_STAGE_AUX_DATA);
		}
	}

	{
		explicit_bzero(ctx->auxDataHash, SIZEOF(ctx->auxDataHash));
		TRACE_BUFFER(wireDataBuffer, wireDataSize);

		read_view_t view = make_read_view(wireDataBuffer, wireDataBuffer + wireDataSize);

		txAuxDataCtx->auxDataType = parse_u1be(&view);
		switch (txAuxDataCtx->auxDataType) {

		case AUX_DATA_TYPE_ARBITRARY_HASH: {
			// parse data
			STATIC_ASSERT(SIZEOF(ctx->auxDataHash) == AUX_DATA_HASH_LENGTH, "wrong auxiliary data hash length");
			view_copyWireToBuffer(ctx->auxDataHash, &view, AUX_DATA_HASH_LENGTH);
			txAuxDataCtx->auxDataReceived = true;
			break;
		}

		case AUX_DATA_TYPE_CATALYST_REGISTRATION:
			break;

		default:
			THROW(ERR_INVALID_DATA);
		}

		VALIDATE(view_remainingSize(&view) == 0, ERR_INVALID_DATA);
	}


	security_policy_t policy = policyForSignTxAuxData(txAuxDataCtx->auxDataType);
	TRACE("Policy: %d", (int) policy);
	ENSURE_NOT_DENIED(policy);

	switch (txAuxDataCtx->auxDataType) {
	case AUX_DATA_TYPE_ARBITRARY_HASH: {
		// select UI step
		switch (policy) {
#define  CASE(POLICY, UI_STEP) case POLICY: {ctx->ui_step=UI_STEP; break;}
			CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_AUX_DATA_ARBITRARY_HASH_STEP_DISPLAY);
			CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_AUX_DATA_ARBITRARY_HASH_STEP_RESPOND);
#undef   CASE
		default:
			THROW(ERR_NOT_IMPLEMENTED);
		}
		signTx_handleAuxDataArbitraryHash_ui_runStep();
		break;
	}
	case AUX_DATA_TYPE_CATALYST_REGISTRATION:
		// select UI step
		switch (policy) {
#define  CASE(POLICY, UI_STEP) case POLICY: {ctx->ui_step=UI_STEP; break;}
			CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_AUX_DATA_CATALYST_REGISTRATION_STEP_DISPLAY);
			CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_AUX_DATA_CATALYST_REGISTRATION_STEP_RESPOND);
#undef   CASE
		default:
			THROW(ERR_NOT_IMPLEMENTED);
		}

		signTx_handleAuxDataCatalystRegistration_ui_runStep();
		break;
	default:
		ASSERT(false);
	}
}

// ============================== INPUTS ==============================

enum {
	HANDLE_INPUT_STEP_RESPOND = 200,
	HANDLE_INPUT_STEP_INVALID,
};

static void signTx_handleInput_ui_runStep()
{
	TRACE("UI step %d", ctx->ui_step);
	ui_callback_fn_t* this_fn = signTx_handleInput_ui_runStep;

	UI_STEP_BEGIN(ctx->ui_step, this_fn);

	UI_STEP(HANDLE_INPUT_STEP_RESPOND) {
		respondSuccessEmptyMsg();

		// Advance stage to the next input
		ASSERT(txBodyCtx->currentInput < ctx->numInputs);
		txBodyCtx->currentInput++;

		if (txBodyCtx->currentInput == ctx->numInputs) {
			advanceStage();
		}
	}
	UI_STEP_END(HANDLE_INPUT_STEP_INVALID);
}

__noinline_due_to_stack__
static void signTx_handleInputAPDU(uint8_t p2, uint8_t* wireDataBuffer, size_t wireDataSize)
{
	TRACE_STACK_USAGE();
	{
		// sanity checks
		CHECK_STAGE(SIGN_STAGE_BODY_INPUTS);
		ASSERT(txBodyCtx->currentInput < ctx->numInputs);

		VALIDATE(p2 == P2_UNUSED, ERR_INVALID_REQUEST_PARAMETERS);
		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}

	// parsed data
	struct {
		uint8_t txHashBuffer[TX_HASH_LENGTH];
		uint32_t parsedIndex;
	} input;

	{
		// parse input
		TRACE_BUFFER(wireDataBuffer, wireDataSize);

		struct {
			uint8_t txHash[TX_HASH_LENGTH];
			uint8_t index[4];
		}* wireUtxo = (void*) wireDataBuffer;

		VALIDATE(wireDataSize == SIZEOF(*wireUtxo), ERR_INVALID_DATA);

		memmove(input.txHashBuffer, wireUtxo->txHash, SIZEOF(input.txHashBuffer));
		input.parsedIndex = u4be_read(wireUtxo->index);
	}

	{
		// add to tx
		TRACE("Adding input to tx hash");
		txHashBuilder_addInput(
		        &txBodyCtx->txHashBuilder,
		        input.txHashBuffer, SIZEOF(input.txHashBuffer),
		        input.parsedIndex
		);
	}

	security_policy_t policy = policyForSignTxInput();
	TRACE("Policy: %d", (int) policy);
	ENSURE_NOT_DENIED(policy);

	{
		// select UI steps
		switch (policy) {
#	define  CASE(POLICY, UI_STEP) case POLICY: {ctx->ui_step=UI_STEP; break;}
			CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_INPUT_STEP_RESPOND);
#	undef   CASE
		default:
			THROW(ERR_NOT_IMPLEMENTED);
		}
	}
	signTx_handleInput_ui_runStep();
}


// ============================== OUTPUTS ==============================

static void signTx_handleOutputAPDU(uint8_t p2, uint8_t* wireDataBuffer, size_t wireDataSize)
{
	{
		TRACE("p2 = %d", p2);
		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
		TRACE_BUFFER(wireDataBuffer, wireDataSize);
	}

	if (ctx->stage == SIGN_STAGE_BODY_OUTPUTS) {
		// new output
		VALIDATE(txBodyCtx->currentOutput < ctx->numOutputs, ERR_INVALID_STATE);
		signTxOutput_init();
		ctx->stage = SIGN_STAGE_BODY_OUTPUTS_SUBMACHINE;
	}

	CHECK_STAGE(SIGN_STAGE_BODY_OUTPUTS_SUBMACHINE);
	ASSERT(txBodyCtx->currentOutput < ctx->numOutputs);

	// all output handling is delegated to a state sub-machine
	VALIDATE(signTxOutput_isValidInstruction(p2), ERR_INVALID_DATA);
	signTxOutput_handleAPDU(p2, wireDataBuffer, wireDataSize);
}

// ============================== FEE ==============================

enum {
	HANDLE_FEE_STEP_DISPLAY = 400,
	HANDLE_FEE_STEP_RESPOND,
	HANDLE_FEE_STEP_INVALID,
};

static void signTx_handleFee_ui_runStep()
{
	TRACE("UI step %d", ctx->ui_step);
	ui_callback_fn_t* this_fn = signTx_handleFee_ui_runStep;

	TRACE_ADA_AMOUNT("fee ", txBodyCtx->stageData.fee);

	UI_STEP_BEGIN(ctx->ui_step, this_fn);

	UI_STEP(HANDLE_FEE_STEP_DISPLAY) {
		ui_displayAdaAmountScreen("Transaction fee", txBodyCtx->stageData.fee, this_fn);
	}
	UI_STEP(HANDLE_FEE_STEP_RESPOND) {
		respondSuccessEmptyMsg();
		advanceStage();
	}
	UI_STEP_END(HANDLE_FEE_STEP_INVALID);
}

__noinline_due_to_stack__
static void signTx_handleFeeAPDU(uint8_t p2, uint8_t* wireDataBuffer, size_t wireDataSize)
{
	{
		// sanity checks
		CHECK_STAGE(SIGN_STAGE_BODY_FEE);

		VALIDATE(p2 == P2_UNUSED, ERR_INVALID_REQUEST_PARAMETERS);
		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}

	{
		// parse data
		TRACE_BUFFER(wireDataBuffer, wireDataSize);

		VALIDATE(wireDataSize == 8, ERR_INVALID_DATA);
		txBodyCtx->stageData.fee = u8be_read(wireDataBuffer);
		txBodyCtx->feeReceived = true;
	}

	{
		// add to tx
		TRACE("Adding fee to tx hash");
		txHashBuilder_addFee(&txBodyCtx->txHashBuilder, txBodyCtx->stageData.fee);
	}

	security_policy_t policy = policyForSignTxFee(ctx->commonTxData.txSigningMode, txBodyCtx->stageData.fee);
	TRACE("Policy: %d", (int) policy);
	ENSURE_NOT_DENIED(policy);

	{
		// select UI steps
		switch (policy) {
#	define  CASE(POLICY, UI_STEP) case POLICY: {ctx->ui_step=UI_STEP; break;}
			CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_FEE_STEP_DISPLAY);
			CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_FEE_STEP_RESPOND);
#	undef   CASE
		default:
			THROW(ERR_NOT_IMPLEMENTED);
		}
	}

	signTx_handleFee_ui_runStep();
}


// ============================== TTL ==============================

enum {
	HANDLE_TTL_STEP_DISPLAY = 500,
	HANDLE_TTL_STEP_RESPOND,
	HANDLE_TTL_STEP_INVALID,
};

static void signTx_handleTtl_ui_runStep()
{
	TRACE("UI step %d", ctx->ui_step);
	ui_callback_fn_t* this_fn = signTx_handleTtl_ui_runStep;

	UI_STEP_BEGIN(ctx->ui_step, this_fn);

	UI_STEP(HANDLE_TTL_STEP_DISPLAY) {
		ui_displayValidityBoundaryScreen(
		        "Transaction TTL",
		        txBodyCtx->stageData.ttl,
		        ctx->commonTxData.networkId, ctx->commonTxData.protocolMagic,
		        this_fn
		);
	}
	UI_STEP(HANDLE_TTL_STEP_RESPOND) {
		respondSuccessEmptyMsg();
		advanceStage();
	}
	UI_STEP_END(HANDLE_TTL_STEP_INVALID);
}

__noinline_due_to_stack__
static void signTx_handleTtlAPDU(uint8_t p2, uint8_t* wireDataBuffer, size_t wireDataSize)
{
	{
		// sanity checks
		CHECK_STAGE(SIGN_STAGE_BODY_TTL);
		ASSERT(ctx->includeTtl == true);

		VALIDATE(p2 == P2_UNUSED, ERR_INVALID_REQUEST_PARAMETERS);
		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}

	{
		// parse data
		TRACE_BUFFER(wireDataBuffer, wireDataSize);

		VALIDATE(wireDataSize == 8, ERR_INVALID_DATA);
		txBodyCtx->stageData.ttl = u8be_read(wireDataBuffer);
		txBodyCtx->ttlReceived = true;
	}

	security_policy_t policy = policyForSignTxTtl(txBodyCtx->stageData.ttl);
	TRACE("Policy: %d", (int) policy);
	ENSURE_NOT_DENIED(policy);

	{
		// add to tx
		TRACE("Adding ttl to tx hash");
		txHashBuilder_addTtl(&txBodyCtx->txHashBuilder, txBodyCtx->stageData.ttl);
	}

	{
		// select UI steps
		switch (policy) {
#	define  CASE(POLICY, UI_STEP) case POLICY: {ctx->ui_step=UI_STEP; break;}
			CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_TTL_STEP_DISPLAY);
			CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_TTL_STEP_RESPOND);
#	undef   CASE
		default:
			THROW(ERR_NOT_IMPLEMENTED);
		}
	}

	signTx_handleTtl_ui_runStep();
}


// ============================== CERTIFICATES ==============================

__noinline_due_to_stack__
static void signTx_handleCertificateAPDU(uint8_t p2, uint8_t* wireDataBuffer, size_t wireDataSize)
{
	TRACE_STACK_USAGE();

	ASSERT(txBodyCtx->currentCertificate < ctx->numCertificates);

	// delegate to state sub-machine for stake pool registration certificate data
	if (signTxPoolRegistration_isValidInstruction(p2)) {
		TRACE();
		VALIDATE(ctx->stage == SIGN_STAGE_BODY_CERTIFICATES_POOL_SUBMACHINE, ERR_INVALID_DATA);

		TRACE_STACK_USAGE();

		signTxPoolRegistration_handleAPDU(p2, wireDataBuffer, wireDataSize);
		return;
	}

	CHECK_STAGE(SIGN_STAGE_BODY_CERTIFICATES);
	VALIDATE(p2 == P2_UNUSED, ERR_INVALID_REQUEST_PARAMETERS);

	// a new certificate arrived
	explicit_bzero(&txBodyCtx->stageData.certificate, SIZEOF(txBodyCtx->stageData.certificate));

	ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	TRACE_BUFFER(wireDataBuffer, wireDataSize);

	read_view_t view = make_read_view(wireDataBuffer, wireDataBuffer + wireDataSize);

	txBodyCtx->stageData.certificate.type = parse_u1be(&view);
	TRACE("Certificate type: %d", txBodyCtx->stageData.certificate.type);
	switch (txBodyCtx->stageData.certificate.type) {
	case CERTIFICATE_TYPE_STAKE_REGISTRATION:
	case CERTIFICATE_TYPE_STAKE_DEREGISTRATION:
	case CERTIFICATE_TYPE_STAKE_DELEGATION:
	case CERTIFICATE_TYPE_STAKE_POOL_REGISTRATION:
	case CERTIFICATE_TYPE_STAKE_POOL_RETIREMENT:
		// these are supported
		break;

	default:
		THROW(ERR_INVALID_DATA);
	}

	{
		// basic policy that just decides if the certificate is allowed
		security_policy_t policy = policyForSignTxCertificate(
		                                   ctx->commonTxData.txSigningMode,
		                                   txBodyCtx->stageData.certificate.type
		                           );
		TRACE("Policy: %d", (int) policy);
		ENSURE_NOT_DENIED(policy);
	}

	switch (txBodyCtx->stageData.certificate.type) {
	case CERTIFICATE_TYPE_STAKE_REGISTRATION:
		handleCertificateRegistration(&view);
		return;

	case CERTIFICATE_TYPE_STAKE_DEREGISTRATION:
		handleCertificateDeregistration(&view);
		return;

	case CERTIFICATE_TYPE_STAKE_DELEGATION:
		handleCertificateDelegation(&view);
		return;

	case CERTIFICATE_TYPE_STAKE_POOL_REGISTRATION: {
		// pool registration certificates have a separate sub-machine for handling APDU and UI
		// nothing more to be done with them here, we just init the sub-machine
		ctx->stage = SIGN_STAGE_BODY_CERTIFICATES_POOL_SUBMACHINE;
		signTxPoolRegistration_init();

		respondSuccessEmptyMsg();
		return;
	}

	case CERTIFICATE_TYPE_STAKE_POOL_RETIREMENT:
		handleCertificatePoolRetirement(&view);
		return;

	default:
		ASSERT(false);
	}
}

// ============================== WITHDRAWALS ==============================

enum {
	HANDLE_WITHDRAWAL_STEP_DISPLAY_AMOUNT = 700,
	HANDLE_WITHDRAWAL_STEP_DISPLAY_PATH,
	HANDLE_WITHDRAWAL_STEP_RESPOND,
	HANDLE_WITHDRAWAL_STEP_INVALID,
};

static void signTx_handleWithdrawal_ui_runStep()
{
	TRACE("UI step %d", ctx->ui_step);
	TRACE_STACK_USAGE();
	ui_callback_fn_t* this_fn = signTx_handleWithdrawal_ui_runStep;

	UI_STEP_BEGIN(ctx->ui_step, this_fn);

	UI_STEP(HANDLE_WITHDRAWAL_STEP_DISPLAY_AMOUNT) {
		ui_displayAdaAmountScreen("Withdrawing rewards", txBodyCtx->stageData.withdrawal.amount, this_fn);
	}
	UI_STEP(HANDLE_WITHDRAWAL_STEP_DISPLAY_PATH) {
		reward_account_t rewardAccount;
		switch (txBodyCtx->stageData.withdrawal.stakeCredential.type) {
		case STAKE_CREDENTIAL_KEY_PATH: {
			rewardAccount.keyReferenceType = KEY_REFERENCE_PATH;
			rewardAccount.path = txBodyCtx->stageData.withdrawal.stakeCredential.keyPath;
			break;
		}
		case STAKE_CREDENTIAL_SCRIPT_HASH: {
			rewardAccount.keyReferenceType = KEY_REFERENCE_HASH;
			constructRewardAddressFromHash(
			        ctx->commonTxData.networkId,
			        REWARD_HASH_SOURCE_SCRIPT,
			        txBodyCtx->stageData.withdrawal.stakeCredential.scriptHash,
			        SIZEOF(txBodyCtx->stageData.withdrawal.stakeCredential.scriptHash),
			        rewardAccount.hashBuffer,
			        SIZEOF(rewardAccount.hashBuffer)
			);
			break;
		}
		default:
			ASSERT(false);
			break;
		}
		ui_displayRewardAccountScreen(&rewardAccount, ctx->commonTxData.networkId, this_fn);
	}
	UI_STEP(HANDLE_WITHDRAWAL_STEP_RESPOND) {
		respondSuccessEmptyMsg();

		// Advance stage to the next withdrawal
		ASSERT(txBodyCtx->currentWithdrawal < ctx->numWithdrawals);
		txBodyCtx->currentWithdrawal++;

		if (txBodyCtx->currentWithdrawal == ctx->numWithdrawals) {
			advanceStage();
		}
	}
	UI_STEP_END(HANDLE_WITHDRAWAL_STEP_INVALID);
}

__noinline_due_to_stack__
static void _addWithdrawalToTxHash()
{
	uint8_t rewardAddress[REWARD_ACCOUNT_SIZE];

	switch (txBodyCtx->stageData.withdrawal.stakeCredential.type) {
	case STAKE_CREDENTIAL_KEY_PATH:
		constructRewardAddressFromKeyPath(
		        &txBodyCtx->stageData.withdrawal.stakeCredential.keyPath,
		        ctx->commonTxData.networkId,
		        rewardAddress,
		        SIZEOF(rewardAddress)
		);
		break;
	case STAKE_CREDENTIAL_SCRIPT_HASH:
		constructRewardAddressFromHash(
		        ctx->commonTxData.networkId,
		        REWARD_HASH_SOURCE_SCRIPT,
		        txBodyCtx->stageData.withdrawal.stakeCredential.scriptHash,
		        SIZEOF(txBodyCtx->stageData.withdrawal.stakeCredential.scriptHash),
		        rewardAddress,
		        SIZEOF(rewardAddress)
		);
		break;
	default:
		ASSERT(false);
		return;
	}

	TRACE("Adding withdrawal to tx hash");
	txHashBuilder_addWithdrawal(
	        &txBodyCtx->txHashBuilder,
	        rewardAddress, SIZEOF(rewardAddress),
	        txBodyCtx->stageData.withdrawal.amount
	);
}

__noinline_due_to_stack__
static void signTx_handleWithdrawalAPDU(uint8_t p2, uint8_t* wireDataBuffer, size_t wireDataSize)
{
	TRACE_STACK_USAGE();
	{
		// sanity checks
		CHECK_STAGE(SIGN_STAGE_BODY_WITHDRAWALS);
		ASSERT(txBodyCtx->currentWithdrawal < ctx->numWithdrawals);

		VALIDATE(p2 == P2_UNUSED, ERR_INVALID_REQUEST_PARAMETERS);
		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}

	explicit_bzero(&txBodyCtx->stageData.withdrawal, SIZEOF(txBodyCtx->stageData.withdrawal));

	{
		// parse input
		TRACE_BUFFER(wireDataBuffer, wireDataSize);

		read_view_t view = make_read_view(wireDataBuffer, wireDataBuffer + wireDataSize);
		txBodyCtx->stageData.withdrawal.amount = parse_u8be(&view);

		parseStakeCredential(&view, &txBodyCtx->stageData.withdrawal.stakeCredential);

		VALIDATE(view_remainingSize(&view) == 0, ERR_INVALID_DATA);

	}

	_addWithdrawalToTxHash();

	security_policy_t policy = policyForSignTxWithdrawal(
	                                   ctx->commonTxData.txSigningMode,
	                                   &txBodyCtx->stageData.withdrawal.stakeCredential
	                           );
	TRACE("Policy: %d", (int) policy);
	ENSURE_NOT_DENIED(policy);

	{
		// select UI steps
		switch (policy) {
#	define  CASE(POLICY, UI_STEP) case POLICY: {ctx->ui_step=UI_STEP; break;}
			CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_WITHDRAWAL_STEP_DISPLAY_AMOUNT);
			CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_WITHDRAWAL_STEP_RESPOND);
#	undef   CASE
		default:
			THROW(ERR_NOT_IMPLEMENTED);
		}
	}

	signTx_handleWithdrawal_ui_runStep();
}

// ============================== VALIDITY INTERVAL START ==============================

enum {
	HANDLE_VALIDITY_INTERVAL_START_STEP_DISPLAY = 900,
	HANDLE_VALIDITY_INTERVAL_START_STEP_RESPOND,
	HANDLE_VALIDITY_INTERVAL_START_STEP_INVALID,
};

static void signTx_handleValidityInterval_ui_runStep()
{
	TRACE("UI step %d", ctx->ui_step);
	ui_callback_fn_t* this_fn = signTx_handleValidityInterval_ui_runStep;

	UI_STEP_BEGIN(ctx->ui_step, this_fn);

	UI_STEP(HANDLE_VALIDITY_INTERVAL_START_STEP_DISPLAY) {
		ui_displayValidityBoundaryScreen(
		        "Validity interval start",
		        txBodyCtx->stageData.validityIntervalStart,
		        ctx->commonTxData.networkId, ctx->commonTxData.protocolMagic,
		        this_fn
		);
	}
	UI_STEP(HANDLE_VALIDITY_INTERVAL_START_STEP_RESPOND) {
		respondSuccessEmptyMsg();
		advanceStage();
	}
	UI_STEP_END(HANDLE_VALIDITY_INTERVAL_START_STEP_INVALID);
}

static void signTx_handleValidityIntervalStartAPDU(uint8_t p2, uint8_t* wireDataBuffer, size_t wireDataSize)
{
	{
		// sanity checks
		CHECK_STAGE(SIGN_STAGE_BODY_VALIDITY_INTERVAL);
		ASSERT(ctx->includeValidityIntervalStart == true);

		VALIDATE(p2 == P2_UNUSED, ERR_INVALID_REQUEST_PARAMETERS);
		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}

	{
		// parse data
		TRACE_BUFFER(wireDataBuffer, wireDataSize);

		VALIDATE(wireDataSize == 8, ERR_INVALID_DATA);
		txBodyCtx->stageData.validityIntervalStart = u8be_read(wireDataBuffer);
		txBodyCtx->validityIntervalStartReceived = true;
	}

	security_policy_t policy = policyForSignTxValidityIntervalStart();
	TRACE("Policy: %d", (int) policy);
	ENSURE_NOT_DENIED(policy);

	{
		// select UI step
		switch (policy) {
#	define  CASE(POLICY, UI_STEP) case POLICY: {ctx->ui_step=UI_STEP; break;}
			CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_VALIDITY_INTERVAL_START_STEP_DISPLAY);
			CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_VALIDITY_INTERVAL_START_STEP_RESPOND);
#	undef   CASE
		default:
			THROW(ERR_NOT_IMPLEMENTED);
		}
	}

	{
		TRACE("Adding validity interval start to tx hash");
		txHashBuilder_addValidityIntervalStart(
		        &txBodyCtx->txHashBuilder,
		        txBodyCtx->stageData.validityIntervalStart
		);
		TRACE();
	}

	signTx_handleValidityInterval_ui_runStep();
}

// ============================== MINT ==============================

static void signTx_handleMintAPDU(uint8_t p2, uint8_t* wireDataBuffer, size_t wireDataSize)
{
	{
		TRACE("p2 = %d", p2);
		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
		TRACE_BUFFER(wireDataBuffer, wireDataSize);
	}

	if (ctx->stage == SIGN_STAGE_BODY_MINT) {
		ctx->stage = SIGN_STAGE_BODY_MINT_SUBMACHINE;
	}

	CHECK_STAGE(SIGN_STAGE_BODY_MINT_SUBMACHINE);

	// all mint handling is delegated to a state sub-machine
	VALIDATE(signTxMint_isValidInstruction(p2), ERR_INVALID_DATA);
	signTxMint_handleAPDU(p2, wireDataBuffer, wireDataSize);
}


// ============================== CONFIRM ==============================

enum {
	HANDLE_CONFIRM_STEP_FINAL_CONFIRM = 1000,
	HANDLE_CONFIRM_STEP_RESPOND,
	HANDLE_CONFIRM_STEP_INVALID,
};

static void signTx_handleConfirm_ui_runStep()
{
	TRACE("UI step %d", ctx->ui_step);
	TRACE_STACK_USAGE();
	ui_callback_fn_t* this_fn = signTx_handleConfirm_ui_runStep;

	UI_STEP_BEGIN(ctx->ui_step, this_fn);

	UI_STEP(HANDLE_CONFIRM_STEP_FINAL_CONFIRM) {
		ui_displayPrompt(
		        "Confirm",
		        "transaction?",
		        this_fn,
		        respond_with_user_reject
		);
	}
	UI_STEP(HANDLE_CONFIRM_STEP_RESPOND) {
		// respond
		io_send_buf(SUCCESS, ctx->txHash, SIZEOF(ctx->txHash));
		ui_displayBusy();

		advanceStage();
	}
	UI_STEP_END(HANDLE_CONFIRM_STEP_INVALID);
}

__noinline_due_to_stack__
static void signTx_handleConfirmAPDU(uint8_t p2, uint8_t* wireDataBuffer MARK_UNUSED, size_t wireDataSize)
{
	TRACE_STACK_USAGE();
	{
		//sanity checks
		CHECK_STAGE(SIGN_STAGE_CONFIRM);

		VALIDATE(p2 == P2_UNUSED, ERR_INVALID_REQUEST_PARAMETERS);
		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}

	{
		// no data to receive
		VALIDATE(wireDataSize == 0, ERR_INVALID_DATA);
	}

	{
		// compute txHash
		TRACE("Finalizing tx hash");
		txHashBuilder_finalize(
		        &txBodyCtx->txHashBuilder,
		        ctx->txHash, SIZEOF(ctx->txHash)
		);
	}

	security_policy_t policy = policyForSignTxConfirm();
	TRACE("Policy: %d", (int) policy);
	ENSURE_NOT_DENIED(policy);

	{
		// select UI step
		switch (policy) {
#	define  CASE(POLICY, UI_STEP) case POLICY: {ctx->ui_step=UI_STEP; break;}
			CASE(POLICY_PROMPT_BEFORE_RESPONSE, HANDLE_CONFIRM_STEP_FINAL_CONFIRM);
			CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_CONFIRM_STEP_RESPOND);
#	undef   CASE
		default:
			THROW(ERR_NOT_IMPLEMENTED);
		}
	}

	signTx_handleConfirm_ui_runStep();
}


// ============================== WITNESS ==============================

enum {
	HANDLE_WITNESS_STEP_WARNING = 1100,
	HANDLE_WITNESS_STEP_DISPLAY,
	HANDLE_WITNESS_STEP_CONFIRM,
	HANDLE_WITNESS_STEP_RESPOND,
	HANDLE_WITNESS_STEP_INVALID,
};

static void signTx_handleWitness_ui_runStep()
{
	TRACE("UI step %d", ctx->ui_step);
	TRACE_STACK_USAGE();
	ui_callback_fn_t* this_fn = signTx_handleWitness_ui_runStep;

	UI_STEP_BEGIN(ctx->ui_step, this_fn);

	UI_STEP(HANDLE_WITNESS_STEP_WARNING) {
		ui_displayPaginatedText(
		        "Warning!",
		        "Host asks for unusual witness",
		        this_fn
		);
	}
	UI_STEP(HANDLE_WITNESS_STEP_DISPLAY) {
		ui_displayPathScreen("Witness path", &txWitnessCtx->stageData.witness.path, this_fn);
	}
	UI_STEP(HANDLE_WITNESS_STEP_CONFIRM) {
		ui_displayPrompt(
		        "Sign using",
		        "this witness?",
		        this_fn,
		        respond_with_user_reject
		);
	}
	UI_STEP(HANDLE_WITNESS_STEP_RESPOND) {
		TRACE("Sending witness data");
		TRACE_BUFFER(txWitnessCtx->stageData.witness.signature, SIZEOF(txWitnessCtx->stageData.witness.signature));
		io_send_buf(SUCCESS, txWitnessCtx->stageData.witness.signature, SIZEOF(txWitnessCtx->stageData.witness.signature));
		ui_displayBusy(); // needs to happen after I/O

		txWitnessCtx->currentWitness++;
		if (txWitnessCtx->currentWitness == ctx->numWitnesses) {
			advanceStage();
		}
	}
	UI_STEP_END(HANDLE_INPUT_STEP_INVALID);
}

__noinline_due_to_stack__
static void signTx_handleWitnessAPDU(uint8_t p2, uint8_t* wireDataBuffer, size_t wireDataSize)
{
	TRACE_STACK_USAGE();
	{
		// sanity checks
		CHECK_STAGE(SIGN_STAGE_WITNESSES);
		VALIDATE(p2 == P2_UNUSED, ERR_INVALID_REQUEST_PARAMETERS);
		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);

		TRACE("Witness no. %d out of %d", txWitnessCtx->currentWitness + 1, ctx->numWitnesses);
		ASSERT(txWitnessCtx->currentWitness < ctx->numWitnesses);
	}

	explicit_bzero(&txWitnessCtx->stageData.witness, SIZEOF(txWitnessCtx->stageData.witness));

	{
		// parse
		TRACE_BUFFER(wireDataBuffer, wireDataSize);

		size_t parsedSize = bip44_parseFromWire(&txWitnessCtx->stageData.witness.path, wireDataBuffer, wireDataSize);
		VALIDATE(parsedSize == wireDataSize, ERR_INVALID_DATA);
	}

	security_policy_t policy = POLICY_DENY;
	{
		// get policy
		policy = policyForSignTxWitness(
		                 ctx->commonTxData.txSigningMode,
		                 &txWitnessCtx->stageData.witness.path,
		                 ctx->includeMint
		         );
		TRACE("Policy: %d", (int) policy);
		ENSURE_NOT_DENIED(policy);
	}

	{
		// compute witness
		TRACE("getTxWitness");
		TRACE("TX HASH");
		TRACE_BUFFER(ctx->txHash, SIZEOF(ctx->txHash));
		TRACE("END TX HASH");

		getTxWitness(
		        &txWitnessCtx->stageData.witness.path,
		        ctx->txHash, SIZEOF(ctx->txHash),
		        txWitnessCtx->stageData.witness.signature, SIZEOF(txWitnessCtx->stageData.witness.signature)
		);
	}

	{
		// choose UI steps
		switch (policy) {
#	define  CASE(POLICY, UI_STEP) case POLICY: {ctx->ui_step=UI_STEP; break;}
			CASE(POLICY_PROMPT_WARN_UNUSUAL,  HANDLE_WITNESS_STEP_WARNING);
			CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_WITNESS_STEP_DISPLAY);
			CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_WITNESS_STEP_RESPOND);
#	undef   CASE
		default:
			THROW(ERR_NOT_IMPLEMENTED);
		}
	}
	signTx_handleWitness_ui_runStep();
}


// ============================== MAIN HANDLER ==============================

typedef void subhandler_fn_t(uint8_t p2, uint8_t* dataBuffer, size_t dataSize);

static subhandler_fn_t* lookup_subhandler(uint8_t p1)
{
	switch (p1) {
#	define  CASE(P1, HANDLER) case P1: return HANDLER;
#	define  DEFAULT(HANDLER)  default: return HANDLER;
		CASE(0x01, signTx_handleInitAPDU);
		/*
		* Auxiliary data have to be handled before tx body because of memory consumption:
		* in certain cases we need compute a rolling hash,
		* and that cannot be done while the computation of tx body hash is in progress
		* without prohibitively bloating the instruction state.
		*/
		CASE(0x08, signTx_handleAuxDataAPDU);
		CASE(0x02, signTx_handleInputAPDU);
		CASE(0x03, signTx_handleOutputAPDU);
		CASE(0x04, signTx_handleFeeAPDU);
		CASE(0x05, signTx_handleTtlAPDU);
		CASE(0x06, signTx_handleCertificateAPDU);
		CASE(0x07, signTx_handleWithdrawalAPDU);
		CASE(0x09, signTx_handleValidityIntervalStartAPDU);
		CASE(0x0b, signTx_handleMintAPDU);
		CASE(0x0a, signTx_handleConfirmAPDU);
		CASE(0x0f, signTx_handleWitnessAPDU);
		DEFAULT(NULL)
#	undef   CASE
#	undef   DEFAULT
	}
}

void signTx_handleAPDU(
        uint8_t p1,
        uint8_t p2,
        uint8_t* wireDataBuffer,
        size_t wireDataSize,
        bool isNewCall
)
{
	TRACE("P1 = 0x%x, P2 = 0x%x, isNewCall = %d", p1, p2, isNewCall);

	if (isNewCall) {
		explicit_bzero(ctx, SIZEOF(*ctx));
		ctx->stage = SIGN_STAGE_INIT;
	}

	// advance stage if a state sub-machine has finished
	checkForFinishedSubmachines();

	// TODO should be replaced by checking which txPartCtx is in use, see https://github.com/vacuumlabs/ledger-app-cardano-shelley/issues/66
	switch (ctx->stage) {
	case SIGN_STAGE_BODY_INPUTS:
	case SIGN_STAGE_BODY_OUTPUTS:
	case SIGN_STAGE_BODY_OUTPUTS_SUBMACHINE:
	case SIGN_STAGE_BODY_FEE:
	case SIGN_STAGE_BODY_TTL:
	case SIGN_STAGE_BODY_CERTIFICATES:
	case SIGN_STAGE_BODY_CERTIFICATES_POOL_SUBMACHINE:
	case SIGN_STAGE_BODY_WITHDRAWALS:
	case SIGN_STAGE_BODY_VALIDITY_INTERVAL:
	case SIGN_STAGE_BODY_MINT:
	case SIGN_STAGE_BODY_MINT_SUBMACHINE:
		explicit_bzero(&txBodyCtx->stageData, SIZEOF(txBodyCtx->stageData));
		break;
	default:
		break;
	}

	subhandler_fn_t* subhandler = lookup_subhandler(p1);
	VALIDATE(subhandler != NULL, ERR_INVALID_REQUEST_PARAMETERS);
	subhandler(p2, wireDataBuffer, wireDataSize);
}
