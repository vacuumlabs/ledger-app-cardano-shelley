#include "app_mode.h"
#include "signTx.h"
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

static inline void initTxBodyCtx()
{
	explicit_bzero(&ctx->txPartCtx, SIZEOF(ctx->txPartCtx));

	{
		// initialization
		BODY_CTX->currentInput = 0;
		BODY_CTX->currentOutput = 0;
		BODY_CTX->currentCertificate = 0;
		BODY_CTX->currentWithdrawal = 0;
		BODY_CTX->currentCollateral = 0;
		BODY_CTX->currentRequiredSigner = 0;
		BODY_CTX->feeReceived = false;
		BODY_CTX->ttlReceived = false;
		BODY_CTX->validityIntervalStartReceived = false;
		BODY_CTX->mintReceived = false;
		BODY_CTX->scriptDataHashReceived = false;
		BODY_CTX->collateralOutputReceived = false;
		BODY_CTX->totalCollateralReceived = false;
	}
}

static inline void initTxAuxDataCtx()
{
	explicit_bzero(&ctx->txPartCtx, SIZEOF(ctx->txPartCtx));
	{
		AUX_DATA_CTX->auxDataReceived = false;
		AUX_DATA_CTX->auxDataType = false;
	}
}

static inline void initTxWitnessCtx()
{
	explicit_bzero(&ctx->txPartCtx, SIZEOF(ctx->txPartCtx));
	{
		WITNESS_CTX->currentWitness = 0;
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
			AUX_DATA_CTX->auxDataReceived = false;
			break;
		}

	// intentional fallthrough

	case SIGN_STAGE_AUX_DATA:
		if (ctx->includeAuxData) {
			ASSERT(AUX_DATA_CTX->auxDataReceived);
		}

		ctx->stage = SIGN_STAGE_BODY_INPUTS;
		initTxBodyCtx();

		{
			// Note: make sure that everything in ctx is initialized properly
			txHashBuilder_init(
			        &BODY_CTX->txHashBuilder,
			        ctx->numInputs,
			        ctx->numOutputs,
			        ctx->includeTtl,
			        ctx->numCertificates,
			        ctx->numWithdrawals,
			        ctx->includeAuxData,
			        ctx->includeValidityIntervalStart,
			        ctx->includeMint,
			        ctx->includeScriptDataHash,
			        ctx->numCollateralInputs,
			        ctx->numRequiredSigners,
			        ctx->includeNetworkId,
			        ctx->includeCollateralOutput,
			        ctx->includeTotalCollateral,
			        ctx->numReferenceInputs
			);
			txHashBuilder_enterInputs(&BODY_CTX->txHashBuilder);
		}
		break;

	case SIGN_STAGE_BODY_INPUTS:
		// we should have received all inputs
		ASSERT(BODY_CTX->currentInput == ctx->numInputs);
		txHashBuilder_enterOutputs(&BODY_CTX->txHashBuilder);
		initializeOutputSubmachine();
		ctx->stage = SIGN_STAGE_BODY_OUTPUTS;

		if (ctx->numOutputs > 0) {
			// wait for output APDUs
			break;
		}

	// intentional fallthrough

	case SIGN_STAGE_BODY_OUTPUTS:
		// we should have received all outputs
		ASSERT(BODY_CTX->currentOutput == ctx->numOutputs);
		ctx->stage = SIGN_STAGE_BODY_FEE;
		break;

	case SIGN_STAGE_BODY_FEE:
		ASSERT(BODY_CTX->feeReceived);

		ctx->stage = SIGN_STAGE_BODY_TTL;

		if (ctx->includeTtl) {
			// wait for TTL APDU
			break;
		}

	// intentional fallthrough

	case SIGN_STAGE_BODY_TTL:
		if (ctx->includeTtl) {
			ASSERT(BODY_CTX->ttlReceived);
		}

		ctx->stage = SIGN_STAGE_BODY_CERTIFICATES;

		if (ctx->numCertificates > 0) {
			txHashBuilder_enterCertificates(&BODY_CTX->txHashBuilder);
			break;
		}

	// intentional fallthrough

	case SIGN_STAGE_BODY_CERTIFICATES:
		// we should have received all certificates
		ASSERT(BODY_CTX->currentCertificate == ctx->numCertificates);

		ctx->stage = SIGN_STAGE_BODY_WITHDRAWALS;

		if (ctx->numWithdrawals > 0) {
			txHashBuilder_enterWithdrawals(&BODY_CTX->txHashBuilder);
			break;
		}

	// intentional fallthrough

	case SIGN_STAGE_BODY_WITHDRAWALS:
		// we should have received all withdrawals
		ASSERT(BODY_CTX->currentWithdrawal == ctx->numWithdrawals);

		if (ctx->includeAuxData) {
			// add auxiliary data to tx
			TRACE("Adding auxiliary data hash to tx hash");
			txHashBuilder_addAuxData(
			        &BODY_CTX->txHashBuilder,
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
			ASSERT(BODY_CTX->validityIntervalStartReceived);
		}
		ctx->stage = SIGN_STAGE_BODY_MINT;
		if (ctx->includeMint) {
			txHashBuilder_enterMint(&BODY_CTX->txHashBuilder);
			signTxMint_init();
			// wait for mint APDU
			break;
		}

	// intentional fallthrough

	case SIGN_STAGE_BODY_MINT:
		if (ctx->includeMint) {
			ASSERT(BODY_CTX->mintReceived);
		}
		ctx->stage = SIGN_STAGE_BODY_SCRIPT_DATA_HASH;
		if (ctx->includeScriptDataHash) {
			break;
		}

	// intentional fallthrough

	case SIGN_STAGE_BODY_SCRIPT_DATA_HASH:
		if (ctx->includeScriptDataHash) {
			ASSERT(BODY_CTX->scriptDataHashReceived);
		}
		ctx->stage = SIGN_STAGE_BODY_COLLATERAL_INPUTS;
		if (ctx->numCollateralInputs > 0) {
			txHashBuilder_enterCollateralInputs(&BODY_CTX->txHashBuilder);
			break;
		}

	// intentional fallthrough

	case SIGN_STAGE_BODY_COLLATERAL_INPUTS:
		ASSERT(BODY_CTX->currentCollateral == ctx->numCollateralInputs);
		ctx->stage = SIGN_STAGE_BODY_REQUIRED_SIGNERS;
		if (ctx->numRequiredSigners > 0) {
			txHashBuilder_enterRequiredSigners(&BODY_CTX->txHashBuilder);
			break;
		}

	// intentional fallthrough

	case SIGN_STAGE_BODY_REQUIRED_SIGNERS:
		ASSERT(BODY_CTX->currentRequiredSigner == ctx->numRequiredSigners);
		if (ctx->includeNetworkId) {
			// we are not waiting for any APDU here, network id is already known from the init APDU
			txHashBuilder_addNetworkId(&BODY_CTX->txHashBuilder, ctx->commonTxData.networkId);
		}
		ctx->stage = SIGN_STAGE_BODY_COLLATERAL_OUTPUT;
		if (ctx->includeCollateralOutput) {
			break;
		}

	// intentional fallthrough

	case SIGN_STAGE_BODY_COLLATERAL_OUTPUT:
		if (ctx->includeCollateralOutput) {
			ASSERT(BODY_CTX->collateralOutputReceived);
		}
		ctx->stage = SIGN_STAGE_BODY_TOTAL_COLLATERAL;
		if (ctx->includeTotalCollateral) {
			break;
		}

	// intentional fallthrough

	case SIGN_STAGE_BODY_TOTAL_COLLATERAL:
		if (ctx->includeTotalCollateral) {
			ASSERT(BODY_CTX->totalCollateralReceived);
		}
		ctx->stage = SIGN_STAGE_BODY_REFERENCE_INPUTS;
		if (ctx->numReferenceInputs > 0) {
			txHashBuilder_enterReferenceInputs(&BODY_CTX->txHashBuilder);
			break;
		}

	// intentional fallthrough

	case SIGN_STAGE_BODY_REFERENCE_INPUTS:
		ASSERT(BODY_CTX->currentReferenceInput == ctx->numReferenceInputs);
		ctx->stage = SIGN_STAGE_CONFIRM;
		break;

	case SIGN_STAGE_CONFIRM:
		ctx->stage = SIGN_STAGE_WITNESSES;
		initTxWitnessCtx();

		if (ctx->numWitnesses > 0) {
			break;
		}

	// intentional fallthrough

	case SIGN_STAGE_WITNESSES:
		ctx->stage = SIGN_STAGE_NONE;
		ui_idle(); // we are done with this tx
		break;

	case SIGN_STAGE_NONE:
		// advanceStage() not supposed to be called after tx processing is finished
		ASSERT(false);

	default:
		ASSERT(false);
	}

	TRACE("Advancing sign tx stage to: %d", ctx->stage);
}

// called from main state machine when a pool registration certificate
// sub-machine is finished, or when other type of certificate is processed
static inline void advanceCertificatesStateIfAppropriate()
{
	TRACE("%u", ctx->stage);

	switch (ctx->stage) {

	case SIGN_STAGE_BODY_CERTIFICATES: {
		ASSERT(BODY_CTX->currentCertificate < ctx->numCertificates);

		// Advance stage to the next certificate
		ASSERT(BODY_CTX->currentCertificate < ctx->numCertificates);
		BODY_CTX->currentCertificate++;

		if (BODY_CTX->currentCertificate == ctx->numCertificates) {
			advanceStage();
		}
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
		if (isCurrentOutputFinished()) {
			TRACE();
			ASSERT(BODY_CTX->currentOutput < ctx->numOutputs);
			ctx->stage = SIGN_STAGE_BODY_OUTPUTS;

			BODY_CTX->currentOutput++;
			if (BODY_CTX->currentOutput == ctx->numOutputs) {
				advanceStage();
			}
		}
		break;

	case SIGN_STAGE_BODY_CERTIFICATES_POOL_SUBMACHINE:
		if (signTxPoolRegistration_isFinished()) {
			TRACE();
			ASSERT(BODY_CTX->currentCertificate < ctx->numCertificates);
			ctx->stage = SIGN_STAGE_BODY_CERTIFICATES;

			advanceCertificatesStateIfAppropriate();
		}
		break;

	case SIGN_STAGE_AUX_DATA_GOVERNANCE_VOTING_REGISTRATION_SUBMACHINE:
		if (signTxGovernanceVotingRegistration_isFinished()) {
			TRACE();
			ctx->stage = SIGN_STAGE_AUX_DATA;
			AUX_DATA_CTX->auxDataReceived = true;

			STATIC_ASSERT(SIZEOF(ctx->auxDataHash) == AUX_DATA_HASH_LENGTH, "Wrong auxiliary data hash length");
			STATIC_ASSERT(SIZEOF(AUX_DATA_CTX->stageContext.governance_voting_registration_subctx.auxDataHash) == AUX_DATA_HASH_LENGTH, "Wrong auxiliary data hash length");
			memmove(ctx->auxDataHash, AUX_DATA_CTX->stageContext.governance_voting_registration_subctx.auxDataHash, AUX_DATA_HASH_LENGTH);

			advanceStage();
		}
		break;

	case SIGN_STAGE_BODY_MINT_SUBMACHINE:
		if (signTxMint_isFinished()) {
			TRACE();
			ctx->stage = SIGN_STAGE_BODY_MINT;
			BODY_CTX->mintReceived = true;
			advanceStage();
		}

	case SIGN_STAGE_BODY_COLLATERAL_OUTPUT_SUBMACHINE:
		if (isCurrentOutputFinished()) {
			TRACE();
			ctx->stage = SIGN_STAGE_BODY_COLLATERAL_OUTPUT;
			BODY_CTX->collateralOutputReceived = true;
			advanceStage();
		}
		break;

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
	HANDLE_INIT_STEP_PROMPT_SIGNINGMODE = 100,
	HANDLE_INIT_STEP_DISPLAY_NETWORK_DETAILS,
	HANDLE_INIT_STEP_SCRIPT_RUNNING_WARNING,
	HANDLE_INIT_STEP_NO_COLLATERAL_WARNING,
	HANDLE_INIT_STEP_UNKNOWN_COLLATERAL_WARNING,
	HANDLE_INIT_STEP_NO_SCRIPT_DATA_HASH_WARNING,
	HANDLE_INIT_STEP_RESPOND,
	HANDLE_INIT_STEP_INVALID,
} ;

static const char* _newTxLine1(sign_tx_signingmode_t txSigningMode)
{
	switch (txSigningMode) {

	case SIGN_TX_SIGNINGMODE_ORDINARY_TX:
		return "New ordinary";

	case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OWNER:
		return "New pool owner";

	case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OPERATOR:
		return "New pool operator";

	case SIGN_TX_SIGNINGMODE_MULTISIG_TX:
		return "New multisig";

	case SIGN_TX_SIGNINGMODE_PLUTUS_TX:
		return "New Plutus";

	default:
		ASSERT(false);
	}
}

static void signTx_handleInit_ui_runStep()
{
	TRACE("UI step %d", ctx->ui_step);
	TRACE_STACK_USAGE();
	ui_callback_fn_t* this_fn = signTx_handleInit_ui_runStep;

	UI_STEP_BEGIN(ctx->ui_step, this_fn);

	UI_STEP(HANDLE_INIT_STEP_PROMPT_SIGNINGMODE) {
		ui_displayPrompt(
		        _newTxLine1(ctx->commonTxData.txSigningMode),
		        "transaction?",
		        this_fn,
		        respond_with_user_reject
		);
	}

	UI_STEP(HANDLE_INIT_STEP_DISPLAY_NETWORK_DETAILS) {
		const bool isNetworkIdVerifiable = isTxNetworkIdVerifiable(
		        ctx->includeNetworkId,
		        ctx->numOutputs, ctx->numWithdrawals,
		        ctx->commonTxData.txSigningMode
		                                   );
		if (isNetworkIdVerifiable) {
			if (isNetworkUsual(ctx->commonTxData.networkId, ctx->commonTxData.protocolMagic)) {
				// no need to display the network details
				UI_STEP_JUMP(HANDLE_INIT_STEP_SCRIPT_RUNNING_WARNING);
			}
			ui_displayNetworkParamsScreen(
			        "Network details",
			        ctx->commonTxData.networkId, ctx->commonTxData.protocolMagic,
			        this_fn
			);
		} else {
			// technically, no pool reg. certificate as well, but the UI message would be too long
			ui_displayPaginatedText(
			        "Warning:",
			        "cannot verify network id: no outputs or withrawals",
			        this_fn
			);
		}
	}

	UI_STEP(HANDLE_INIT_STEP_SCRIPT_RUNNING_WARNING) {
		if (!needsRunningScriptWarning(ctx->numCollateralInputs)) {
			UI_STEP_JUMP(HANDLE_INIT_STEP_NO_COLLATERAL_WARNING);
		}
		ui_displayPaginatedText("WARNING:", "Plutus script will be evaluated", this_fn);
	}

	UI_STEP(HANDLE_INIT_STEP_NO_COLLATERAL_WARNING) {
		if (!needsMissingCollateralWarning(ctx->commonTxData.txSigningMode, ctx->numCollateralInputs)) {
			UI_STEP_JUMP(HANDLE_INIT_STEP_NO_SCRIPT_DATA_HASH_WARNING);
		}
		ui_displayPaginatedText("WARNING:", "No collateral given for Plutus transaction", this_fn);
	}

	UI_STEP(HANDLE_INIT_STEP_UNKNOWN_COLLATERAL_WARNING) {
		if (!needsUnknownCollateralWarning(ctx->commonTxData.txSigningMode, ctx->includeTotalCollateral)) {
			UI_STEP_JUMP(HANDLE_INIT_STEP_NO_SCRIPT_DATA_HASH_WARNING);
		}
		ui_displayPaginatedText("WARNING:", "Unknown collateral amount", this_fn);
	}

	UI_STEP(HANDLE_INIT_STEP_NO_SCRIPT_DATA_HASH_WARNING) {
		if (!needsMissingScriptDataHashWarning(ctx->commonTxData.txSigningMode, ctx->includeScriptDataHash)) {
			UI_STEP_JUMP(HANDLE_INIT_STEP_RESPOND);
		}
		ui_displayPaginatedText("WARNING:", "No script data given for Plutus transaction", this_fn);
	}

	UI_STEP(HANDLE_INIT_STEP_RESPOND) {
		respondSuccessEmptyMsg();
		advanceStage();
	}
	UI_STEP_END(HANDLE_INIT_STEP_INVALID);
}

__noinline_due_to_stack__
static void signTx_handleInitAPDU(uint8_t p2, const uint8_t* wireDataBuffer, size_t wireDataSize)
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
			uint8_t includeScriptDataHash;
			uint8_t includeNetworkId;
			uint8_t includeCollateralOutput;
			uint8_t includeTotalCollateral;
			uint8_t txSigningMode;

			uint8_t numInputs[4];
			uint8_t numOutputs[4];
			uint8_t numCertificates[4];
			uint8_t numWithdrawals[4];
			uint8_t numCollateralInputs[4];
			uint8_t numRequiredSigners[4];
			uint8_t numReferenceInputs[4];

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

		ctx->includeScriptDataHash = signTx_parseIncluded(wireHeader->includeScriptDataHash);
		TRACE("Include script data hash %d", ctx->includeScriptDataHash);

		ctx->includeNetworkId = signTx_parseIncluded(wireHeader->includeNetworkId);
		TRACE("Include network id %d", ctx->includeNetworkId);

		ctx->includeCollateralOutput = signTx_parseIncluded(wireHeader->includeCollateralOutput);
		TRACE("Include collateral output %d", ctx->includeCollateralOutput);

		ctx->includeTotalCollateral = signTx_parseIncluded(wireHeader->includeTotalCollateral);
		TRACE("Include total collateral %d", ctx->includeTotalCollateral);

		ctx->commonTxData.txSigningMode = wireHeader->txSigningMode;
		TRACE("Signing mode %d", (int) ctx->commonTxData.txSigningMode);
		switch (ctx->commonTxData.txSigningMode) {
		case SIGN_TX_SIGNINGMODE_ORDINARY_TX:
		case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OWNER:
		case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OPERATOR:
		case SIGN_TX_SIGNINGMODE_MULTISIG_TX:
		case SIGN_TX_SIGNINGMODE_PLUTUS_TX:
			// these signing modes are allowed
			break;

		default:
			THROW(ERR_INVALID_DATA);
		}

		ASSERT_TYPE(ctx->numInputs, uint16_t);
		ASSERT_TYPE(ctx->numOutputs, uint16_t);
		ASSERT_TYPE(ctx->numCertificates, uint16_t);
		ASSERT_TYPE(ctx->numWithdrawals, uint16_t);
		ASSERT_TYPE(ctx->numCollateralInputs, uint16_t);
		ASSERT_TYPE(ctx->numRequiredSigners, uint16_t);
		ASSERT_TYPE(ctx->numReferenceInputs, uint16_t);
		ASSERT_TYPE(ctx->numWitnesses, uint16_t);

		ctx->numInputs            = (uint16_t) u4be_read(wireHeader->numInputs);
		ctx->numOutputs           = (uint16_t) u4be_read(wireHeader->numOutputs);
		ctx->numCertificates      = (uint16_t) u4be_read(wireHeader->numCertificates);
		ctx->numWithdrawals       = (uint16_t) u4be_read(wireHeader->numWithdrawals);
		ctx->numCollateralInputs       = (uint16_t) u4be_read(wireHeader->numCollateralInputs);
		ctx->numRequiredSigners	  = (uint16_t) u4be_read(wireHeader->numRequiredSigners);
		ctx->numReferenceInputs   = (uint16_t) u4be_read(wireHeader->numReferenceInputs);
		ctx->numWitnesses         = (uint16_t) u4be_read(wireHeader->numWitnesses);

		TRACE(
		        "num inputs, outputs, certificates, withdrawals, collateral inputs, required signers, reference inputs, witnesses: %d %d %d %d %d %d %d %d",
		        ctx->numInputs, ctx->numOutputs, ctx->numCertificates, ctx->numWithdrawals,
		        ctx->numCollateralInputs, ctx->numRequiredSigners, ctx->numReferenceInputs, ctx->numWitnesses
		);
		VALIDATE(ctx->numInputs <= SIGN_MAX_INPUTS, ERR_INVALID_DATA);
		VALIDATE(ctx->numOutputs <= SIGN_MAX_OUTPUTS, ERR_INVALID_DATA);
		VALIDATE(ctx->numCertificates <= SIGN_MAX_CERTIFICATES, ERR_INVALID_DATA);
		VALIDATE(ctx->numWithdrawals <= SIGN_MAX_REWARD_WITHDRAWALS, ERR_INVALID_DATA);
		VALIDATE(ctx->numCollateralInputs <= SIGN_MAX_COLLATERAL_INPUTS, ERR_INVALID_DATA);
		VALIDATE(ctx->numRequiredSigners <= SIGN_MAX_REQUIRED_SIGNERS, ERR_INVALID_DATA);
		VALIDATE(ctx->numReferenceInputs <= SIGN_MAX_REFERENCE_INPUTS, ERR_INVALID_DATA);

		// Current code design assumes at least one input.
		// If this is to be relaxed, stage switching logic needs to be re-visited.
		// However, an input is needed for certificate replay protection (enforced by node),
		// so double-check this protection is no longer necessary before allowing no inputs.
		VALIDATE(ctx->numInputs > 0, ERR_INVALID_DATA);
	}

	{
		// default values for variables whose value is not given in the APDU
		ctx->poolOwnerByPath = false;
		ctx->shouldDisplayTxid = false;
	}

	security_policy_t policy = policyForSignTxInit(
	                                   ctx->commonTxData.txSigningMode,
	                                   ctx->commonTxData.networkId,
	                                   ctx->commonTxData.protocolMagic,
	                                   ctx->numOutputs,
	                                   ctx->numCertificates,
	                                   ctx->numWithdrawals,
	                                   ctx->includeMint,
	                                   ctx->includeScriptDataHash,
	                                   ctx->numCollateralInputs,
	                                   ctx->numRequiredSigners,
	                                   ctx->includeNetworkId,
	                                   ctx->includeCollateralOutput,
	                                   ctx->includeTotalCollateral,
	                                   ctx->numReferenceInputs
	                           );
	TRACE("Policy: %d", (int) policy);
	ENSURE_NOT_DENIED(policy);
	{
		// select UI steps
		switch (policy) {
#define  CASE(POLICY, UI_STEP) case POLICY: {ctx->ui_step=UI_STEP; break;}
			CASE(POLICY_PROMPT_WARN_UNUSUAL,    HANDLE_INIT_STEP_PROMPT_SIGNINGMODE);
			CASE(POLICY_PROMPT_BEFORE_RESPONSE, HANDLE_INIT_STEP_PROMPT_SIGNINGMODE);
			CASE(POLICY_ALLOW_WITHOUT_PROMPT,   HANDLE_INIT_STEP_RESPOND);
#undef   CASE
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
	HANDLE_AUX_DATA_GOVERNANCE_VOTING_REGISTRATION_STEP_DISPLAY = 850,
	HANDLE_AUX_DATA_GOVERNANCE_VOTING_REGISTRATION_STEP_RESPOND,
	HANDLE_AUX_DATA_GOVERNANCE_VOTING_REGISTRATION_STEP_INVALID,
};

static void signTx_handleAuxDataGovernanceVotingRegistration_ui_runStep()
{
	TRACE("UI step %d", ctx->ui_step);
	TRACE_STACK_USAGE();
	ui_callback_fn_t* this_fn = signTx_handleAuxDataGovernanceVotingRegistration_ui_runStep;

	UI_STEP_BEGIN(ctx->ui_step, this_fn);

	UI_STEP(HANDLE_AUX_DATA_GOVERNANCE_VOTING_REGISTRATION_STEP_DISPLAY) {
		ui_displayPrompt(
		        "Register governance",
		        "vote key?",
		        this_fn,
		        respond_with_user_reject
		);
	}
	UI_STEP(HANDLE_AUX_DATA_GOVERNANCE_VOTING_REGISTRATION_STEP_RESPOND) {
		respondSuccessEmptyMsg();
		signTxGovernanceVotingRegistration_init();
		ctx->stage = SIGN_STAGE_AUX_DATA_GOVERNANCE_VOTING_REGISTRATION_SUBMACHINE;
	}
	UI_STEP_END(HANDLE_AUX_DATA_GOVERNANCE_VOTING_REGISTRATION_STEP_INVALID);
}

__noinline_due_to_stack__
static void signTx_handleAuxDataAPDU(uint8_t p2, const uint8_t* wireDataBuffer, size_t wireDataSize)
{
	{
		TRACE_STACK_USAGE();
		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
		ASSERT(ctx->includeAuxData == true);

		// delegate to state sub-machine for governance voting registration data
		if (signTxGovernanceVotingRegistration_isValidInstruction(p2)) {
			TRACE();
			CHECK_STAGE(SIGN_STAGE_AUX_DATA_GOVERNANCE_VOTING_REGISTRATION_SUBMACHINE);

			TRACE_STACK_USAGE();

			signTxGovernanceVotingRegistration_handleAPDU(p2, wireDataBuffer, wireDataSize);
			return;
		}

		VALIDATE(p2 == P2_UNUSED, ERR_INVALID_REQUEST_PARAMETERS);
		CHECK_STAGE(SIGN_STAGE_AUX_DATA);
	}
	{
		explicit_bzero(ctx->auxDataHash, SIZEOF(ctx->auxDataHash));
		TRACE_BUFFER(wireDataBuffer, wireDataSize);

		read_view_t view = make_read_view(wireDataBuffer, wireDataBuffer + wireDataSize);

		AUX_DATA_CTX->auxDataType = parse_u1be(&view);
		switch (AUX_DATA_CTX->auxDataType) {

		case AUX_DATA_TYPE_ARBITRARY_HASH: {
			// parse data
			STATIC_ASSERT(SIZEOF(ctx->auxDataHash) == AUX_DATA_HASH_LENGTH, "wrong auxiliary data hash length");
			view_parseBuffer(ctx->auxDataHash, &view, AUX_DATA_HASH_LENGTH);
			AUX_DATA_CTX->auxDataReceived = true;
			break;
		}

		case AUX_DATA_TYPE_CIP36_REGISTRATION:
			break;

		default:
			THROW(ERR_INVALID_DATA);
		}

		VALIDATE(view_remainingSize(&view) == 0, ERR_INVALID_DATA);
	}


	security_policy_t policy = policyForSignTxAuxData(AUX_DATA_CTX->auxDataType);
	TRACE("Policy: %d", (int) policy);
	ENSURE_NOT_DENIED(policy);

	switch (AUX_DATA_CTX->auxDataType) {
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
	case AUX_DATA_TYPE_CIP36_REGISTRATION:
		// select UI step
		switch (policy) {
#define  CASE(POLICY, UI_STEP) case POLICY: {ctx->ui_step=UI_STEP; break;}
			CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_AUX_DATA_GOVERNANCE_VOTING_REGISTRATION_STEP_DISPLAY);
			CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_AUX_DATA_GOVERNANCE_VOTING_REGISTRATION_STEP_RESPOND);
#undef   CASE
		default:
			THROW(ERR_NOT_IMPLEMENTED);
		}

		signTx_handleAuxDataGovernanceVotingRegistration_ui_runStep();
		break;
	default:
		ASSERT(false);
	}
}

// ============================== INPUTS ==============================

enum {
	HANDLE_INPUT_STEP_DISPLAY = 200,
	HANDLE_INPUT_STEP_RESPOND,
	HANDLE_INPUT_STEP_INVALID,
};

static void signTx_handleInput_ui_runStep()
{
	TRACE("UI step %d", ctx->ui_step);
	ui_callback_fn_t* this_fn = signTx_handleInput_ui_runStep;

	UI_STEP_BEGIN(ctx->ui_step, this_fn);

	UI_STEP(HANDLE_INPUT_STEP_DISPLAY) {
		ui_displayInputScreen(&BODY_CTX->stageData.input, this_fn);
	}

	UI_STEP(HANDLE_INPUT_STEP_RESPOND) {
		respondSuccessEmptyMsg();

		ASSERT(ctx->ui_advanceState != NULL);
		ctx->ui_advanceState();
	}
	UI_STEP_END(HANDLE_INPUT_STEP_INVALID);
}

// Advance stage to the next input
static void ui_advanceState_input()
{
	ASSERT(BODY_CTX->currentInput < ctx->numInputs);
	BODY_CTX->currentInput++;

	if (BODY_CTX->currentInput == ctx->numInputs) {
		advanceStage();
	}
}

static void parseInput(const uint8_t* wireDataBuffer, size_t wireDataSize)
{
	sign_tx_transaction_input_t* input = &BODY_CTX->stageData.input;

	struct {
		uint8_t txHash[TX_HASH_LENGTH];
		uint8_t index[4];
	}* wireUtxo = (void*) wireDataBuffer;

	VALIDATE(wireDataSize == SIZEOF(*wireUtxo), ERR_INVALID_DATA);

	tx_input_t* inputData = &input->input_data;
	memmove(inputData->txHashBuffer, wireUtxo->txHash, SIZEOF(inputData->txHashBuffer));
	inputData->index = u4be_read(wireUtxo->index);
}

static void constructInputLabel(const char* prefix, uint16_t index)
{
	char* label = BODY_CTX->stageData.input.label;
	const size_t labelSize = SIZEOF(BODY_CTX->stageData.input.label);
	explicit_bzero(label, labelSize);
	// indexed from 0 as agreed with IOHK on Slack
	snprintf(label, labelSize, "%s #%u", prefix, index);
	// make sure all the information is displayed to the user
	ASSERT(strlen(label) + 1 < labelSize);
}

static void ui_selectInputStep(security_policy_t policy)
{
	// select UI steps
	switch (policy) {
#define  CASE(POLICY, UI_STEP) case POLICY: {ctx->ui_step=UI_STEP; break;}
		CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_INPUT_STEP_DISPLAY);
		CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_INPUT_STEP_RESPOND);
#undef   CASE
	default:
		THROW(ERR_NOT_IMPLEMENTED);
	}
}

__noinline_due_to_stack__
static void signTx_handleInputAPDU(uint8_t p2, const uint8_t* wireDataBuffer, size_t wireDataSize)
{
	TRACE_STACK_USAGE();
	{
		// sanity checks
		CHECK_STAGE(SIGN_STAGE_BODY_INPUTS);
		ASSERT(BODY_CTX->currentInput < ctx->numInputs);

		VALIDATE(p2 == P2_UNUSED, ERR_INVALID_REQUEST_PARAMETERS);
		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}

	parseInput(wireDataBuffer, wireDataSize);

	security_policy_t policy = policyForSignTxInput(ctx->commonTxData.txSigningMode);
	TRACE("Policy: %d", (int) policy);
	ENSURE_NOT_DENIED(policy);

	{
		// add to tx
		TRACE("Adding input to tx hash");
		txHashBuilder_addInput(
		        &BODY_CTX->txHashBuilder,
		        &BODY_CTX->stageData.input.input_data
		);
	}
	{
		// not needed if input is not shown, but does not cost much time, so not worth branching
		constructInputLabel("Input", BODY_CTX->currentInput);

		ctx->ui_advanceState = ui_advanceState_input;
		ui_selectInputStep(policy);
		signTx_handleInput_ui_runStep();
	}
}


// ============================== OUTPUTS ==============================

static void signTx_handleOutputAPDU(uint8_t p2, const uint8_t* wireDataBuffer, size_t wireDataSize)
{
	{
		TRACE("p2 = %d", p2);
		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
		TRACE_BUFFER(wireDataBuffer, wireDataSize);
	}

	if (ctx->stage == SIGN_STAGE_BODY_OUTPUTS) {
		// new output
		VALIDATE(BODY_CTX->currentOutput < ctx->numOutputs, ERR_INVALID_STATE);
		initializeOutputSubmachine();
		ctx->stage = SIGN_STAGE_BODY_OUTPUTS_SUBMACHINE;
	}

	CHECK_STAGE(SIGN_STAGE_BODY_OUTPUTS_SUBMACHINE);
	ASSERT(BODY_CTX->currentOutput < ctx->numOutputs);

	// all output handling is delegated to a state sub-machine
	VALIDATE(signTxOutput_isValidInstruction(p2), ERR_INVALID_REQUEST_PARAMETERS);
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

	TRACE_ADA_AMOUNT("fee ", BODY_CTX->stageData.fee);

	UI_STEP_BEGIN(ctx->ui_step, this_fn);

	UI_STEP(HANDLE_FEE_STEP_DISPLAY) {
		ui_displayAdaAmountScreen("Transaction fee", BODY_CTX->stageData.fee, this_fn);
	}
	UI_STEP(HANDLE_FEE_STEP_RESPOND) {
		respondSuccessEmptyMsg();
		advanceStage();
	}
	UI_STEP_END(HANDLE_FEE_STEP_INVALID);
}

__noinline_due_to_stack__
static void signTx_handleFeeAPDU(uint8_t p2, const uint8_t* wireDataBuffer, size_t wireDataSize)
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
		BODY_CTX->stageData.fee = u8be_read(wireDataBuffer);
		BODY_CTX->feeReceived = true;
	}

	security_policy_t policy = policyForSignTxFee(ctx->commonTxData.txSigningMode, BODY_CTX->stageData.fee);
	TRACE("Policy: %d", (int) policy);
	ENSURE_NOT_DENIED(policy);

	{
		// add to tx
		TRACE("Adding fee to tx hash");
		txHashBuilder_addFee(&BODY_CTX->txHashBuilder, BODY_CTX->stageData.fee);
	}

	{
		// select UI steps
		switch (policy) {
#define  CASE(POLICY, UI_STEP) case POLICY: {ctx->ui_step=UI_STEP; break;}
			CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_FEE_STEP_DISPLAY);
			CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_FEE_STEP_RESPOND);
#undef   CASE
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
		        BODY_CTX->stageData.ttl,
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
static void signTx_handleTtlAPDU(uint8_t p2, const uint8_t* wireDataBuffer, size_t wireDataSize)
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
		BODY_CTX->stageData.ttl = u8be_read(wireDataBuffer);
		BODY_CTX->ttlReceived = true;
	}

	security_policy_t policy = policyForSignTxTtl(BODY_CTX->stageData.ttl);
	TRACE("Policy: %d", (int) policy);
	ENSURE_NOT_DENIED(policy);

	{
		// add to tx
		TRACE("Adding ttl to tx hash");
		txHashBuilder_addTtl(&BODY_CTX->txHashBuilder, BODY_CTX->stageData.ttl);
	}

	{
		// select UI steps
		switch (policy) {
#define  CASE(POLICY, UI_STEP) case POLICY: {ctx->ui_step=UI_STEP; break;}
			CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_TTL_STEP_DISPLAY);
			CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_TTL_STEP_RESPOND);
#undef   CASE
		default:
			THROW(ERR_NOT_IMPLEMENTED);
		}
	}

	signTx_handleTtl_ui_runStep();
}


// ============================== CERTIFICATES ==============================

enum {
	HANDLE_CERTIFICATE_STEP_DISPLAY_OPERATION = 600,
	HANDLE_CERTIFICATE_STEP_DISPLAY_STAKING_KEY,
	HANDLE_CERTIFICATE_STEP_CONFIRM,
	HANDLE_CERTIFICATE_STEP_RESPOND,
	HANDLE_CERTIFICATE_STEP_INVALID,
};

static void signTx_handleCertificate_ui_runStep()
{
	TRACE("UI step %d", ctx->ui_step);
	ui_callback_fn_t* this_fn = signTx_handleCertificate_ui_runStep;

	UI_STEP_BEGIN(ctx->ui_step, this_fn);

	UI_STEP(HANDLE_CERTIFICATE_STEP_DISPLAY_OPERATION) {
		switch (BODY_CTX->stageData.certificate.type) {
		case CERTIFICATE_TYPE_STAKE_REGISTRATION:
			ui_displayPaginatedText(
			        "Register",
			        "staking key",
			        this_fn
			);
			break;

		case CERTIFICATE_TYPE_STAKE_DEREGISTRATION:
			ui_displayPaginatedText(
			        "Deregister",
			        "staking key",
			        this_fn
			);
			break;

		case CERTIFICATE_TYPE_STAKE_DELEGATION:
			ui_displayBech32Screen(
			        "Delegate stake to",
			        "pool",
			        BODY_CTX->stageData.certificate.poolKeyHash, SIZEOF(BODY_CTX->stageData.certificate.poolKeyHash),
			        this_fn
			);
			break;

		default:
			// includes CERTIFICATE_TYPE_STAKE_POOL_REGISTRATION
			// and CERTIFICATE_TYPE_STAKE_POOL_RETIREMENT
			// which have separate UI; this handler must not be used
			ASSERT(false);
		}
	}
	UI_STEP(HANDLE_CERTIFICATE_STEP_DISPLAY_STAKING_KEY) {
		switch (BODY_CTX->stageData.certificate.stakeCredential.type) {
		case STAKE_CREDENTIAL_KEY_PATH:
			ui_displayPathScreen(
			        "Staking key",
			        &BODY_CTX->stageData.certificate.stakeCredential.keyPath,
			        this_fn
			);
			break;
		case STAKE_CREDENTIAL_KEY_HASH:
			ui_displayBech32Screen(
			        "Staking key hash",
			        "stake_vkh",
			        BODY_CTX->stageData.certificate.stakeCredential.keyHash,
			        SIZEOF(BODY_CTX->stageData.certificate.stakeCredential.keyHash),
			        this_fn
			);
			break;
		case STAKE_CREDENTIAL_SCRIPT_HASH:
			ui_displayBech32Screen(
			        "Staking script hash",
			        "script",
			        BODY_CTX->stageData.certificate.stakeCredential.scriptHash,
			        SIZEOF(BODY_CTX->stageData.certificate.stakeCredential.scriptHash),
			        this_fn
			);
			break;
		default:
			ASSERT(false);
			break;
		}
	}
	UI_STEP(HANDLE_CERTIFICATE_STEP_CONFIRM) {
		char description[50] = {0};
		explicit_bzero(description, SIZEOF(description));

		switch (BODY_CTX->stageData.certificate.type) {
		case CERTIFICATE_TYPE_STAKE_REGISTRATION:
			snprintf(description, SIZEOF(description), "registration?");
			break;

		case CERTIFICATE_TYPE_STAKE_DEREGISTRATION:
			snprintf(description, SIZEOF(description), "deregistration?");
			break;

		case CERTIFICATE_TYPE_STAKE_DELEGATION:
			snprintf(description, SIZEOF(description), "delegation?");
			break;

		default:
			ASSERT(false);
		}
		// make sure all the information is displayed to the user
		ASSERT(strlen(description) + 1 < SIZEOF(description));

		ui_displayPrompt(
		        "Confirm",
		        description,
		        this_fn,
		        respond_with_user_reject
		);
	}
	UI_STEP(HANDLE_CERTIFICATE_STEP_RESPOND) {
		respondSuccessEmptyMsg();

		advanceCertificatesStateIfAppropriate();
	}
	UI_STEP_END(HANDLE_CERTIFICATE_STEP_INVALID);
}

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
	ASSERT(BODY_CTX->stageData.certificate.type == CERTIFICATE_TYPE_STAKE_POOL_RETIREMENT);

	ui_callback_fn_t* this_fn = signTx_handleCertificatePoolRetirement_ui_runStep;

	UI_STEP_BEGIN(ctx->ui_step, this_fn);

	UI_STEP(HANDLE_CERTIFICATE_POOL_RETIREMENT_STEP_DISPLAY_OPERATION) {
		ui_displayBech32Screen(
		        "Retire stake pool",
		        "pool",
		        BODY_CTX->stageData.certificate.poolKeyHash, SIZEOF(BODY_CTX->stageData.certificate.poolKeyHash),
		        this_fn
		);
	}
	UI_STEP(HANDLE_CERTIFICATE_POOL_RETIREMENT_STEP_DISPLAY_EPOCH) {
		ui_displayUint64Screen(
		        "at the start of epoch",
		        BODY_CTX->stageData.certificate.epoch,
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

static void _parsePathSpec(read_view_t* view, bip44_path_t* pathSpec)
{
	view_skipBytes(view, bip44_parseFromWire(pathSpec, VIEW_REMAINING_TO_TUPLE_BUF_SIZE(view)));
	TRACE();
	BIP44_PRINTF(pathSpec);
	PRINTF("\n");
}

static void _parseStakeCredential(read_view_t* view, stake_credential_t* stakeCredential)
{
	stakeCredential->type = parse_u1be(view);
	switch (stakeCredential->type) {
	case STAKE_CREDENTIAL_KEY_PATH:
		_parsePathSpec(view, &stakeCredential->keyPath);
		break;
	case STAKE_CREDENTIAL_KEY_HASH: {
		STATIC_ASSERT(SIZEOF(stakeCredential->keyHash) == ADDRESS_KEY_HASH_LENGTH, "bad key hash container size");
		view_parseBuffer(stakeCredential->keyHash, view, SIZEOF(stakeCredential->keyHash));
		break;
	}
	case STAKE_CREDENTIAL_SCRIPT_HASH: {
		STATIC_ASSERT(SIZEOF(stakeCredential->scriptHash) == SCRIPT_HASH_LENGTH, "bad script hash container size");
		view_parseBuffer(stakeCredential->scriptHash, view, SIZEOF(stakeCredential->scriptHash));
		break;
	}
	default:
		THROW(ERR_INVALID_DATA);
	}
}

static void _parseCertificateData(const uint8_t* wireDataBuffer, size_t wireDataSize, sign_tx_certificate_data_t* certificateData)
{
	ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	TRACE_BUFFER(wireDataBuffer, wireDataSize);

	read_view_t view = make_read_view(wireDataBuffer, wireDataBuffer + wireDataSize);

	certificateData->type = parse_u1be(&view);
	TRACE("Certificate type: %d", certificateData->type);

	switch (certificateData->type) {
	case CERTIFICATE_TYPE_STAKE_REGISTRATION:
		_parseStakeCredential(&view, &certificateData->stakeCredential);
		break;

	case CERTIFICATE_TYPE_STAKE_DEREGISTRATION:
		_parseStakeCredential(&view, &certificateData->stakeCredential);
		break;

	case CERTIFICATE_TYPE_STAKE_DELEGATION:
		_parseStakeCredential(&view, &certificateData->stakeCredential);
		STATIC_ASSERT(SIZEOF(certificateData->poolKeyHash) == POOL_KEY_HASH_LENGTH, "wrong poolKeyHash size");
		view_parseBuffer(certificateData->poolKeyHash, &view, POOL_KEY_HASH_LENGTH);
		break;

	case CERTIFICATE_TYPE_STAKE_POOL_REGISTRATION:
		// nothing more to parse, certificate data will be provided
		// in additional APDUs processed by a submachine
		return;

	case CERTIFICATE_TYPE_STAKE_POOL_RETIREMENT:
		_parsePathSpec(&view, &certificateData->poolIdPath);
		certificateData->epoch = parse_u8be(&view);
		break;

	default:
		THROW(ERR_INVALID_DATA);
	}

	VALIDATE(view_remainingSize(&view) == 0, ERR_INVALID_DATA);
}

static void _fillHashFromPath(const bip44_path_t* path,
                              uint8_t* hash, size_t hashSize)
{
	ASSERT(ADDRESS_KEY_HASH_LENGTH <= hashSize);
	ASSERT(hashSize < BUFFER_SIZE_PARANOIA);

	bip44_pathToKeyHash(
	        path,
	        hash, hashSize
	);
}

static void _fillHashFromStakeCredential(const stake_credential_t* stakeCredential,
        uint8_t* hash, size_t hashSize)
{
	ASSERT(hashSize < BUFFER_SIZE_PARANOIA);

	switch (stakeCredential->type) {
	case STAKE_CREDENTIAL_KEY_PATH:
		_fillHashFromPath(&stakeCredential->keyPath, hash, hashSize);
		break;
	case STAKE_CREDENTIAL_KEY_HASH:
		ASSERT(ADDRESS_KEY_HASH_LENGTH <= hashSize);
		STATIC_ASSERT(SIZEOF(stakeCredential->keyHash) == ADDRESS_KEY_HASH_LENGTH, "bad key hash container size");
		memmove(hash, stakeCredential->keyHash, SIZEOF(stakeCredential->keyHash));
		break;
	case STAKE_CREDENTIAL_SCRIPT_HASH:
		ASSERT(SCRIPT_HASH_LENGTH <= hashSize);
		STATIC_ASSERT(SIZEOF(stakeCredential->scriptHash) == SCRIPT_HASH_LENGTH, "bad script hash container size");
		memmove(hash, stakeCredential->scriptHash, SIZEOF(stakeCredential->scriptHash));
		break;
	default:
		ASSERT(false);
		break;
	}
}


__noinline_due_to_stack__
static void _addCertificateDataToTx(
        sign_tx_certificate_data_t* certificateData,
        tx_hash_builder_t* txHashBuilder
)
{
	// data only added in the sub-machine, see signTxPoolRegistration.c
	ASSERT(BODY_CTX->stageData.certificate.type != CERTIFICATE_TYPE_STAKE_POOL_REGISTRATION);

	TRACE("Adding certificate (type %d) to tx hash", certificateData->type);

	STATIC_ASSERT(ADDRESS_KEY_HASH_LENGTH == SCRIPT_HASH_LENGTH, "incompatible hash sizes");
	uint8_t stakingHash[ADDRESS_KEY_HASH_LENGTH] = {0};

	switch (BODY_CTX->stageData.certificate.type) {

	case CERTIFICATE_TYPE_STAKE_REGISTRATION:
	case CERTIFICATE_TYPE_STAKE_DEREGISTRATION: {
		_fillHashFromStakeCredential(&BODY_CTX->stageData.certificate.stakeCredential, stakingHash, SIZEOF(stakingHash));
		txHashBuilder_addCertificate_stakingHash(
		        txHashBuilder, certificateData->type, certificateData->stakeCredential.type,
		        stakingHash, SIZEOF(stakingHash)
		);
		break;
	}

	case CERTIFICATE_TYPE_STAKE_DELEGATION: {
		_fillHashFromStakeCredential(&BODY_CTX->stageData.certificate.stakeCredential, stakingHash, SIZEOF(stakingHash));
		txHashBuilder_addCertificate_delegation(
		        txHashBuilder, certificateData->stakeCredential.type,
		        stakingHash, SIZEOF(stakingHash),
		        certificateData->poolKeyHash, SIZEOF(certificateData->poolKeyHash)
		);
		break;
	}

	case CERTIFICATE_TYPE_STAKE_POOL_RETIREMENT: {
		_fillHashFromPath(&BODY_CTX->stageData.certificate.poolIdPath, certificateData->poolKeyHash, SIZEOF(certificateData->poolKeyHash));
		txHashBuilder_addCertificate_poolRetirement(
		        txHashBuilder,
		        certificateData->poolKeyHash, SIZEOF(certificateData->poolKeyHash),
		        certificateData->epoch
		);
		break;
	}

	default:
		ASSERT(false);
	}
}

__noinline_due_to_stack__
static void signTx_handleCertificateAPDU(uint8_t p2, const uint8_t* wireDataBuffer, size_t wireDataSize)
{
	TRACE_STACK_USAGE();
	ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	ASSERT(BODY_CTX->currentCertificate < ctx->numCertificates);

	// delegate to state sub-machine for stake pool registration certificate data
	if (signTxPoolRegistration_isValidInstruction(p2)) {
		TRACE();
		VALIDATE(ctx->stage == SIGN_STAGE_BODY_CERTIFICATES_POOL_SUBMACHINE, ERR_INVALID_DATA);

		TRACE_STACK_USAGE();

		signTxPoolRegistration_handleAPDU(p2, wireDataBuffer, wireDataSize);
		return;
	}

	VALIDATE(p2 == P2_UNUSED, ERR_INVALID_REQUEST_PARAMETERS);
	CHECK_STAGE(SIGN_STAGE_BODY_CERTIFICATES);

	// a new certificate arrived
	explicit_bzero(&BODY_CTX->stageData.certificate, SIZEOF(BODY_CTX->stageData.certificate));

	_parseCertificateData(wireDataBuffer, wireDataSize, &BODY_CTX->stageData.certificate);

	{
		// basic policy that just decides if the certificate is allowed
		security_policy_t policy = policyForSignTxCertificate(
		                                   ctx->commonTxData.txSigningMode,
		                                   BODY_CTX->stageData.certificate.type
		                           );
		TRACE("Policy: %d", (int) policy);
		ENSURE_NOT_DENIED(policy);
	}

	// TODO refactor --- does it make sense to process different certificate types entirely separately?
	// or perhaps group registration with deregistration?
	// notice that _parseCertificateData and _addCertificateDataToTx already do a big switch on cert type
	switch (BODY_CTX->stageData.certificate.type) {
	case CERTIFICATE_TYPE_STAKE_REGISTRATION:
	case CERTIFICATE_TYPE_STAKE_DEREGISTRATION:
	case CERTIFICATE_TYPE_STAKE_DELEGATION: {
		security_policy_t policy = policyForSignTxCertificateStaking(
		                                   ctx->commonTxData.txSigningMode,
		                                   BODY_CTX->stageData.certificate.type,
		                                   &BODY_CTX->stageData.certificate.stakeCredential
		                           );
		TRACE("Policy: %d", (int) policy);
		ENSURE_NOT_DENIED(policy);

		_addCertificateDataToTx(&BODY_CTX->stageData.certificate, &BODY_CTX->txHashBuilder);

		switch (policy) {
#define  CASE(POLICY, UI_STEP) case POLICY: {ctx->ui_step=UI_STEP; break;}
			CASE(POLICY_PROMPT_BEFORE_RESPONSE, HANDLE_CERTIFICATE_STEP_DISPLAY_OPERATION);
			CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_CERTIFICATE_STEP_RESPOND);
#undef   CASE
		default:
			THROW(ERR_NOT_IMPLEMENTED);
		}

		signTx_handleCertificate_ui_runStep();
		return;
	}

	case CERTIFICATE_TYPE_STAKE_POOL_REGISTRATION: {
		// pool registration certificates have a separate sub-machine for handling APDU and UI
		// nothing more to be done with them here, we just init the sub-machine
		ctx->stage = SIGN_STAGE_BODY_CERTIFICATES_POOL_SUBMACHINE;
		signTxPoolRegistration_init();

		respondSuccessEmptyMsg();
		return;
	}

	case CERTIFICATE_TYPE_STAKE_POOL_RETIREMENT: {
		security_policy_t policy = policyForSignTxCertificateStakePoolRetirement(
		                                   ctx->commonTxData.txSigningMode,
		                                   &BODY_CTX->stageData.certificate.poolIdPath,
		                                   BODY_CTX->stageData.certificate.epoch
		                           );
		TRACE("Policy: %d", (int) policy);
		ENSURE_NOT_DENIED(policy);

		_addCertificateDataToTx(&BODY_CTX->stageData.certificate, &BODY_CTX->txHashBuilder);

		switch (policy) {
#define  CASE(POLICY, UI_STEP) case POLICY: {ctx->ui_step=UI_STEP; break;}
			CASE(POLICY_PROMPT_BEFORE_RESPONSE, HANDLE_CERTIFICATE_POOL_RETIREMENT_STEP_DISPLAY_OPERATION);
			CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_CERTIFICATE_POOL_RETIREMENT_STEP_RESPOND);
#undef   CASE
		default:
			THROW(ERR_NOT_IMPLEMENTED);
		}
		signTx_handleCertificatePoolRetirement_ui_runStep();
		return;
	}

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
		ui_displayAdaAmountScreen("Withdrawing rewards", BODY_CTX->stageData.withdrawal.amount, this_fn);
	}
	UI_STEP(HANDLE_WITHDRAWAL_STEP_DISPLAY_PATH) {
		reward_account_t rewardAccount;
		switch (BODY_CTX->stageData.withdrawal.stakeCredential.type) {
		case STAKE_CREDENTIAL_KEY_PATH: {
			rewardAccount.keyReferenceType = KEY_REFERENCE_PATH;
			rewardAccount.path = BODY_CTX->stageData.withdrawal.stakeCredential.keyPath;
			break;
		}
		case STAKE_CREDENTIAL_KEY_HASH: {
			rewardAccount.keyReferenceType = KEY_REFERENCE_HASH;
			constructRewardAddressFromHash(
			        ctx->commonTxData.networkId,
			        REWARD_HASH_SOURCE_KEY,
			        BODY_CTX->stageData.withdrawal.stakeCredential.keyHash,
			        SIZEOF(BODY_CTX->stageData.withdrawal.stakeCredential.keyHash),
			        rewardAccount.hashBuffer,
			        SIZEOF(rewardAccount.hashBuffer)
			);
			break;
		}
		case STAKE_CREDENTIAL_SCRIPT_HASH: {
			rewardAccount.keyReferenceType = KEY_REFERENCE_HASH;
			constructRewardAddressFromHash(
			        ctx->commonTxData.networkId,
			        REWARD_HASH_SOURCE_SCRIPT,
			        BODY_CTX->stageData.withdrawal.stakeCredential.scriptHash,
			        SIZEOF(BODY_CTX->stageData.withdrawal.stakeCredential.scriptHash),
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
		ASSERT(BODY_CTX->currentWithdrawal < ctx->numWithdrawals);
		BODY_CTX->currentWithdrawal++;

		if (BODY_CTX->currentWithdrawal == ctx->numWithdrawals) {
			advanceStage();
		}
	}
	UI_STEP_END(HANDLE_WITHDRAWAL_STEP_INVALID);
}

__noinline_due_to_stack__
static void _addWithdrawalToTxHash(bool validateCanonicalOrdering)
{
	uint8_t rewardAddress[REWARD_ACCOUNT_SIZE] = {0};

	switch (BODY_CTX->stageData.withdrawal.stakeCredential.type) {
	case STAKE_CREDENTIAL_KEY_PATH:
		constructRewardAddressFromKeyPath(
		        &BODY_CTX->stageData.withdrawal.stakeCredential.keyPath,
		        ctx->commonTxData.networkId,
		        rewardAddress,
		        SIZEOF(rewardAddress)
		);
		break;
	case STAKE_CREDENTIAL_KEY_HASH:
		constructRewardAddressFromHash(
		        ctx->commonTxData.networkId,
		        REWARD_HASH_SOURCE_KEY,
		        BODY_CTX->stageData.withdrawal.stakeCredential.keyHash,
		        SIZEOF(BODY_CTX->stageData.withdrawal.stakeCredential.keyHash),
		        rewardAddress,
		        SIZEOF(rewardAddress)
		);
		break;
	case STAKE_CREDENTIAL_SCRIPT_HASH:
		constructRewardAddressFromHash(
		        ctx->commonTxData.networkId,
		        REWARD_HASH_SOURCE_SCRIPT,
		        BODY_CTX->stageData.withdrawal.stakeCredential.scriptHash,
		        SIZEOF(BODY_CTX->stageData.withdrawal.stakeCredential.scriptHash),
		        rewardAddress,
		        SIZEOF(rewardAddress)
		);
		break;
	default:
		ASSERT(false);
		return;
	}

	{
		STATIC_ASSERT(SIZEOF(BODY_CTX->stageData.withdrawal.previousRewardAccount) == REWARD_ACCOUNT_SIZE, "wrong reward account buffer size");
		STATIC_ASSERT(SIZEOF(rewardAddress) == REWARD_ACCOUNT_SIZE, "wrong reward account buffer size");

		if (validateCanonicalOrdering) {
			// compare with previous map entry
			VALIDATE(cbor_mapKeyFulfillsCanonicalOrdering(
			                 BODY_CTX->stageData.withdrawal.previousRewardAccount, REWARD_ACCOUNT_SIZE,
			                 rewardAddress, REWARD_ACCOUNT_SIZE
			         ), ERR_INVALID_DATA);
		}

		// update the value for potential future comparison
		memmove(BODY_CTX->stageData.withdrawal.previousRewardAccount, rewardAddress, REWARD_ACCOUNT_SIZE);
	}

	TRACE("Adding withdrawal to tx hash");
	txHashBuilder_addWithdrawal(
	        &BODY_CTX->txHashBuilder,
	        rewardAddress, SIZEOF(rewardAddress),
	        BODY_CTX->stageData.withdrawal.amount
	);
}

__noinline_due_to_stack__
static void signTx_handleWithdrawalAPDU(uint8_t p2, const uint8_t* wireDataBuffer, size_t wireDataSize)
{
	TRACE_STACK_USAGE();
	{
		// sanity checks
		CHECK_STAGE(SIGN_STAGE_BODY_WITHDRAWALS);
		ASSERT(BODY_CTX->currentWithdrawal < ctx->numWithdrawals);

		VALIDATE(p2 == P2_UNUSED, ERR_INVALID_REQUEST_PARAMETERS);
		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}

	explicit_bzero(&BODY_CTX->stageData.withdrawal, SIZEOF(BODY_CTX->stageData.withdrawal));

	{
		// parse input
		TRACE_BUFFER(wireDataBuffer, wireDataSize);

		read_view_t view = make_read_view(wireDataBuffer, wireDataBuffer + wireDataSize);
		BODY_CTX->stageData.withdrawal.amount = parse_u8be(&view);

		_parseStakeCredential(&view, &BODY_CTX->stageData.withdrawal.stakeCredential);

		VALIDATE(view_remainingSize(&view) == 0, ERR_INVALID_DATA);

	}

	security_policy_t policy = policyForSignTxWithdrawal(
	                                   ctx->commonTxData.txSigningMode,
	                                   &BODY_CTX->stageData.withdrawal.stakeCredential
	                           );
	TRACE("Policy: %d", (int) policy);
	ENSURE_NOT_DENIED(policy);

	const bool validateCanonicalOrdering = BODY_CTX->currentWithdrawal > 0;
	_addWithdrawalToTxHash(validateCanonicalOrdering);

	{
		// select UI steps
		switch (policy) {
#define  CASE(POLICY, UI_STEP) case POLICY: {ctx->ui_step=UI_STEP; break;}
			CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_WITHDRAWAL_STEP_DISPLAY_AMOUNT);
			CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_WITHDRAWAL_STEP_RESPOND);
#undef   CASE
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
		        BODY_CTX->stageData.validityIntervalStart,
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

static void signTx_handleValidityIntervalStartAPDU(uint8_t p2, const uint8_t* wireDataBuffer, size_t wireDataSize)
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
		BODY_CTX->stageData.validityIntervalStart = u8be_read(wireDataBuffer);
		BODY_CTX->validityIntervalStartReceived = true;
	}

	security_policy_t policy = policyForSignTxValidityIntervalStart();
	TRACE("Policy: %d", (int) policy);
	ENSURE_NOT_DENIED(policy);

	{
		TRACE("Adding validity interval start to tx hash");
		txHashBuilder_addValidityIntervalStart(
		        &BODY_CTX->txHashBuilder,
		        BODY_CTX->stageData.validityIntervalStart
		);
		TRACE();
	}

	{
		// select UI step
		switch (policy) {
#define  CASE(POLICY, UI_STEP) case POLICY: {ctx->ui_step=UI_STEP; break;}
			CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_VALIDITY_INTERVAL_START_STEP_DISPLAY);
			CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_VALIDITY_INTERVAL_START_STEP_RESPOND);
#undef   CASE
		default:
			THROW(ERR_NOT_IMPLEMENTED);
		}
	}

	signTx_handleValidityInterval_ui_runStep();
}

// ============================== MINT ==============================

static void signTx_handleMintAPDU(uint8_t p2, const uint8_t* wireDataBuffer, size_t wireDataSize)
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
	VALIDATE(signTxMint_isValidInstruction(p2), ERR_INVALID_REQUEST_PARAMETERS);
	signTxMint_handleAPDU(p2, wireDataBuffer, wireDataSize);
}

// ========================= SCRIPT DATA HASH ==========================


enum {
	HANDLE_SCRIPT_DATA_HASH_STEP_DISPLAY = 1200,
	HANDLE_SCRIPT_DATA_HASH_STEP_RESPOND,
	HANDLE_SCRIPT_DATA_HASH_STEP_INVALID,
};

static void signTx_handleScriptDataHash_ui_runStep()
{
	TRACE("UI step %d", ctx->ui_step);
	ui_callback_fn_t* this_fn = signTx_handleScriptDataHash_ui_runStep;

	UI_STEP_BEGIN(ctx->ui_step, this_fn);

	UI_STEP(HANDLE_SCRIPT_DATA_HASH_STEP_DISPLAY) {
		ui_displayBech32Screen(
		        "Script data hash",
		        "script_data",
		        BODY_CTX->stageData.scriptDataHash, SCRIPT_DATA_HASH_LENGTH,
		        this_fn
		);
	}
	UI_STEP(HANDLE_SCRIPT_DATA_HASH_STEP_RESPOND) {
		respondSuccessEmptyMsg();
		advanceStage();
	}
	UI_STEP_END(HANDLE_FEE_STEP_INVALID);
}

static void signTx_handleScriptDataHashAPDU(uint8_t p2, const uint8_t* wireDataBuffer, size_t wireDataSize)
{
	{
		// sanity checks
		CHECK_STAGE(SIGN_STAGE_BODY_SCRIPT_DATA_HASH);

		VALIDATE(p2 == P2_UNUSED, ERR_INVALID_REQUEST_PARAMETERS);
		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}
	{
		// parse data
		TRACE_BUFFER(wireDataBuffer, wireDataSize);

		read_view_t view = make_read_view(wireDataBuffer, wireDataBuffer + wireDataSize);
		STATIC_ASSERT(SIZEOF(BODY_CTX->stageData.scriptDataHash) == SCRIPT_DATA_HASH_LENGTH, "wrong script data hash length");
		view_parseBuffer(BODY_CTX->stageData.scriptDataHash, &view, SCRIPT_DATA_HASH_LENGTH);
		VALIDATE(view_remainingSize(&view) == 0, ERR_INVALID_DATA);

		BODY_CTX->scriptDataHashReceived = true;
	}

	security_policy_t policy = policyForSignTxScriptDataHash(ctx->commonTxData.txSigningMode);
	TRACE("Policy: %d", (int) policy);
	ENSURE_NOT_DENIED(policy);

	{
		// add to tx
		TRACE("Adding script data hash to tx hash");
		txHashBuilder_addScriptDataHash(&BODY_CTX->txHashBuilder, BODY_CTX->stageData.scriptDataHash, SIZEOF(BODY_CTX->stageData.scriptDataHash));
	}

	{
		// select UI steps
		switch (policy) {
#	define  CASE(POLICY, UI_STEP) case POLICY: {ctx->ui_step=UI_STEP; break;}
			CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_SCRIPT_DATA_HASH_STEP_DISPLAY);
			CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_SCRIPT_DATA_HASH_STEP_RESPOND);
#	undef   CASE
		default:
			THROW(ERR_NOT_IMPLEMENTED);
		}
	}

	signTx_handleScriptDataHash_ui_runStep();
}

// ============================== COLLATERAL INPUTS ==============================

// Advance stage to the next collateral input
static void ui_advanceState_collateralInput()
{
	ASSERT(BODY_CTX->currentCollateral < ctx->numCollateralInputs);
	BODY_CTX->currentCollateral++;

	if (BODY_CTX->currentCollateral == ctx->numCollateralInputs) {
		advanceStage();
	}
}

__noinline_due_to_stack__
static void signTx_handleCollateralInputAPDU(uint8_t p2, const uint8_t* wireDataBuffer, size_t wireDataSize)
{
	TRACE_STACK_USAGE();
	{
		// sanity checks
		CHECK_STAGE(SIGN_STAGE_BODY_COLLATERAL_INPUTS);
		ASSERT(BODY_CTX->currentCollateral < ctx->numCollateralInputs);

		VALIDATE(p2 == P2_UNUSED, ERR_INVALID_REQUEST_PARAMETERS);
		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}

	parseInput(wireDataBuffer, wireDataSize);

	security_policy_t policy = policyForSignTxCollateralInput(
	                                   ctx->commonTxData.txSigningMode,
	                                   ctx->includeTotalCollateral
	                           );
	TRACE("Policy: %d", (int) policy);
	ENSURE_NOT_DENIED(policy);

	{
		// add to tx
		TRACE("Adding collateral input to tx hash");
		txHashBuilder_addCollateralInput(
		        &BODY_CTX->txHashBuilder,
		        &BODY_CTX->stageData.input.input_data
		);
	}
	{
		// not needed if input is not shown, but does not cost much time, so not worth branching
		constructInputLabel("Collat. input", BODY_CTX->currentCollateral);

		ctx->ui_advanceState = ui_advanceState_collateralInput;
		ui_selectInputStep(policy);
		signTx_handleInput_ui_runStep();
	}
}

// ========================= REQUIRED SIGNERS ===========================

enum {
	HANDLE_REQUIRED_SIGNERS_STEP_DISPLAY = 1400,
	HANDLE_REQUIRED_SIGNERS_STEP_RESPOND,
	HANDLE_REQUIRED_SIGNERS_STEP_INVALID,
};

static void signTx_handleRequiredSigner_ui_runStep()
{
	TRACE("UI step %d", ctx->ui_step);
	ui_callback_fn_t* this_fn = signTx_handleRequiredSigner_ui_runStep;

	UI_STEP_BEGIN(ctx->ui_step, this_fn);

	UI_STEP(HANDLE_REQUIRED_SIGNERS_STEP_DISPLAY) {
		switch (BODY_CTX->stageData.requiredSigner.type) {
		case REQUIRED_SIGNER_WITH_PATH:
			ui_displayPathScreen("Required signer", &BODY_CTX->stageData.requiredSigner.keyPath, this_fn);
			break;
		case REQUIRED_SIGNER_WITH_HASH:
			ui_displayBech32Screen(
			        "Required signer",
			        "req_signer_vkh",
			        BODY_CTX->stageData.requiredSigner.keyHash,
			        SIZEOF(BODY_CTX->stageData.requiredSigner.keyHash),
			        this_fn
			);
			break;

		default:
			ASSERT(false);
			break;
		}
	}

	UI_STEP(HANDLE_REQUIRED_SIGNERS_STEP_RESPOND) {
		respondSuccessEmptyMsg();

		// Advance stage to the next input
		ASSERT(BODY_CTX->currentRequiredSigner < ctx->numRequiredSigners);
		BODY_CTX->currentRequiredSigner++;

		if (BODY_CTX->currentRequiredSigner == ctx->numRequiredSigners) {
			advanceStage();
		}
	}
	UI_STEP_END(HANDLE_REQUIRED_SIGNERS_STEP_INVALID);
}

__noinline_due_to_stack__
static void signTx_handleRequiredSignerAPDU(uint8_t p2, const uint8_t* wireDataBuffer, size_t wireDataSize)
{
	TRACE_STACK_USAGE();
	{
		// sanity checks
		CHECK_STAGE(SIGN_STAGE_BODY_REQUIRED_SIGNERS);
		ASSERT(BODY_CTX->currentRequiredSigner < ctx->numRequiredSigners);

		VALIDATE(p2 == P2_UNUSED, ERR_INVALID_REQUEST_PARAMETERS);
		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}

	{
		TRACE_BUFFER(wireDataBuffer, wireDataSize);

		read_view_t view = make_read_view(wireDataBuffer, wireDataBuffer + wireDataSize);
		BODY_CTX->stageData.requiredSigner.type = parse_u1be(&view);
		STATIC_ASSERT(SIZEOF(BODY_CTX->stageData.requiredSigner.keyHash) == ADDRESS_KEY_HASH_LENGTH, "wrong key hash length");
		switch (BODY_CTX->stageData.requiredSigner.type) {
		case REQUIRED_SIGNER_WITH_PATH:
			_parsePathSpec(&view, &BODY_CTX->stageData.requiredSigner.keyPath);
			break;
		case REQUIRED_SIGNER_WITH_HASH:
			view_parseBuffer(BODY_CTX->stageData.requiredSigner.keyHash, &view, ADDRESS_KEY_HASH_LENGTH);
			break;
		}
		VALIDATE(view_remainingSize(&view) == 0, ERR_INVALID_DATA);
	}

	security_policy_t policy = policyForSignTxRequiredSigner(
	                                   ctx->commonTxData.txSigningMode,
	                                   &BODY_CTX->stageData.requiredSigner
	                           );
	TRACE("Policy: %d", (int) policy);
	ENSURE_NOT_DENIED(policy);

	{
		// add to tx
		TRACE("Adding required signer to tx hash");
		if (BODY_CTX->stageData.requiredSigner.type == REQUIRED_SIGNER_WITH_PATH) {
			uint8_t keyHash[ADDRESS_KEY_HASH_LENGTH] = {0};
			bip44_pathToKeyHash(&BODY_CTX->stageData.requiredSigner.keyPath, keyHash, SIZEOF(keyHash));
			txHashBuilder_addRequiredSigner(
			        &BODY_CTX->txHashBuilder,
			        keyHash, SIZEOF(keyHash)
			);
		} else {
			txHashBuilder_addRequiredSigner(
			        &BODY_CTX->txHashBuilder,
			        BODY_CTX->stageData.requiredSigner.keyHash, SIZEOF(BODY_CTX->stageData.requiredSigner.keyHash)
			);
		}
	}

	{
		// select UI steps
		switch (policy) {
#	define  CASE(POLICY, UI_STEP) case POLICY: {ctx->ui_step=UI_STEP; break;}
			CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_REQUIRED_SIGNERS_STEP_DISPLAY);
			CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_REQUIRED_SIGNERS_STEP_RESPOND);
#	undef   CASE
		default:
			THROW(ERR_NOT_IMPLEMENTED);
		}
	}
	signTx_handleRequiredSigner_ui_runStep();
}
// ========================= COLLATERAL RETURN OUTPUT ===========================

static void signTx_handleCollateralOutputAPDU(uint8_t p2, const uint8_t* wireDataBuffer, size_t wireDataSize)
{
	{
		TRACE("p2 = %d", p2);
		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
		TRACE_BUFFER(wireDataBuffer, wireDataSize);
	}

	if (ctx->stage == SIGN_STAGE_BODY_COLLATERAL_OUTPUT) {
		// first APDU for collateral return output
		initializeOutputSubmachine();
		ctx->stage = SIGN_STAGE_BODY_COLLATERAL_OUTPUT_SUBMACHINE;
	}

	CHECK_STAGE(SIGN_STAGE_BODY_COLLATERAL_OUTPUT_SUBMACHINE);

	// all output handling is delegated to a state sub-machine
	VALIDATE(signTxCollateralOutput_isValidInstruction(p2), ERR_INVALID_REQUEST_PARAMETERS);
	signTxCollateralOutput_handleAPDU(p2, wireDataBuffer, wireDataSize);
}

// ========================= TOTAL COLLATERAL ===========================

enum {
	HANDLE_TOTAL_COLLATERAL_STEP_DISPLAY = 400,
	HANDLE_TOTAL_COLLATERAL_STEP_RESPOND,
	HANDLE_TOTAL_COLLATERAL_STEP_INVALID,
};

static void signTx_handleTotalCollateral_ui_runStep()
{
	TRACE("UI step %d", ctx->ui_step);
	ui_callback_fn_t* this_fn = signTx_handleTotalCollateral_ui_runStep;

	TRACE_ADA_AMOUNT("total collateral ", BODY_CTX->stageData.totalCollateral);

	UI_STEP_BEGIN(ctx->ui_step, this_fn);

	UI_STEP(HANDLE_TOTAL_COLLATERAL_STEP_DISPLAY) {
		ui_displayAdaAmountScreen("Total collateral", BODY_CTX->stageData.totalCollateral, this_fn);
	}
	UI_STEP(HANDLE_TOTAL_COLLATERAL_STEP_RESPOND) {
		respondSuccessEmptyMsg();
		advanceStage();
	}
	UI_STEP_END(HANDLE_TOTAL_COLLATERAL_STEP_INVALID);
}

__noinline_due_to_stack__
static void signTx_handleTotalCollateralAPDU(uint8_t p2, const uint8_t* wireDataBuffer, size_t wireDataSize)
{
	{
		// sanity checks
		CHECK_STAGE(SIGN_STAGE_BODY_TOTAL_COLLATERAL);

		VALIDATE(p2 == P2_UNUSED, ERR_INVALID_REQUEST_PARAMETERS);
		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}
	{
		// parse data
		TRACE_BUFFER(wireDataBuffer, wireDataSize);

		VALIDATE(wireDataSize == 8, ERR_INVALID_DATA);

		BODY_CTX->stageData.totalCollateral = u8be_read(wireDataBuffer);
		BODY_CTX->totalCollateralReceived = true;
		TRACE("totalCollateral:");
		TRACE_UINT64(BODY_CTX->stageData.totalCollateral);
	}

	security_policy_t policy = policyForSignTxTotalCollateral();
	TRACE("Policy: %d", (int) policy);
	ENSURE_NOT_DENIED(policy);

	{
		// add to tx
		TRACE("Adding total collateral to tx hash");
		txHashBuilder_addTotalCollateral(&BODY_CTX->txHashBuilder, BODY_CTX->stageData.totalCollateral);
	}

	{
		// select UI steps
		switch (policy) {
#define  CASE(POLICY, UI_STEP) case POLICY: {ctx->ui_step=UI_STEP; break;}
			CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_FEE_STEP_DISPLAY);
			CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_FEE_STEP_RESPOND);
#undef   CASE
		default:
			THROW(ERR_NOT_IMPLEMENTED);
		}
	}

	signTx_handleTotalCollateral_ui_runStep();
}

// ============================== REFERENCE INPUTS ==============================

// Advance stage to the next input
static void ui_advanceState_ReferenceInput()
{
	ASSERT(BODY_CTX->currentReferenceInput < ctx->numReferenceInputs);
	BODY_CTX->currentReferenceInput++;

	if (BODY_CTX->currentReferenceInput == ctx->numReferenceInputs) {
		advanceStage();
	}
}

__noinline_due_to_stack__
static void signTx_handleReferenceInputsAPDU(uint8_t p2, const uint8_t* wireDataBuffer, size_t wireDataSize)
{
	TRACE_STACK_USAGE();
	{
		// sanity checks
		CHECK_STAGE(SIGN_STAGE_BODY_REFERENCE_INPUTS);
		ASSERT(BODY_CTX->currentReferenceInput < ctx->numReferenceInputs);

		VALIDATE(p2 == P2_UNUSED, ERR_INVALID_REQUEST_PARAMETERS);
		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}
	// Parsed in same way as the inputs
	parseInput(wireDataBuffer, wireDataSize);

	security_policy_t policy = policyForSignTxReferenceInput(ctx->commonTxData.txSigningMode);
	TRACE("Policy: %d", (int) policy);
	ENSURE_NOT_DENIED(policy);

	{
		// add to tx
		TRACE("Adding reference input to tx hash");
		txHashBuilder_addReferenceInput(
		        &BODY_CTX->txHashBuilder,
		        &BODY_CTX->stageData.input.input_data
		);
	}
	{
		// not needed if input is not shown, but does not cost much time, so not worth branching
		constructInputLabel("Refer. input", BODY_CTX->currentReferenceInput);

		ctx->ui_advanceState = ui_advanceState_ReferenceInput;
		ui_selectInputStep(policy);
		signTx_handleInput_ui_runStep();
	}
}

// ============================== CONFIRM ==============================

enum {
	HANDLE_CONFIRM_STEP_TXID = 1000,
	HANDLE_CONFIRM_STEP_FINAL_CONFIRM,
	HANDLE_CONFIRM_STEP_RESPOND,
	HANDLE_CONFIRM_STEP_INVALID,
};

static void signTx_handleConfirm_ui_runStep()
{
	TRACE("UI step %d", ctx->ui_step);
	TRACE_STACK_USAGE();
	ui_callback_fn_t* this_fn = signTx_handleConfirm_ui_runStep;

	UI_STEP_BEGIN(ctx->ui_step, this_fn);

	UI_STEP(HANDLE_CONFIRM_STEP_TXID) {
		ui_displayHexBufferScreen(
		        "Transaction id",
		        ctx->txHash, SIZEOF(ctx->txHash),
		        this_fn
		);
	}
	UI_STEP(HANDLE_CONFIRM_STEP_FINAL_CONFIRM) {
		ui_displayPrompt(
		        "Confirm",
		        "transaction?",
		        this_fn,
		        respond_with_user_reject
		);
	}
	UI_STEP(HANDLE_CONFIRM_STEP_RESPOND) {
		io_send_buf(SUCCESS, ctx->txHash, SIZEOF(ctx->txHash));
		ui_displayBusy(); // displays dots, called only after I/O to avoid freezing

		advanceStage();
	}
	UI_STEP_END(HANDLE_CONFIRM_STEP_INVALID);
}

static bool _shouldDisplayTxId(sign_tx_signingmode_t signingMode)
{
	switch(signingMode) {

	case SIGN_TX_SIGNINGMODE_ORDINARY_TX:
	case SIGN_TX_SIGNINGMODE_MULTISIG_TX:
		if (ctx->shouldDisplayTxid && app_mode_expert())
			return true;
		return false;

	case SIGN_TX_SIGNINGMODE_PLUTUS_TX:
		return true;

	default:
		return false;
	}
}

__noinline_due_to_stack__
static void signTx_handleConfirmAPDU(uint8_t p2, const uint8_t* wireDataBuffer MARK_UNUSED, size_t wireDataSize)
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

	security_policy_t policy = policyForSignTxConfirm();
	TRACE("Policy: %d", (int) policy);
	ENSURE_NOT_DENIED(policy);

	{
		// compute txHash
		TRACE("Finalizing tx hash");
		txHashBuilder_finalize(
		        &BODY_CTX->txHashBuilder,
		        ctx->txHash, SIZEOF(ctx->txHash)
		);
	}

	{
		// select UI step
		const int firstStep = (_shouldDisplayTxId(ctx->commonTxData.txSigningMode)) ?
		                      HANDLE_CONFIRM_STEP_TXID : HANDLE_CONFIRM_STEP_FINAL_CONFIRM;
		switch (policy) {
#define  CASE(POLICY, UI_STEP) case POLICY: {ctx->ui_step=UI_STEP; break;}
			CASE(POLICY_PROMPT_BEFORE_RESPONSE, firstStep);
			CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_CONFIRM_STEP_RESPOND);
#undef   CASE
		default:
			THROW(ERR_NOT_IMPLEMENTED);
		}
	}

	signTx_handleConfirm_ui_runStep();
}


// ============================== WITNESS ==============================

static void _wipeWitnessSignature()
{
	// safer not to keep the signature in memory
	explicit_bzero(WITNESS_CTX->stageData.witness.signature, SIZEOF(WITNESS_CTX->stageData.witness.signature));
	respond_with_user_reject();
}

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
		        "WARNING:",
		        "unusual witness requested",
		        this_fn
		);
	}
	UI_STEP(HANDLE_WITNESS_STEP_DISPLAY) {
		ui_displayPathScreen("Witness path", &WITNESS_CTX->stageData.witness.path, this_fn);
	}
	UI_STEP(HANDLE_WITNESS_STEP_CONFIRM) {
		ui_displayPrompt(
		        "Sign using",
		        "this witness?",
		        this_fn,
		        _wipeWitnessSignature
		);
	}
	UI_STEP(HANDLE_WITNESS_STEP_RESPOND) {
		TRACE("Sending witness data");
		TRACE_BUFFER(WITNESS_CTX->stageData.witness.signature, SIZEOF(WITNESS_CTX->stageData.witness.signature));
		io_send_buf(SUCCESS, WITNESS_CTX->stageData.witness.signature, SIZEOF(WITNESS_CTX->stageData.witness.signature));
		ui_displayBusy(); // displays dots, called only after I/O to avoid freezing

		WITNESS_CTX->currentWitness++;
		if (WITNESS_CTX->currentWitness == ctx->numWitnesses) {
			advanceStage();
		}
	}
	UI_STEP_END(HANDLE_WITNESS_STEP_INVALID);
}

__noinline_due_to_stack__
static void signTx_handleWitnessAPDU(uint8_t p2, const uint8_t* wireDataBuffer, size_t wireDataSize)
{
	TRACE_STACK_USAGE();
	{
		// sanity checks
		CHECK_STAGE(SIGN_STAGE_WITNESSES);
		VALIDATE(p2 == P2_UNUSED, ERR_INVALID_REQUEST_PARAMETERS);
		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);

		TRACE("Witness no. %d out of %d", WITNESS_CTX->currentWitness + 1, ctx->numWitnesses);
		ASSERT(WITNESS_CTX->currentWitness < ctx->numWitnesses);
	}

	explicit_bzero(&WITNESS_CTX->stageData.witness, SIZEOF(WITNESS_CTX->stageData.witness));

	{
		// parse
		TRACE_BUFFER(wireDataBuffer, wireDataSize);

		size_t parsedSize = bip44_parseFromWire(&WITNESS_CTX->stageData.witness.path, wireDataBuffer, wireDataSize);
		VALIDATE(parsedSize == wireDataSize, ERR_INVALID_DATA);

		TRACE();
		BIP44_PRINTF(&WITNESS_CTX->stageData.witness.path);
		PRINTF("\n");
	}

	security_policy_t policy = policyForSignTxWitness(
	                                   ctx->commonTxData.txSigningMode,
	                                   &WITNESS_CTX->stageData.witness.path,
	                                   ctx->includeMint,
	                                   ctx->poolOwnerByPath ? &ctx->poolOwnerPath : NULL
	                           );
	TRACE("Policy: %d", (int) policy);
	ENSURE_NOT_DENIED(policy);

	{
		// compute witness
		TRACE("getWitness");
		TRACE("TX HASH");
		TRACE_BUFFER(ctx->txHash, SIZEOF(ctx->txHash));
		TRACE("END TX HASH");

		getWitness(
		        &WITNESS_CTX->stageData.witness.path,
		        ctx->txHash, SIZEOF(ctx->txHash),
		        WITNESS_CTX->stageData.witness.signature, SIZEOF(WITNESS_CTX->stageData.witness.signature)
		);
	}

	{
		// choose UI steps
		switch (policy) {
#define  CASE(POLICY, UI_STEP) case POLICY: {ctx->ui_step=UI_STEP; break;}
			CASE(POLICY_PROMPT_WARN_UNUSUAL, HANDLE_WITNESS_STEP_WARNING);
			CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_WITNESS_STEP_DISPLAY);
			CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_WITNESS_STEP_RESPOND);
#undef   CASE
		default:
			THROW(ERR_NOT_IMPLEMENTED);
		}
	}
	signTx_handleWitness_ui_runStep();
}


// ============================== MAIN HANDLER ==============================

typedef void subhandler_fn_t(uint8_t p2, const uint8_t* dataBuffer, size_t dataSize);

static subhandler_fn_t* lookup_subhandler(uint8_t p1)
{
	switch (p1) {
#define  CASE(P1, HANDLER) case P1: return HANDLER;
#define  DEFAULT(HANDLER)  default: return HANDLER;
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
		CASE(0x0c, signTx_handleScriptDataHashAPDU);
		CASE(0x0d, signTx_handleCollateralInputAPDU);
		CASE(0x0e, signTx_handleRequiredSignerAPDU);
		CASE(0x12, signTx_handleCollateralOutputAPDU); // TODO perhaps change the numbers for the newly added items?
		CASE(0x10, signTx_handleTotalCollateralAPDU);
		CASE(0x11, signTx_handleReferenceInputsAPDU);
		CASE(0x0a, signTx_handleConfirmAPDU);
		CASE(0x0f, signTx_handleWitnessAPDU);
		DEFAULT(NULL)
#undef   CASE
#undef   DEFAULT
	}
}

void signTx_handleAPDU(
        uint8_t p1,
        uint8_t p2,
        const uint8_t* wireDataBuffer,
        size_t wireDataSize,
        bool isNewCall
)
{
	TRACE("P1 = 0x%x, P2 = 0x%x, isNewCall = %d", p1, p2, isNewCall);
	ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);

	if (isNewCall) {
		explicit_bzero(ctx, SIZEOF(*ctx));
		ctx->stage = SIGN_STAGE_INIT;
	}

	// advance stage if a state sub-machine has finished
	checkForFinishedSubmachines();

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
	case SIGN_STAGE_BODY_SCRIPT_DATA_HASH:
	case SIGN_STAGE_BODY_COLLATERAL_INPUTS:
	case SIGN_STAGE_BODY_REQUIRED_SIGNERS:
	case SIGN_STAGE_BODY_COLLATERAL_OUTPUT:
	case SIGN_STAGE_BODY_COLLATERAL_OUTPUT_SUBMACHINE:
	case SIGN_STAGE_BODY_TOTAL_COLLATERAL:
	case SIGN_STAGE_BODY_REFERENCE_INPUTS: {
		explicit_bzero(&BODY_CTX->stageData, SIZEOF(BODY_CTX->stageData));
		break;
	}
	default:
		break;
	}

	subhandler_fn_t* subhandler = lookup_subhandler(p1);
	VALIDATE(subhandler != NULL, ERR_INVALID_REQUEST_PARAMETERS);
	subhandler(p2, wireDataBuffer, wireDataSize);
}

ins_sign_tx_aux_data_context_t* accessAuxDataContext()
{
	switch (ctx->stage) {

	case SIGN_STAGE_AUX_DATA:
	case SIGN_STAGE_AUX_DATA_GOVERNANCE_VOTING_REGISTRATION_SUBMACHINE:
		return &(ctx->txPartCtx.aux_data_ctx);

	default:
		#ifndef DEVEL
		ASSERT(false);
		#endif
		THROW(ERR_ASSERT);
	}
}

ins_sign_tx_body_context_t* accessBodyContext()
{
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
	case SIGN_STAGE_BODY_SCRIPT_DATA_HASH:
	case SIGN_STAGE_BODY_COLLATERAL_INPUTS:
	case SIGN_STAGE_BODY_REQUIRED_SIGNERS:
	case SIGN_STAGE_BODY_COLLATERAL_OUTPUT:
	case SIGN_STAGE_BODY_COLLATERAL_OUTPUT_SUBMACHINE:
	case SIGN_STAGE_BODY_TOTAL_COLLATERAL:
	case SIGN_STAGE_BODY_REFERENCE_INPUTS:
	case SIGN_STAGE_CONFIRM:
		return &(ctx->txPartCtx.body_ctx);

	default:
		#ifndef DEVEL
		ASSERT(false);
		#endif
		THROW(ERR_ASSERT);
	}
}

ins_sign_tx_witness_context_t* accessWitnessContext()
{
	switch (ctx->stage) {

	case SIGN_STAGE_WITNESSES:
		return &(ctx->txPartCtx.witnesses_ctx);

	default:
		#ifndef DEVEL
		ASSERT(false);
		#endif
		THROW(ERR_ASSERT);
	}
}
