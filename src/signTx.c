#include "signTx.h"
#include "state.h"
#include "cardano.h"
#include "addressUtilsByron.h"
#include "addressUtilsShelley.h"
#include "uiHelpers.h"
#include "signTxUtils.h"
#include "uiScreens.h"
#include "txHashBuilder.h"
#include "textUtils.h"
#include "hexUtils.h"
#include "messageSigning.h"
#include "bufView.h"
#include "securityPolicy.h"

enum {
	SIGN_TX_OUTPUT_TYPE_ADDRESS = 1,
	SIGN_TX_OUTPUT_TYPE_ADDRESS_PARAMS = 2,
};

enum {
	SIGN_TX_METADATA_NO = 1,
	SIGN_TX_METADATA_YES = 2
};

static ins_sign_tx_context_t* ctx = &(instructionState.signTxContext);

static inline void CHECK_STAGE(sign_tx_stage_t expected)
{
	TRACE("Checking stage... current one is %d, expected %d", ctx->stage, expected);
	VALIDATE(ctx->stage == expected, ERR_INVALID_STATE);
}

static inline void advanceStage()
{
	TRACE("Advancing sign tx stage from: %d", ctx->stage);

	switch (ctx->stage) {

	case SIGN_STAGE_INIT:
		txHashBuilder_enterInputs(&ctx->txHashBuilder);
		ctx->stage = SIGN_STAGE_INPUTS;
		break;

	case SIGN_STAGE_INPUTS:
		// we should have received all inputs
		ASSERT(ctx->currentInput == ctx->numInputs);
		txHashBuilder_enterOutputs(&ctx->txHashBuilder);
		ctx->stage = SIGN_STAGE_OUTPUTS;
		break;

	case SIGN_STAGE_OUTPUTS:
		// we should have received all outputs
		ASSERT(ctx->currentOutput == ctx->numOutputs);
		ctx->stage = SIGN_STAGE_FEE;
		break;

	case SIGN_STAGE_FEE:
		// check if fee was received (initially LOVELACE_MAX_SUPPLY + 1)
		ASSERT(ctx->fee < LOVELACE_MAX_SUPPLY);
		ctx->stage = SIGN_STAGE_TTL;
		break;

	case SIGN_STAGE_TTL:
		// check if ttl was received
		ASSERT(ctx->ttl > 0);

		ctx->stage = SIGN_STAGE_CERTIFICATES;
		if (ctx->numCertificates > 0) {
			txHashBuilder_enterCertificates(&ctx->txHashBuilder);
			break;
		}

	// intentional fallthrough

	case SIGN_STAGE_CERTIFICATES:
		// we should have received all certificates
		ASSERT(ctx->currentCertificate == ctx->numCertificates);

		ctx->stage = SIGN_STAGE_WITHDRAWALS;

		if (ctx->numWithdrawals > 0) {
			txHashBuilder_enterWithdrawals(&ctx->txHashBuilder);
			break;
		}

	// intentional fallthough

	case SIGN_STAGE_WITHDRAWALS:
		// we should have received all withdrawals
		ASSERT(ctx->currentWithdrawal == ctx->numWithdrawals);

		ctx->stage = SIGN_STAGE_METADATA;

		if (ctx->includeMetadata) {
			break;
		}

	// intentional fallthrough

	case SIGN_STAGE_METADATA:
		ctx->stage = SIGN_STAGE_CONFIRM;
		break;

	case SIGN_STAGE_CONFIRM:
		ctx->stage = SIGN_STAGE_WITNESSES;
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
	ui_callback_fn_t* this_fn = signTx_handleInit_ui_runStep;

	UI_STEP_BEGIN(ctx->ui_step);
	UI_STEP(HANDLE_INIT_STEP_DISPLAY_DETAILS) {
		ui_displayNetworkParamsScreen(
		        "New transaction",
		        ctx->networkId, ctx->protocolMagic,
		        this_fn
		);
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

static void signTx_handleInitAPDU(uint8_t p2, uint8_t* wireDataBuffer, size_t wireDataSize)
{
	{
		// sanity checks
		CHECK_STAGE(SIGN_STAGE_INIT);

		VALIDATE(p2 == P2_UNUSED, ERR_INVALID_REQUEST_PARAMETERS);
		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}

	{
		// initialization

		ctx->fee = LOVELACE_MAX_SUPPLY + 1;
		ctx->ttl = 0; // ttl is absolute slot, so 0 is supposed to be invalid for our purpose

		ctx->currentInput = 0;
		ctx->currentOutput = 0;
		ctx->currentCertificate = 0;
		ctx->currentWithdrawal = 0;
		ctx->currentWitness = 0;
	}

	{
		// parse data

		TRACE_BUFFER(wireDataBuffer, wireDataSize);

		struct {
			uint8_t networkId;
			uint8_t protocolMagic[4];

			uint8_t includeMetadata;

			uint8_t numInputs[4];
			uint8_t numOutputs[4];
			uint8_t numCertificates[4];
			uint8_t numWithdrawals[4];
			uint8_t numWitnesses[4];
		}* wireHeader = (void*) wireDataBuffer;

		VALIDATE(SIZEOF(*wireHeader) == wireDataSize, ERR_INVALID_DATA);

		ASSERT_TYPE(ctx->networkId, uint8_t);
		ctx->networkId = wireHeader->networkId;
		TRACE("network id %d", ctx->networkId);
		VALIDATE(isValidNetworkId(ctx->networkId), ERR_INVALID_DATA);

		ASSERT_TYPE(ctx->protocolMagic, uint32_t);
		ctx->protocolMagic = u4be_read(wireHeader->protocolMagic);
		TRACE("protocol magic %d", ctx->protocolMagic);

		switch (wireHeader->includeMetadata) {
		case SIGN_TX_METADATA_YES:
			ctx->includeMetadata = true;
			break;

		case SIGN_TX_METADATA_NO:
			ctx->includeMetadata = false;
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
		VALIDATE(ctx->numInputs < SIGN_MAX_INPUTS, ERR_INVALID_DATA);
		VALIDATE(ctx->numOutputs < SIGN_MAX_OUTPUTS, ERR_INVALID_DATA);
		VALIDATE(ctx->numCertificates < SIGN_MAX_CERTIFICATES, ERR_INVALID_DATA);
		VALIDATE(ctx->numWithdrawals < SIGN_MAX_REWARD_WITHDRAWALS, ERR_INVALID_DATA);

		// Current code design assumes at least one input and at least one output.
		// If this is to be relaxed, stage switching logic needs to be re-visited.
		// An input is needed for certificate replay protection (enforced by node).
		// An output is needed to make sure the tx is signed for the correct
		// network id and cannot be used on a different network by an adversary.
		VALIDATE(ctx->numInputs > 0, ERR_INVALID_DATA);
		VALIDATE(ctx->numOutputs > 0, ERR_INVALID_DATA);

		// Note(ppershing): do not allow more witnesses than necessary.
		// This tries to lessen potential pubkey privacy leaks because
		// in WITNESS stage we do not verify whether the witness belongs
		// to a given utxo.
		const size_t maxNumWitnesses = (size_t) ctx->numInputs +
		                               (size_t) ctx->numCertificates +
		                               (size_t) ctx->numWithdrawals;
		VALIDATE(ctx->numWitnesses <= maxNumWitnesses, ERR_INVALID_DATA);
	}

	// Note: make sure that everything in ctx is initialized properly
	txHashBuilder_init(
	        &ctx->txHashBuilder,
	        ctx->numInputs,
	        ctx->numOutputs,
	        ctx->numCertificates,
	        ctx->numWithdrawals,
	        ctx->includeMetadata
	);

	security_policy_t policy = policyForSignTxInit(ctx->networkId, ctx->protocolMagic);

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


// ============================== INPUTS ==============================

enum {
	HANDLE_INPUT_STEP_RESPOND = 200,
	HANDLE_INPUT_STEP_INVALID,
};

static void signTx_handleInput_ui_runStep()
{
	TRACE("UI step %d", ctx->ui_step);

	UI_STEP_BEGIN(ctx->ui_step);

	UI_STEP(HANDLE_INPUT_STEP_RESPOND) {
		respondSuccessEmptyMsg();

		// Advance state to next input
		ctx->currentInput++;
		if (ctx->currentInput == ctx->numInputs) {
			advanceStage();
		}
	}
	UI_STEP_END(HANDLE_INPUT_STEP_INVALID);
}

static void signTx_handleInputAPDU(uint8_t p2, uint8_t* wireDataBuffer, size_t wireDataSize)
{
	{
		// sanity checks
		CHECK_STAGE(SIGN_STAGE_INPUTS);
		ASSERT(ctx->currentInput < ctx->numInputs);

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

		os_memmove(input.txHashBuffer, wireUtxo->txHash, SIZEOF(input.txHashBuffer));
		input.parsedIndex =  u4be_read(wireUtxo->index);
	}

	{
		// add to tx
		TRACE("Adding input to tx hash");
		txHashBuilder_addInput(
		        &ctx->txHashBuilder,
		        input.txHashBuffer, SIZEOF(input.txHashBuffer),
		        input.parsedIndex
		);
	}

	security_policy_t policy = policyForSignTxInput();

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

enum {
	HANDLE_OUTPUT_ADDRESS_STEP_DISPLAY_AMOUNT = 300,
	HANDLE_OUTPUT_ADDRESS_STEP_DISPLAY_ADDRESS,
	HANDLE_OUTPUT_ADDRESS_STEP_RESPOND,
	HANDLE_OUTPUT_ADDRESS_STEP_INVALID,
};

static void signTx_handleOutput_address_ui_runStep()
{
	TRACE("UI step %d", ctx->ui_step);
	ui_callback_fn_t* this_fn = signTx_handleOutput_address_ui_runStep;

	UI_STEP_BEGIN(ctx->ui_step);

	UI_STEP(HANDLE_OUTPUT_ADDRESS_STEP_DISPLAY_AMOUNT) {
		ui_displayAmountScreen("Send ADA", ctx->stageData.output.amount, this_fn);
	}
	UI_STEP(HANDLE_OUTPUT_ADDRESS_STEP_DISPLAY_ADDRESS) {
		ASSERT(ctx->stageData.output.addressSize <= SIZEOF(ctx->stageData.output.addressBuffer));
		ui_displayAddressScreen(
		        "To address",
		        ctx->stageData.output.addressBuffer,
		        ctx->stageData.output.addressSize,
		        this_fn
		);
	}
	UI_STEP(HANDLE_OUTPUT_ADDRESS_STEP_RESPOND) {
		respondSuccessEmptyMsg();

		// Advance state to next output
		ctx->currentOutput++;
		if (ctx->currentOutput == ctx->numOutputs) {
			advanceStage();
		}
	}
	UI_STEP_END(HANDLE_OUTPUT_ADDRESS_STEP_INVALID);
}

static void signTx_handleOutput_address()
{
	ASSERT(ctx->stageData.output.outputType == SIGN_TX_OUTPUT_TYPE_ADDRESS);

	security_policy_t policy = policyForSignTxOutputAddress(
	                                   ctx->stageData.output.addressBuffer, ctx->stageData.output.addressSize,
	                                   ctx->networkId, ctx->protocolMagic
	                           );
	TRACE("Policy: %d", (int) policy);
	ENSURE_NOT_DENIED(policy);

	{
		// add to tx
		ASSERT(ctx->stageData.output.addressSize > 0);
		ASSERT(ctx->stageData.output.addressSize < BUFFER_SIZE_PARANOIA);

		txHashBuilder_addOutput(
		        &ctx->txHashBuilder,
		        ctx->stageData.output.addressBuffer,
		        ctx->stageData.output.addressSize,
		        ctx->stageData.output.amount
		);
	}

	{
		// select UI steps
		switch (policy) {
#	define  CASE(POLICY, UI_STEP) case POLICY: {ctx->ui_step=UI_STEP; break;}
			CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_OUTPUT_ADDRESS_STEP_DISPLAY_AMOUNT);
			CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_OUTPUT_ADDRESS_STEP_RESPOND);
#	undef   CASE
		default:
			THROW(ERR_NOT_IMPLEMENTED);
		}
	}
	signTx_handleOutput_address_ui_runStep();
}

enum {
	HANDLE_OUTPUT_ADDRESSPARAMS_STEP_DISPLAY_AMOUNT = 350,
	HANDLE_OUTPUT_ADDRESSPARAMS_STEP_DISPLAY_SPENDING_PATH,
	HANDLE_OUTPUT_ADDRESSPARAMS_STEP_DISPLAY_STAKING_INFO,
	HANDLE_OUTPUT_ADDRESSPARAMS_STEP_RESPOND,
	HANDLE_OUTPUT_ADDRESSPARAMS_STEP_INVALID,
};

static void signTx_handleOutput_addressParams_ui_runStep()
{
	TRACE("UI step %d", ctx->ui_step);
	ui_callback_fn_t* this_fn = signTx_handleOutput_addressParams_ui_runStep;

	UI_STEP_BEGIN(ctx->ui_step);

	UI_STEP(HANDLE_OUTPUT_ADDRESSPARAMS_STEP_DISPLAY_AMOUNT) {
		ui_displayAmountScreen("Send ADA", ctx->stageData.output.amount, this_fn);
	}
	UI_STEP(HANDLE_OUTPUT_ADDRESSPARAMS_STEP_DISPLAY_SPENDING_PATH) {
		ui_displayPathScreen("To address", &ctx->stageData.output.params.spendingKeyPath, this_fn);
	}
	UI_STEP(HANDLE_OUTPUT_ADDRESSPARAMS_STEP_DISPLAY_STAKING_INFO) {
		ui_displayStakingInfoScreen(&ctx->stageData.output.params, this_fn);
	}
	UI_STEP(HANDLE_OUTPUT_ADDRESSPARAMS_STEP_RESPOND) {
		respondSuccessEmptyMsg();

		// Advance state to next output
		ctx->currentOutput++;
		if (ctx->currentOutput == ctx->numOutputs) {
			advanceStage();
		}
	}
	UI_STEP_END(HANDLE_OUTPUT_ADDRESSPARAMS_STEP_INVALID);
}

static void signTx_handleOutput_addressParams()
{
	ASSERT(ctx->stageData.output.outputType == SIGN_TX_OUTPUT_TYPE_ADDRESS_PARAMS);

	security_policy_t policy = policyForSignTxOutputAddressParams(
	                                   &ctx->stageData.output.params,
	                                   ctx->networkId, ctx->protocolMagic
	                           );
	TRACE("Policy: %d", (int) policy);
	ENSURE_NOT_DENIED(policy);

	{
		// add to tx
		ctx->stageData.output.addressSize = deriveAddress(
		        &ctx->stageData.output.params,
		        ctx->stageData.output.addressBuffer,
		        SIZEOF(ctx->stageData.output.addressBuffer)
		                                    );
		ASSERT(ctx->stageData.output.addressSize > 0);
		ASSERT(ctx->stageData.output.addressSize < BUFFER_SIZE_PARANOIA);

		txHashBuilder_addOutput(
		        &ctx->txHashBuilder,
		        ctx->stageData.output.addressBuffer,
		        ctx->stageData.output.addressSize,
		        ctx->stageData.output.amount
		);
	}

	{
		// select UI steps
		switch (policy) {
#	define  CASE(POLICY, UI_STEP) case POLICY: {ctx->ui_step=UI_STEP; break;}
			CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_OUTPUT_ADDRESSPARAMS_STEP_DISPLAY_AMOUNT);
			CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_OUTPUT_ADDRESSPARAMS_STEP_RESPOND);
#	undef   CASE
		default:
			THROW(ERR_NOT_IMPLEMENTED);
		}
	}
	signTx_handleOutput_addressParams_ui_runStep();
}

static void signTx_handleOutputAPDU(uint8_t p2, uint8_t* wireDataBuffer, size_t wireDataSize)
{
	{
		// safety checks
		CHECK_STAGE(SIGN_STAGE_OUTPUTS);
		ASSERT(ctx->currentOutput < ctx->numOutputs);

		VALIDATE(p2 == P2_UNUSED, ERR_INVALID_REQUEST_PARAMETERS);
		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}

	explicit_bzero(&ctx->stageData.output, SIZEOF(ctx->stageData.output));

	{
		// parse all APDU data and call an appropriate handler depending on output type
		TRACE_BUFFER(wireDataBuffer, wireDataSize);

		read_view_t view = make_read_view(wireDataBuffer, wireDataBuffer + wireDataSize);

		// read data preamble
		VALIDATE(view_remainingSize(&view) >= 8, ERR_INVALID_DATA);
		uint64_t amount = parse_u8be(&view);
		ctx->stageData.output.amount = amount;
		TRACE("Amount: %u.%06u", (unsigned) (amount / 1000000), (unsigned)(amount % 1000000));

		VALIDATE(view_remainingSize(&view) >= 1, ERR_INVALID_DATA);
		ctx->stageData.output.outputType = parse_u1be(&view);
		TRACE("Output type %d", (int) ctx->stageData.output.outputType);

		switch(ctx->stageData.output.outputType) {
		case SIGN_TX_OUTPUT_TYPE_ADDRESS: {
			// Rest of input is all address
			ASSERT(view_remainingSize(&view) <= SIZEOF(ctx->stageData.output.addressBuffer));
			ctx->stageData.output.addressSize = view_remainingSize(&view);
			os_memmove(ctx->stageData.output.addressBuffer, VIEW_REMAINING_TO_TUPLE_BUF_SIZE(&view));
			TRACE_BUFFER(ctx->stageData.output.addressBuffer, ctx->stageData.output.addressSize);
			signTx_handleOutput_address();
			break;
		}
		case SIGN_TX_OUTPUT_TYPE_ADDRESS_PARAMS: {
			parseAddressParams(VIEW_REMAINING_TO_TUPLE_BUF_SIZE(&view), &ctx->stageData.output.params);
			signTx_handleOutput_addressParams();
			break;
		}
		default:
			THROW(ERR_INVALID_DATA);
		};
	}
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

	TRACE("fee %d", ctx->fee);

	UI_STEP_BEGIN(ctx->ui_step);

	UI_STEP(HANDLE_FEE_STEP_DISPLAY) {
		ui_displayAmountScreen("Transaction fee", ctx->fee, this_fn);
	}
	UI_STEP(HANDLE_FEE_STEP_RESPOND) {
		respondSuccessEmptyMsg();
		advanceStage();
	}
	UI_STEP_END(HANDLE_FEE_STEP_INVALID);
}

static void signTx_handleFeeAPDU(uint8_t p2, uint8_t* wireDataBuffer, size_t wireDataSize)
{
	{
		// sanity checks
		CHECK_STAGE(SIGN_STAGE_FEE);

		VALIDATE(p2 == P2_UNUSED, ERR_INVALID_REQUEST_PARAMETERS);
		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}

	{
		// parse data
		TRACE_BUFFER(wireDataBuffer, wireDataSize);

		VALIDATE(wireDataSize == 8, ERR_INVALID_DATA);
		ctx->fee = u8be_read(wireDataBuffer);
	}

	{
		// add to tx
		TRACE("Adding fee to tx hash");
		txHashBuilder_addFee(&ctx->txHashBuilder, ctx->fee);
	}

	security_policy_t policy = policyForSignTxFee(ctx->fee);

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

	UI_STEP_BEGIN(ctx->ui_step);

	UI_STEP(HANDLE_TTL_STEP_DISPLAY) {
		char ttlString[50];
		str_formatTtl(ctx->ttl, ttlString, SIZEOF(ttlString));
		ui_displayPaginatedText(
		        "Transaction TTL",
		        ttlString,
		        this_fn
		);
	}
	UI_STEP(HANDLE_TTL_STEP_RESPOND) {
		respondSuccessEmptyMsg();
		advanceStage();
	}
	UI_STEP_END(HANDLE_TTL_STEP_INVALID);
}

static void signTx_handleTtlAPDU(uint8_t p2, uint8_t* wireDataBuffer, size_t wireDataSize)
{
	{
		// sanity checks
		CHECK_STAGE(SIGN_STAGE_TTL);

		VALIDATE(p2 == P2_UNUSED, ERR_INVALID_REQUEST_PARAMETERS);
		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}

	{
		// parse data
		TRACE_BUFFER(wireDataBuffer, wireDataSize);

		VALIDATE(wireDataSize == 8, ERR_INVALID_DATA);
		ctx->ttl = u8be_read(wireDataBuffer);
	}

	{
		// add to tx
		TRACE("Adding ttl to tx hash");
		txHashBuilder_addTtl(&ctx->txHashBuilder, ctx->ttl);
	}

	security_policy_t policy = policyForSignTxTtl(ctx->ttl);

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

	UI_STEP_BEGIN(ctx->ui_step);

	UI_STEP(HANDLE_CERTIFICATE_STEP_DISPLAY_OPERATION) {
		char title[50];
		explicit_bzero(title, SIZEOF(title));
		char details[200];
		explicit_bzero(details, SIZEOF(details));

		switch (ctx->stageData.certificate.type) {
		case CERTIFICATE_TYPE_STAKE_REGISTRATION:
			snprintf(title, SIZEOF(title), "Register");
			snprintf(details, SIZEOF(details), "staking key");
			break;

		case CERTIFICATE_TYPE_STAKE_DEREGISTRATION:
			snprintf(title, SIZEOF(title), "Deregister");
			snprintf(details, SIZEOF(details), "staking key");
			break;

		case CERTIFICATE_TYPE_STAKE_DELEGATION:
			snprintf(title, SIZEOF(title), "Delegate stake to pool");
			encode_hex(
			        ctx->stageData.certificate.poolKeyHash, SIZEOF(ctx->stageData.certificate.poolKeyHash),
			        details, SIZEOF(details)
			);
			break;

		default:
			ASSERT(false);
		}

		ui_displayPaginatedText(
		        title,
		        details,
		        this_fn
		);
	}
	UI_STEP(HANDLE_CERTIFICATE_STEP_DISPLAY_STAKING_KEY) {
		ui_displayPathScreen(
		        "Staking key",
		        &ctx->stageData.certificate.keyPath,
		        this_fn
		);
	}
	UI_STEP(HANDLE_CERTIFICATE_STEP_CONFIRM) {
		char description[50];
		explicit_bzero(description, SIZEOF(description));

		switch (ctx->stageData.certificate.type) {
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

		ui_displayPrompt(
		        "Confirm",
		        description,
		        this_fn,
		        respond_with_user_reject
		);
	}
	UI_STEP(HANDLE_CERTIFICATE_STEP_RESPOND) {
		respondSuccessEmptyMsg();

		// Advance state to next certificate
		ctx->currentCertificate++;
		if (ctx->currentCertificate == ctx->numCertificates) {
			advanceStage();
		}

	}
	UI_STEP_END(HANDLE_INPUT_STEP_INVALID);
}

static void _parseCertificateData(uint8_t* wireDataBuffer, size_t wireDataSize, sign_tx_certificate_data_t* certificateData)
{
	ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	TRACE_BUFFER(wireDataBuffer, wireDataSize);

	read_view_t view = make_read_view(wireDataBuffer, wireDataBuffer + wireDataSize);

	VALIDATE(view_remainingSize(&view) >= 1, ERR_INVALID_DATA);
	certificateData->type = parse_u1be(&view);
	TRACE("Certificate type: %d\n", certificateData->type);
	VALIDATE(
	        (certificateData->type == CERTIFICATE_TYPE_STAKE_REGISTRATION) ||
	        (certificateData->type == CERTIFICATE_TYPE_STAKE_DEREGISTRATION) ||
	        (certificateData->type == CERTIFICATE_TYPE_STAKE_DELEGATION),
	        ERR_INVALID_DATA
	);

	// staking key derivation path
	view_skipBytes(&view, bip44_parseFromWire(&certificateData->keyPath, VIEW_REMAINING_TO_TUPLE_BUF_SIZE(&view)));
	TRACE();
	BIP44_PRINTF(&certificateData->keyPath);

	TRACE("Remaining bytes: %d", view_remainingSize(&view));

	switch (certificateData->type) {

	case CERTIFICATE_TYPE_STAKE_REGISTRATION:
	case CERTIFICATE_TYPE_STAKE_DEREGISTRATION: {
		VALIDATE(view_remainingSize(&view) == 0, ERR_INVALID_DATA);

		break;
	}
	case CERTIFICATE_TYPE_STAKE_DELEGATION: {
		VALIDATE(view_remainingSize(&view) == POOL_KEY_HASH_LENGTH, ERR_INVALID_DATA);
		ASSERT(SIZEOF(certificateData->poolKeyHash) == POOL_KEY_HASH_LENGTH);
		os_memmove(certificateData->poolKeyHash, view.ptr, POOL_KEY_HASH_LENGTH);
		break;
	}
	default:
		THROW(ERR_INVALID_DATA);
	}
}

static void _addCertificateDataToTx(sign_tx_certificate_data_t* certificateData, tx_hash_builder_t* txHashBuilder)
{
	// compute staking key hash
	uint8_t stakingKeyHash[ADDRESS_KEY_HASH_LENGTH];
	{
		write_view_t stakingKeyHashView = make_write_view(stakingKeyHash, stakingKeyHash + SIZEOF(stakingKeyHash));
		size_t keyHashLength = view_appendPublicKeyHash(&stakingKeyHashView, &ctx->stageData.certificate.keyPath);
		ASSERT(keyHashLength == ADDRESS_KEY_HASH_LENGTH);
	}

	switch (ctx->stageData.certificate.type) {

	case CERTIFICATE_TYPE_STAKE_REGISTRATION:
	case CERTIFICATE_TYPE_STAKE_DEREGISTRATION: {
		TRACE("Adding certificate (type %d) to tx hash", certificateData->type);
		txHashBuilder_addCertificate_stakingKey(
		        txHashBuilder, certificateData->type,
		        stakingKeyHash, SIZEOF(stakingKeyHash));
		break;
	}
	case CERTIFICATE_TYPE_STAKE_DELEGATION: {
		TRACE("Adding delegation certificate to tx hash");
		txHashBuilder_addCertificate_delegation(
		        txHashBuilder,
		        stakingKeyHash, SIZEOF(stakingKeyHash),
		        certificateData->poolKeyHash, SIZEOF(certificateData->poolKeyHash)
		);
		break;
	}
	default:
		ASSERT(false);
	}
}

static void signTx_handleCertificateAPDU(uint8_t p2, uint8_t* wireDataBuffer, size_t wireDataSize)
{
	CHECK_STAGE(SIGN_STAGE_CERTIFICATES);
	ASSERT(ctx->currentCertificate < ctx->numCertificates);

	VALIDATE(p2 == P2_UNUSED, ERR_INVALID_REQUEST_PARAMETERS);

	explicit_bzero(&ctx->stageData.certificate, SIZEOF(ctx->stageData.certificate));

	_parseCertificateData(wireDataBuffer, wireDataSize, &ctx->stageData.certificate);

	security_policy_t policy = policyForSignTxCertificate(ctx->stageData.certificate.type, &ctx->stageData.certificate.keyPath);
	ENSURE_NOT_DENIED(policy);

	switch (policy) {
#	define  CASE(POLICY, UI_STEP) case POLICY: {ctx->ui_step=UI_STEP; break;}
		CASE(POLICY_PROMPT_BEFORE_RESPONSE, HANDLE_CERTIFICATE_STEP_DISPLAY_OPERATION);
		CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_CERTIFICATE_STEP_RESPOND);
#	undef   CASE
	default:
		THROW(ERR_NOT_IMPLEMENTED);
	}

	_addCertificateDataToTx(&ctx->stageData.certificate, &ctx->txHashBuilder);

	signTx_handleCertificate_ui_runStep();
}

// ============================== WITHDRAWALS ==============================

enum {
	HANDLE_WITHDRAWAL_STEP_DISPLAY = 700,
	HANDLE_WITHDRAWAL_STEP_RESPOND,
	HANDLE_WITHDRAWAL_STEP_INVALID,
};

static void signTx_handleWithdrawal_ui_runStep()
{
	TRACE("UI step %d", ctx->ui_step);
	ui_callback_fn_t* this_fn = signTx_handleWithdrawal_ui_runStep;

	UI_STEP_BEGIN(ctx->ui_step);

	UI_STEP(HANDLE_WITHDRAWAL_STEP_DISPLAY) {
		ui_displayAmountScreen("Withdrawing rewards", ctx->stageData.withdrawal.amount, this_fn);
	}
	UI_STEP(HANDLE_WITHDRAWAL_STEP_RESPOND) {
		respondSuccessEmptyMsg();

		// Advance state to next withdrawal
		ctx->currentWithdrawal++;
		if (ctx->currentWithdrawal == ctx->numWithdrawals) {
			advanceStage();
		}
	}
	UI_STEP_END(HANDLE_WITHDRAWAL_STEP_INVALID);
}

static void signTx_handleWithdrawalAPDU(uint8_t p2, uint8_t* wireDataBuffer, size_t wireDataSize)
{
	{
		// sanity checks
		CHECK_STAGE(SIGN_STAGE_WITHDRAWALS);
		ASSERT(ctx->currentWithdrawal < ctx->numWithdrawals);

		VALIDATE(p2 == P2_UNUSED, ERR_INVALID_REQUEST_PARAMETERS);
		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}

	explicit_bzero(&ctx->stageData.withdrawal, SIZEOF(ctx->stageData.withdrawal));

	{
		// parse input
		TRACE_BUFFER(wireDataBuffer, wireDataSize);

		read_view_t view = make_read_view(wireDataBuffer, wireDataBuffer + wireDataSize);
		VALIDATE(view_remainingSize(&view) >= 8, ERR_INVALID_DATA);
		ctx->stageData.withdrawal.amount = parse_u8be(&view);
		// the rest is path

		view_skipBytes(
		        &view,
		        bip44_parseFromWire(&ctx->stageData.withdrawal.path, VIEW_REMAINING_TO_TUPLE_BUF_SIZE(&view))
		);

		VALIDATE(view_remainingSize(&view) == 0, ERR_INVALID_DATA);

	}

	{
		uint8_t rewardAddress[1 + ADDRESS_KEY_HASH_LENGTH];
		{
			addressParams_t rewardAddressParams = {
				.type = REWARD,
				.networkId = ctx->networkId,
				.spendingKeyPath = ctx->stageData.withdrawal.path,
				.stakingChoice = NO_STAKING,
			};

			deriveAddress(
			        &rewardAddressParams,
			        rewardAddress,
			        SIZEOF(rewardAddress)
			);
		}

		TRACE("Adding withdrawal to tx hash");
		txHashBuilder_addWithdrawal(
		        &ctx->txHashBuilder,
		        rewardAddress, SIZEOF(rewardAddress),
		        ctx->stageData.withdrawal.amount
		);
	}

	security_policy_t policy = policyForSignTxWithdrawal();

	{
		// select UI steps
		switch (policy) {
#	define  CASE(POLICY, UI_STEP) case POLICY: {ctx->ui_step=UI_STEP; break;}
			CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_WITHDRAWAL_STEP_DISPLAY);
			CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_WITHDRAWAL_STEP_RESPOND);
#	undef   CASE
		default:
			THROW(ERR_NOT_IMPLEMENTED);
		}
	}

	signTx_handleWithdrawal_ui_runStep();
}

// ============================== METADATA ==============================

enum {
	HANDLE_METADATA_STEP_DISPLAY = 800,
	HANDLE_METADATA_STEP_RESPOND,
	HANDLE_METADATA_STEP_INVALID,
};

static void signTx_handleMetadata_ui_runStep()
{
	TRACE("UI step %d", ctx->ui_step);
	ui_callback_fn_t* this_fn = signTx_handleMetadata_ui_runStep;

	UI_STEP_BEGIN(ctx->ui_step);

	UI_STEP(HANDLE_METADATA_STEP_DISPLAY) {
		char metadataHashHex[1 + 2 * METADATA_HASH_LENGTH];
		size_t len = str_formatMetadata(
		                     ctx->stageData.metadata.metadataHash, SIZEOF(ctx->stageData.metadata.metadataHash),
		                     metadataHashHex, SIZEOF(metadataHashHex)
		             );
		ASSERT(len == SIZEOF(metadataHashHex));

		ui_displayPaginatedText(
		        "Transaction metadata",
		        metadataHashHex,
		        this_fn
		);
	}
	UI_STEP(HANDLE_METADATA_STEP_RESPOND) {
		respondSuccessEmptyMsg();
		advanceStage();
	}
	UI_STEP_END(HANDLE_METADATA_STEP_INVALID);
}

static void signTx_handleMetadataAPDU(uint8_t p2, uint8_t* wireDataBuffer, size_t wireDataSize)
{
	{
		// sanity checks
		CHECK_STAGE(SIGN_STAGE_METADATA);
		ASSERT(ctx->includeMetadata == true);

		VALIDATE(p2 == P2_UNUSED, ERR_INVALID_REQUEST_PARAMETERS);
		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}

	explicit_bzero(&ctx->stageData.metadata, SIZEOF(ctx->stageData.metadata));

	{
		// parse data
		TRACE_BUFFER(wireDataBuffer, wireDataSize);

		VALIDATE(wireDataSize == METADATA_HASH_LENGTH, ERR_INVALID_DATA);
		os_memmove(ctx->stageData.metadata.metadataHash, wireDataBuffer, SIZEOF(ctx->stageData.metadata.metadataHash));
	}

	security_policy_t policy = policyForSignTxMetadata();

	{
		// select UI step
		switch (policy) {
#	define  CASE(POLICY, UI_STEP) case POLICY: {ctx->ui_step=UI_STEP; break;}
			CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_METADATA_STEP_DISPLAY);
			CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_METADATA_STEP_RESPOND);
#	undef   CASE
		default:
			THROW(ERR_NOT_IMPLEMENTED);
		}
	}

	{
		// add metadata to tx
		TRACE("Adding metadata hash to tx hash");
		txHashBuilder_addMetadata(
		        &ctx->txHashBuilder,
		        ctx->stageData.metadata.metadataHash, SIZEOF(ctx->stageData.metadata.metadataHash)
		);
		TRACE();
	}

	signTx_handleMetadata_ui_runStep();
}

// ============================== CONFIRM ==============================

enum {
	HANDLE_CONFIRM_STEP_FINAL_CONFIRM = 900,
	HANDLE_CONFIRM_STEP_RESPOND,
	HANDLE_CONFIRM_STEP_INVALID,
};

static void signTx_handleConfirm_ui_runStep()
{
	TRACE("UI step %d", ctx->ui_step);
	ui_callback_fn_t* this_fn = signTx_handleConfirm_ui_runStep;

	UI_STEP_BEGIN(ctx->ui_step);

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

static void signTx_handleConfirmAPDU(uint8_t p2, uint8_t* wireDataBuffer MARK_UNUSED, size_t wireDataSize)
{
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
		        &ctx->txHashBuilder,
		        ctx->txHash, SIZEOF(ctx->txHash)
		);
	}

	security_policy_t policy = policyForSignTxConfirm();

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
	HANDLE_WITNESS_STEP_WARNING = 1000,
	HANDLE_WITNESS_STEP_DISPLAY,
	HANDLE_WITNESS_STEP_CONFIRM,
	HANDLE_WITNESS_STEP_RESPOND,
	HANDLE_WITNESS_STEP_INVALID,
};

static void signTx_handleWitness_ui_runStep()
{
	TRACE("UI step %d", ctx->ui_step);
	ui_callback_fn_t* this_fn = signTx_handleWitness_ui_runStep;

	UI_STEP_BEGIN(ctx->ui_step);

	UI_STEP(HANDLE_WITNESS_STEP_WARNING) {
		ui_displayPaginatedText(
		        "Warning!",
		        "Host asks for unusual witness",
		        this_fn
		);
	}
	UI_STEP(HANDLE_WITNESS_STEP_DISPLAY) {
		ui_displayPathScreen("Witness path", &ctx->stageData.witness.path, this_fn);
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
		TRACE_BUFFER(ctx->stageData.witness.signature, SIZEOF(ctx->stageData.witness.signature));
		io_send_buf(SUCCESS, ctx->stageData.witness.signature, SIZEOF(ctx->stageData.witness.signature));
		ui_displayBusy(); // needs to happen after I/O

		ctx->currentWitness++;
		if (ctx->currentWitness == ctx->numWitnesses) {
			advanceStage();
		}
	}
	UI_STEP_END(HANDLE_INPUT_STEP_INVALID);
}

static void signTx_handleWitnessAPDU(uint8_t p2, uint8_t* wireDataBuffer, size_t wireDataSize)
{
	{
		// sanity checks
		CHECK_STAGE(SIGN_STAGE_WITNESSES);
		VALIDATE(p2 == P2_UNUSED, ERR_INVALID_REQUEST_PARAMETERS);
		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);

		TRACE("Witness no. %d out of %d", ctx->currentWitness, ctx->numWitnesses);
		ASSERT(ctx->currentWitness < ctx->numWitnesses);
	}

	explicit_bzero(&ctx->stageData.witness, SIZEOF(ctx->stageData.witness));

	{
		// parse
		TRACE_BUFFER(wireDataBuffer, wireDataSize);

		size_t parsedSize = bip44_parseFromWire(&ctx->stageData.witness.path, wireDataBuffer, wireDataSize);
		VALIDATE(parsedSize == wireDataSize, ERR_INVALID_DATA);
	}

	security_policy_t policy = POLICY_DENY;

	{
		// get policy
		policy = policyForSignTxWitness(&ctx->stageData.witness.path);
		TRACE("policy %d", (int) policy);
		ENSURE_NOT_DENIED(policy);
	}

	{
		// compute witness
		TRACE("getTxWitness");
		TRACE("TX HASH");
		TRACE_BUFFER(ctx->txHash, SIZEOF(ctx->txHash));
		TRACE("END TX HASH");

		getTxWitness(
		        &ctx->stageData.witness.path,
		        ctx->txHash, SIZEOF(ctx->txHash),
		        ctx->stageData.witness.signature, SIZEOF(ctx->stageData.witness.signature)
		);
	}

	{
		// choose UI steps
		switch (policy) {
#	define  CASE(POLICY, UI_STEP) case POLICY: {ctx->ui_step=UI_STEP; break;}
			CASE(POLICY_PROMPT_WARN_UNUSUAL,  HANDLE_WITNESS_STEP_WARNING);
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
	switch(p1) {
#	define  CASE(P1, HANDLER) case P1: return HANDLER;
#	define  DEFAULT(HANDLER)  default: return HANDLER;
		CASE(0x01, signTx_handleInitAPDU);
		CASE(0x02, signTx_handleInputAPDU);
		CASE(0x03, signTx_handleOutputAPDU);
		CASE(0x04, signTx_handleFeeAPDU);
		CASE(0x05, signTx_handleTtlAPDU);
		CASE(0x06, signTx_handleCertificateAPDU);
		CASE(0x07, signTx_handleWithdrawalAPDU);
		CASE(0x08, signTx_handleMetadataAPDU);
		CASE(0x09, signTx_handleConfirmAPDU);
		CASE(0x0a, signTx_handleWitnessAPDU);
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
	if (isNewCall) {
		explicit_bzero(ctx, SIZEOF(*ctx));
		ctx->stage = SIGN_STAGE_INIT;
	}
	subhandler_fn_t* subhandler = lookup_subhandler(p1);
	VALIDATE(subhandler != NULL, ERR_INVALID_REQUEST_PARAMETERS);
	subhandler(p2, wireDataBuffer, wireDataSize);
}
