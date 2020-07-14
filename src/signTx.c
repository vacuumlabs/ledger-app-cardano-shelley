#include "common.h"
#include "signTx.h"
#include "cbor.h"
#include "state.h"
#include "cardano.h" // TODO revise & update
#include "keyDerivation.h"
#include "ux.h"
#include "endian.h"
#include "addressUtilsByron.h"
#include "addressUtilsShelley.h"
#include "uiHelpers.h"
#include "crc32.h"
#include "txHashBuilder.h"
#include "textUtils.h"
#include "base58.h"
#include "messageSigning.h"
#include "bip44.h"
#include "bufView.h"
#include "os.h"

enum {
	SIGN_TX_OUTPUT_TYPE_ADDRESS = 1,
	SIGN_TX_OUTPUT_TYPE_PATH = 2,
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
	switch (ctx->stage) {

	case SIGN_STAGE_INIT:
		txHashBuilder_enterInputs(&ctx->txHashBuilder, ctx->numInputs);
		ctx->stage = SIGN_STAGE_INPUTS;
		break;

	case SIGN_STAGE_INPUTS:
		// we should have received all inputs
		ASSERT(ctx->currentInput == ctx->numInputs);
		txHashBuilder_enterOutputs(&ctx->txHashBuilder, ctx->numOutputs);
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
		if (ctx->numCertificates > 0) {
			txHashBuilder_enterCertificates(&ctx->txHashBuilder, ctx->numCertificates);
			ctx->stage = SIGN_STAGE_CERTIFICATES;
		} else if (ctx->numWithdrawals > 0) {
			txHashBuilder_enterWithdrawals(&ctx->txHashBuilder, ctx->numWithdrawals);
			ctx->stage = SIGN_STAGE_WITHDRAWALS;
		} else if (ctx->includeMetadata) {
			ctx->stage = SIGN_STAGE_METADATA;
		} else {
			ctx->stage = SIGN_STAGE_CONFIRM;
		}
		break;

	case SIGN_STAGE_CERTIFICATES:
		// we should have received all certificates
		ASSERT(ctx->currentCertificate == ctx->numCertificates);
		if (ctx->numWithdrawals > 0) {
			txHashBuilder_enterWithdrawals(&ctx->txHashBuilder, ctx->numWithdrawals);
			ctx->stage = SIGN_STAGE_WITHDRAWALS;
		} else if (ctx->includeMetadata) {
			ctx->stage = SIGN_STAGE_METADATA;
		} else {
			ctx->stage = SIGN_STAGE_CONFIRM;
		}
		break;

	case SIGN_STAGE_WITHDRAWALS:
		// we should have received all withdrawals
		ASSERT(ctx->currentWithdrawal == ctx->numWithdrawals);
		if (ctx->includeMetadata) {
			ctx->stage = SIGN_STAGE_METADATA;
		} else {
			ctx->stage = SIGN_STAGE_CONFIRM;
		}
		break;

	case SIGN_STAGE_METADATA:
		ctx->stage = SIGN_STAGE_CONFIRM;
		break;

	case SIGN_STAGE_CONFIRM:
		ctx->stage = SIGN_STAGE_WITNESSES; // TODO?
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
}

void respondSuccessEmptyMsg()
{
	io_send_buf(SUCCESS, NULL, 0);
	ui_displayBusy(); // needs to happen after I/O
}


// ============================== INIT ==============================

enum {
	HANDLE_INIT_STEP_CONFIRM = 100,
	HANDLE_INIT_STEP_RESPOND,
	HANDLE_INIT_STEP_INVALID,
} ;

static void signTx_handleInit_ui_runStep()
{
	TRACE("Step %d", ctx->ui_step);
	ui_callback_fn_t* this_fn = signTx_handleInit_ui_runStep;
	int nextStep = HANDLE_INIT_STEP_INVALID;

	switch(ctx->ui_step) {
	case HANDLE_INIT_STEP_CONFIRM: {
		ui_displayPrompt(
		        "Start new",
		        "transaction?",
		        this_fn,
		        respond_with_user_reject
		);
		nextStep = HANDLE_INIT_STEP_RESPOND;
		break;
	}
	case HANDLE_INIT_STEP_RESPOND: {
		TRACE();
		advanceStage();
		respondSuccessEmptyMsg();
		nextStep = HANDLE_INIT_STEP_INVALID;
		break;
	}
	default:
		ASSERT(false);
	}
	ctx->ui_step = nextStep;
}

static void signTx_handleInitAPDU(uint8_t p2, uint8_t* wireDataBuffer, size_t wireDataSize)
{
	TRACE();

	CHECK_STAGE(SIGN_STAGE_INIT);
	TRACE();
	VALIDATE(p2 == 0, ERR_INVALID_REQUEST_PARAMETERS);
	TRACE();
	// Note: make sure that everything in ctx is initialized properly

	txHashBuilder_init(
		&ctx->txHashBuilder,
		ctx->numCertificates, ctx->numWithdrawals, ctx->includeMetadata
	);
	TRACE();

	ctx->fee = LOVELACE_MAX_SUPPLY + 1;
	ctx->ttl = 0; // ttl is absolute slot, so 0 is supposed to be invalid for our purpose

	ctx->currentInput = 0;
	ctx->currentOutput = 0;
	ctx->currentCertificate = 0;
	ctx->currentWithdrawal = 0;
	ctx->currentWitness = 0;

	TRACE();
	struct {
		uint8_t numInputs[4];
		uint8_t numOutputs[4];
		uint8_t numCertificates[4];
		uint8_t numWithdrawals[4];
		uint8_t numWitnesses[4];
		uint8_t includeMetadata;
	}* wireHeader = (void*) wireDataBuffer;

	VALIDATE(SIZEOF(*wireHeader) == wireDataSize, ERR_INVALID_DATA);

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

	VALIDATE(ctx->numInputs < SIGN_MAX_INPUTS, ERR_INVALID_DATA);
	VALIDATE(ctx->numOutputs < SIGN_MAX_OUTPUTS, ERR_INVALID_DATA);
	VALIDATE(ctx->numCertificates < SIGN_MAX_CERTIFICATES, ERR_INVALID_DATA);
	VALIDATE(ctx->numWithdrawals < SIGN_MAX_REWARD_WITHDRAWALS, ERR_INVALID_DATA);

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

	// TODO shorten this comment
	// Note(ppershing): current code design assumes at least one input
	// and at least one output. If this has to be relaxed, stage switching
	// logic needs to be re-visited
	// Note(janmazak): we need both to be at least one
	// an input is needed for certificate replay protection (enforced by full node)
	// an output is needed to make sure the tx is signed for the correct network id
	// and cannot be used on a different network by an adversary
	VALIDATE(ctx->numInputs > 0, ERR_INVALID_DATA);
	VALIDATE(ctx->numOutputs > 0, ERR_INVALID_DATA);

	// Note(ppershing): do not allow more witnesses than necessary. This
	// tries to lessen potential pubkey privacy leaks because
	// in WITNESS stage we do not verify whether the witness belongs
	// to a given utxo.
	VALIDATE(ctx->numWitnesses <= ctx->numInputs + ctx->numCertificates + ctx->numWithdrawals, ERR_INVALID_DATA);

	security_policy_t policy = policyForSignTxInit(); // TODO review policies
	switch (policy) {
#	define  CASE(POLICY, UI_STEP) case POLICY: {ctx->ui_step=UI_STEP; break;}
		CASE(POLICY_PROMPT_BEFORE_RESPONSE, HANDLE_INIT_STEP_CONFIRM);
		CASE(POLICY_ALLOW_WITHOUT_PROMPT,   HANDLE_INIT_STEP_RESPOND);
#	undef   CASE
	default:
		THROW(ERR_NOT_IMPLEMENTED);
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
	TRACE("step %d", ctx->ui_step);

	UI_STEP_BEGIN(ctx->ui_step);

	UI_STEP(HANDLE_INPUT_STEP_RESPOND) {
		// Advance state to next input
		ctx->currentInput++;
		if (ctx->currentInput == ctx->numInputs)
			advanceStage();

		respondSuccessEmptyMsg();
	}
	UI_STEP_END(HANDLE_INPUT_STEP_INVALID);
}

static void signTx_handleInputAPDU(uint8_t p2, uint8_t* wireDataBuffer, size_t wireDataSize)
{
	TRACE();
	ASSERT(ctx->currentInput < ctx->numInputs);
	CHECK_STAGE(SIGN_STAGE_INPUTS);

	VALIDATE(p2 == 0, ERR_INVALID_REQUEST_PARAMETERS);

	struct {
		uint8_t txHash[32]; // TODO named constant?
		uint8_t index[4];
	}* wireUtxo = (void*) wireDataBuffer;

	VALIDATE(wireDataSize == SIZEOF(*wireUtxo), ERR_INVALID_DATA);

	uint8_t* txHashBuffer = wireUtxo->txHash;
	size_t txHashSize = SIZEOF(wireUtxo->txHash);
	uint32_t parsedIndex = u4be_read(wireUtxo->index);

	TRACE("Adding input to tx hash");
	txHashBuilder_addInput(&ctx->txHashBuilder, txHashBuffer, txHashSize, parsedIndex);

	security_policy_t policy = policyForSignTxInput();

	switch (policy) {
#	define  CASE(POLICY, UI_STEP) case POLICY: {ctx->ui_step=UI_STEP; break;}
		CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_INPUT_STEP_RESPOND);
#	undef   CASE
	default:
		THROW(ERR_NOT_IMPLEMENTED);
	}
	signTx_handleInput_ui_runStep();
}


// ============================== OUTPUTS ==============================

enum {
	HANDLE_OUTPUT_STEP_DISPLAY_AMOUNT = 300,
	HANDLE_OUTPUT_STEP_DISPLAY_ADDRESS,
	HANDLE_OUTPUT_STEP_RESPOND,
	HANDLE_OUTPUT_STEP_INVALID,
};

static void signTx_handleOutput_ui_runStep()
{
	TRACE("step %d", ctx->ui_step);
	ui_callback_fn_t* this_fn = signTx_handleOutput_ui_runStep;

	UI_STEP_BEGIN(ctx->ui_step);

	UI_STEP(HANDLE_OUTPUT_STEP_DISPLAY_AMOUNT) {
		char adaAmountStr[50];
		str_formatAdaAmount( ctx->currentAmount, adaAmountStr, SIZEOF(adaAmountStr));
		ui_displayPaginatedText(
		        "Send ADA",
		        adaAmountStr,
		        this_fn
		);
	}
	UI_STEP(HANDLE_OUTPUT_STEP_DISPLAY_ADDRESS) {
		char addressStr[200];
		ASSERT(ctx->currentAddress.size <= SIZEOF(ctx->currentAddress.buffer));
		humanReadableAddress(
		        ctx->currentAddress.buffer,
		        ctx->currentAddress.size,
		        addressStr,
		        SIZEOF(addressStr)
		);

		ui_displayPaginatedText(
		        "To address",
		        addressStr,
		        this_fn
		);
	}
	UI_STEP(HANDLE_OUTPUT_STEP_RESPOND) {
		// Advance state to next output
		ctx->currentOutput++;
		if (ctx->currentOutput == ctx->numOutputs)
			advanceStage();

		respondSuccessEmptyMsg();
	}
	UI_STEP_END(HANDLE_OUTPUT_STEP_INVALID);
}

static void signTx_handleOutputAPDU(uint8_t p2, uint8_t* wireDataBuffer, size_t wireDataSize)
{
	TRACE();
	ASSERT(ctx->currentOutput < ctx->numOutputs);
	CHECK_STAGE(SIGN_STAGE_OUTPUTS);
	ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);

	VALIDATE(p2 == 0, ERR_INVALID_REQUEST_PARAMETERS);

	read_view_t view = make_read_view(wireDataBuffer, wireDataBuffer + wireDataSize);

	// Read data preamble
	uint64_t amount = parse_u8be(&view);
	ctx->currentAmount = amount;
	TRACE("Amount: %u.%06u", (unsigned) (amount / 1000000), (unsigned)(amount % 1000000));

	uint8_t outputType = parse_u1be(&view);
	TRACE("Output type %d", (int) outputType);

	security_policy_t policy;

	switch(outputType) {
	case SIGN_TX_OUTPUT_TYPE_ADDRESS: {
		// Rest of input is all address
		ASSERT(view_remainingSize(&view) <= SIZEOF(ctx->currentAddress.buffer));
		ctx->currentAddress.size = view_remainingSize(&view);
		os_memcpy(ctx->currentAddress.buffer, VIEW_REMAINING_TO_TUPLE_BUF_SIZE(&view));

		policy =  policyForSignTxOutputAddress(ctx->currentAddress.buffer, ctx->currentAddress.size);
		TRACE("Policy: %d", (int) policy);
		ENSURE_NOT_DENIED(policy);
		break;
	}
	case SIGN_TX_OUTPUT_TYPE_PATH: { // TODO rename the label?
		parseAddressParams(VIEW_REMAINING_TO_TUPLE_BUF_SIZE(&view), &ctx->currentAddressParams);

		// policy = policyForSignTxOutputAddressParams(&ctx->currentAddressParams);
		// TRACE("Policy: %d", (int) policy);
		// ENSURE_NOT_DENIED(policy);

		ctx->currentAddress.size = deriveAddress_shelley(&ctx->currentAddressParams, ctx->currentAddress.buffer, SIZEOF(ctx->currentAddress.buffer));
		break;
	}
	default:
		THROW(ERR_INVALID_DATA);
	};

	ASSERT(ctx->currentAddress.size > 0);
	ASSERT(ctx->currentAddress.size < BUFFER_SIZE_PARANOIA);

	txHashBuilder_addOutput(
	        &ctx->txHashBuilder,
	        ctx->currentAddress.buffer,
	        ctx->currentAddress.size,
	        ctx->currentAmount
	);

#	define  CASE(POLICY, UI_STEP) case POLICY: {ctx->ui_step=UI_STEP; break;}
#	define  DEFAULT(ERR) default: { THROW(ERR); }
	switch (policy) {
		CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_OUTPUT_STEP_DISPLAY_AMOUNT);
		CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_OUTPUT_STEP_RESPOND);
		DEFAULT(ERR_NOT_IMPLEMENTED)
	}
#	undef   CASE
#	undef   DEFAULT

	signTx_handleOutput_ui_runStep();
}

// ============================== FEE ==============================

enum {
	HANDLE_FEE_STEP_DISPLAY = 400,
	HANDLE_FEE_STEP_RESPOND,
	HANDLE_FEE_STEP_INVALID,
};

static void signTx_handleFee_ui_runStep()
{
	TRACE("step %d", ctx->ui_step);
	ui_callback_fn_t* this_fn = signTx_handleFee_ui_runStep;

	TRACE("fee %d", ctx->fee);

	UI_STEP_BEGIN(ctx->ui_step);

	UI_STEP(HANDLE_FEE_STEP_DISPLAY) {
		char adaAmount[50];
		str_formatAdaAmount(ctx->fee, adaAmount, SIZEOF(adaAmount));
		ui_displayPaginatedText(
		        "Transaction fee",
		        adaAmount,
		        this_fn
		);
	}
	UI_STEP(HANDLE_FEE_STEP_RESPOND) {
		advanceStage();
		respondSuccessEmptyMsg();
	}
	UI_STEP_END(HANDLE_FEE_STEP_INVALID);
}

static void signTx_handleFeeAPDU(uint8_t p2, uint8_t* wireDataBuffer, size_t wireDataSize)
{
	TRACE();
	CHECK_STAGE(SIGN_STAGE_FEE);

	VALIDATE(p2 == 0, ERR_INVALID_REQUEST_PARAMETERS);

	struct {
		uint8_t fee[8];
	}* wireUtxo = (void*) wireDataBuffer;

	VALIDATE(wireDataSize == SIZEOF(*wireUtxo), ERR_INVALID_DATA);

	uint64_t parsedFee = u8be_read(wireUtxo->fee);
	ctx->fee = parsedFee;

	TRACE("Adding fee to tx hash");
	txHashBuilder_addFee(&ctx->txHashBuilder, parsedFee);
	TRACE();

	security_policy_t policy = policyForSignTxFee(parsedFee);

	TRACE();
	switch (policy) {
#	define  CASE(POLICY, UI_STEP) case POLICY: {ctx->ui_step=UI_STEP; break;}
		CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_FEE_STEP_RESPOND); // TODO show tx fee instead
		CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_FEE_STEP_RESPOND);
#	undef   CASE
	default:
		THROW(ERR_NOT_IMPLEMENTED);
	}
	TRACE();
	signTx_handleFee_ui_runStep();
	TRACE();
}


// ============================== TTL ==============================

enum {
	HANDLE_TTL_STEP_DISPLAY = 500,
	HANDLE_TTL_STEP_RESPOND,
	HANDLE_TTL_STEP_INVALID,
};

static void signTx_handleTtl_ui_runStep()
{
	TRACE("step %d", ctx->ui_step);
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
		advanceStage();
		respondSuccessEmptyMsg();
	}
	UI_STEP_END(HANDLE_TTL_STEP_INVALID);
}

static void signTx_handleTtlAPDU(uint8_t p2, uint8_t* wireDataBuffer, size_t wireDataSize)
{
	TRACE();
	CHECK_STAGE(SIGN_STAGE_TTL);

	VALIDATE(p2 == 0, ERR_INVALID_REQUEST_PARAMETERS);

	struct {
		uint8_t ttl[8];
	}* wireUtxo = (void*) wireDataBuffer;

	VALIDATE(wireDataSize == SIZEOF(*wireUtxo), ERR_INVALID_DATA);

	uint64_t parsedTtl = u8be_read(wireUtxo->ttl);
	ctx->ttl = parsedTtl;

	TRACE("Adding ttl to tx hash");
	txHashBuilder_addTtl(&ctx->txHashBuilder, parsedTtl);

	// TODO the policy should require that ttl is not 0, such txs are invalid and we use 0 for checking when advancing to the next stage
	security_policy_t policy = policyForSignTxTtl(parsedTtl);

	switch (policy) {
#	define  CASE(POLICY, UI_STEP) case POLICY: {ctx->ui_step=UI_STEP; break;}
		CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_TTL_STEP_RESPOND); // TODO show ttl instead
		CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_TTL_STEP_RESPOND);
#	undef   CASE
	default:
		THROW(ERR_NOT_IMPLEMENTED);
	}
	signTx_handleTtl_ui_runStep();
}


// ============================== CERTIFICATES ==============================

enum {
	HANDLE_CERTIFICATE_STEP_DISPLAY = 600,
	HANDLE_CERTIFICATE_STEP_RESPOND,
	HANDLE_CERTIFICATE_STEP_INVALID,
};

static void signTx_handleCertificate_ui_runStep()
{
	TRACE("step %d", ctx->ui_step);
	ui_callback_fn_t* this_fn = signTx_handleOutput_ui_runStep;

	UI_STEP_BEGIN(ctx->ui_step);

	UI_STEP(HANDLE_CERTIFICATE_STEP_DISPLAY) {
		ui_displayPaginatedText(
		        "Certificate",
		        "...", // TODO
		        this_fn
		);
	}
	UI_STEP(HANDLE_CERTIFICATE_STEP_RESPOND) {
		// Advance state to next certificate
		ctx->currentCertificate++;
		if (ctx->currentCertificate == ctx->numCertificates)
			advanceStage();

		respondSuccessEmptyMsg();
	}
	UI_STEP_END(HANDLE_INPUT_STEP_INVALID);
}

static void signTx_handleCertificateAPDU(uint8_t p2, uint8_t* wireDataBuffer, size_t wireDataSize)
{
	TRACE();
	ASSERT(ctx->currentCertificate < ctx->numCertificates);
	CHECK_STAGE(SIGN_STAGE_CERTIFICATES);

	VALIDATE(p2 == 0, ERR_INVALID_REQUEST_PARAMETERS);

// TODO
// 	VALIDATE(wireDataSize >= 1, ERR_INVALID_DATA);

// 	struct {
// 		uint8_t txHash[32]; // TODO named constant?
// 		uint8_t index[4];
// 	}* wireUtxo = (void*) wireDataBuffer + 1;

// 	VALIDATE(wireDataSize == SIZEOF(*wireUtxo), ERR_INVALID_DATA);

// 	uint8_t* txHashBuffer = wireUtxo->txHash;
// 	size_t txHashSize = SIZEOF(wireUtxo->txHash);
// 	uint32_t parsedIndex = u4be_read(wireUtxo->index);

// 	TRACE("Adding input to tx hash");
// 	txHashBuilder_addInput(&ctx->txHashBuilder, txHashBuffer, txHashSize, parsedIndex);

// 	security_policy_t policy = policyForSignTxInput();

// 	switch (policy) {
// #	define  CASE(POLICY, UI_STEP) case POLICY: {ctx->ui_step=UI_STEP; break;}
// 		CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_INPUT_STEP_RESPOND);
// #	undef   CASE
// 	default:
// 		THROW(ERR_NOT_IMPLEMENTED);
// 	}

	signTx_handleCertificate_ui_runStep();
}

// ============================== WITHDRAWALS ==============================

enum {
	HANDLE_WITHDRAWAL_STEP_RESPOND = 700,
	HANDLE_WITHDRAWAL_STEP_INVALID,
};

static void signTx_handleWithdrawal_ui_runStep()
{
	TRACE("step %d", ctx->ui_step);

	UI_STEP_BEGIN(ctx->ui_step);

	UI_STEP(HANDLE_WITHDRAWAL_STEP_RESPOND) {
		// Advance state to next withdrawal
		ctx->currentWithdrawal++;
		if (ctx->currentWithdrawal == ctx->numWithdrawals)
			advanceStage();

		respondSuccessEmptyMsg();
	}
	UI_STEP_END(HANDLE_WITHDRAWAL_STEP_INVALID);
}

static void signTx_handleWithdrawalAPDU(uint8_t p2, uint8_t* wireDataBuffer, size_t wireDataSize)
{
	TRACE();
	ASSERT(ctx->currentWithdrawal < ctx->numWithdrawals);
	CHECK_STAGE(SIGN_STAGE_WITHDRAWALS);

	VALIDATE(p2 == 0, ERR_INVALID_REQUEST_PARAMETERS);

	read_view_t view = make_read_view(wireDataBuffer, wireDataBuffer + wireDataSize);
	VALIDATE(view_remainingSize(&view) > 8, ERR_INVALID_DATA);
	uint64_t amount = parse_u8be(&view);

	uint8_t rewardAccount[PUBLIC_KEY_HASH_LENGTH];  // TODO --- what exactly is reward account?
	{
		// the rest is path
		bip44_path_t path;
		view_skipBytes(&view, bip44_parseFromWire(&path, VIEW_REMAINING_TO_TUPLE_BUF_SIZE(&view)));
		VALIDATE(view_remainingSize(&view) == 0, ERR_INVALID_DATA);
		VALIDATE(bip44_isValidStakingKeyPath(&path), ERR_INVALID_DATA);
		{
			write_view_t out = make_write_view(rewardAccount, rewardAccount + SIZEOF(rewardAccount));
			view_appendPublicKeyHash(&out, &path);
		}
	}

	TRACE("Adding withdrawal to tx hash");
	txHashBuilder_addWithdrawal(&ctx->txHashBuilder, rewardAccount, SIZEOF(rewardAccount), amount);

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
	TRACE("step %d", ctx->ui_step);
	ui_callback_fn_t* this_fn = signTx_handleMetadata_ui_runStep;

	UI_STEP_BEGIN(ctx->ui_step);

	UI_STEP(HANDLE_METADATA_STEP_DISPLAY) {
		char metadataHashHex[100];
		str_formatMetadata(ctx->metadataHash, SIZEOF(ctx->metadataHash), metadataHashHex, SIZEOF(metadataHashHex));
		ui_displayPaginatedText(
		        "Transaction metadata",
		        metadataHashHex,
		        this_fn
		);
	}
	UI_STEP(HANDLE_METADATA_STEP_RESPOND) {
		advanceStage();
		respondSuccessEmptyMsg();
	}
	UI_STEP_END(HANDLE_METADATA_STEP_INVALID);
}

static void signTx_handleMetadataAPDU(uint8_t p2, uint8_t* wireDataBuffer, size_t wireDataSize)
{
	TRACE();
	ASSERT(ctx->includeMetadata == true);
	CHECK_STAGE(SIGN_STAGE_METADATA);

	VALIDATE(p2 == 0, ERR_INVALID_REQUEST_PARAMETERS);

	ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	VALIDATE(wireDataSize == METADATA_HASH_LENGTH, ERR_INVALID_DATA);
	os_memcpy(ctx->metadataHash, wireDataBuffer, METADATA_HASH_LENGTH);

	security_policy_t policy = policyForSignTxMetadata();

	switch (policy) {
#	    define  CASE(POLICY, UI_STEP) case POLICY: {ctx->ui_step=UI_STEP; break;}
		CASE(POLICY_PROMPT_BEFORE_RESPONSE, HANDLE_METADATA_STEP_DISPLAY);
		CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_METADATA_STEP_RESPOND);
#	    undef   CASE
	default:
		THROW(ERR_NOT_IMPLEMENTED);
	}

	TRACE("Adding metadata hash to tx hash");
	txHashBuilder_addMetadata(&ctx->txHashBuilder, ctx->metadataHash, SIZEOF(ctx->metadataHash));

	TRACE();

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
	TRACE("step %d", ctx->ui_step);
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
		advanceStage();

		// respond
		io_send_buf(SUCCESS, ctx->txHash, SIZEOF(ctx->txHash));
		ui_displayBusy();
	}
	UI_STEP_END(HANDLE_CONFIRM_STEP_INVALID);
}

static void signTx_handleConfirmAPDU(uint8_t p2, uint8_t* dataBuffer MARK_UNUSED, size_t dataSize)
{
	TRACE();
	VALIDATE(p2 == 0, ERR_INVALID_REQUEST_PARAMETERS);
	VALIDATE(dataSize == 0, ERR_INVALID_REQUEST_PARAMETERS);

	CHECK_STAGE(SIGN_STAGE_CONFIRM);

	TRACE();

	txHashBuilder_finalize(
	        &ctx->txHashBuilder,
	        ctx->txHash, SIZEOF(ctx->txHash)
	);

	TRACE();

	security_policy_t policy = policyForSignTxConfirm();

	TRACE();

#	define  CASE(POLICY, UI_STEP) case POLICY: {ctx->ui_step=UI_STEP; break;}
#	define  DEFAULT(ERR) default: { THROW(ERR); }
	switch (policy) {
		CASE(POLICY_PROMPT_BEFORE_RESPONSE, HANDLE_CONFIRM_STEP_FINAL_CONFIRM);
		CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_CONFIRM_STEP_RESPOND);
		DEFAULT(ERR_NOT_IMPLEMENTED);
	}
#	undef   CASE
#	undef   DEFAULT

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
	TRACE("step %d", ctx->ui_step);
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
		char pathStr[100];
		bip44_printToStr(&ctx->currentWitnessPath, pathStr, SIZEOF(pathStr));
		ui_displayPaginatedText(
		        "Witness path",
		        pathStr,
		        this_fn
		);
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
		TRACE("io_send_buf");
		io_send_buf(SUCCESS, ctx->currentWitnessData, SIZEOF(ctx->currentWitnessData));
		ui_displayBusy(); // needs to happen after I/O

		ctx->currentWitness++;
		if (ctx->currentWitness == ctx->numWitnesses) {
			TRACE();
			advanceStage();
		}
	}
	UI_STEP_END(HANDLE_INPUT_STEP_INVALID);
}

static void signTx_handleWitnessAPDU(uint8_t p2, uint8_t* dataBuffer, size_t dataSize)
{
	VALIDATE(p2 == 0, ERR_INVALID_REQUEST_PARAMETERS);
	TRACE("Witness n. %d, total %d", ctx->currentWitness, ctx->numWitnesses);

	ASSERT(ctx->currentWitness < ctx->numWitnesses);

	size_t parsedSize = bip44_parseFromWire(&ctx->currentWitnessPath, dataBuffer, dataSize);
	VALIDATE(parsedSize == dataSize, ERR_INVALID_DATA);

	security_policy_t policy = policyForSignTxWitness(&ctx->currentWitnessPath);
	TRACE("policy %d", (int) policy);
	ENSURE_NOT_DENIED(policy);

	TRACE("getTxWitness");
	TRACE("TX HASH");
	TRACE_BUFFER(ctx->txHash, SIZEOF(ctx->txHash));
	TRACE("END TX HASH");

	getTxWitness(
	        &ctx->currentWitnessPath,
	        ctx->txHash, SIZEOF(ctx->txHash),
	        ctx->currentWitnessData, SIZEOF(ctx->currentWitnessData)
	);
	TRACE();

#	define  CASE(POLICY, UI_STEP) case POLICY: {ctx->ui_step=UI_STEP; break;}
#	define  DEFAULT(ERR) default: { THROW(ERR); }
	switch (policy) {
		CASE(POLICY_PROMPT_WARN_UNUSUAL,  HANDLE_WITNESS_STEP_WARNING);
		CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_WITNESS_STEP_RESPOND);
		DEFAULT(ERR_NOT_IMPLEMENTED);
	}
#	undef   CASE
#	undef   DEFAULT

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
		os_memset(ctx, 0, SIZEOF(*ctx));
		ctx->stage = SIGN_STAGE_INIT;
	}
	subhandler_fn_t* subhandler = lookup_subhandler(p1);
	VALIDATE(subhandler != NULL, ERR_INVALID_REQUEST_PARAMETERS);
	subhandler(p2, wireDataBuffer, wireDataSize);
}
