#include "signTxOutput.h"
#include "state.h"
#include "uiHelpers.h"
#include "signTxUtils.h"
#include "uiScreens.h"
#include "txHashBuilder.h"
#include "textUtils.h"
#include "bufView.h"
#include "securityPolicy.h"

// we want to distinguish the two state machines to avoid potential confusion:
// ctx / subctx
// stage / state
// from ctx, we only make the necessary parts available to avoid mistaken overwrites
static output_context_t* subctx = &(instructionState.signTxContext.txPartCtx.body_ctx.stageContext.output_subctx);
static common_tx_data_t* commonTxData = &(instructionState.signTxContext.commonTxData);
static tx_hash_builder_t* txHashBuilder = &(instructionState.signTxContext.txPartCtx.body_ctx.txHashBuilder);

bool signTxOutput_isFinished()
{
	TRACE("Output submachine state: %d", subctx->state);
	// we are also asserting that the state is valid
	switch (subctx->state) {
	case STATE_OUTPUT_FINISHED:
		return true;

	case STATE_OUTPUT_TOP_LEVEL_DATA:
	case STATE_OUTPUT_ASSET_GROUP:
	case STATE_OUTPUT_TOKEN:
	case STATE_OUTPUT_CONFIRM:
		return false;

	default:
		ASSERT(false);
	}
}

void signTxOutput_init()
{
	{
		ins_sign_tx_body_context_t* txBodyCtx = &(instructionState.signTxContext.txPartCtx.body_ctx);
		explicit_bzero(&txBodyCtx->stageContext, SIZEOF(txBodyCtx->stageContext));
	}

	subctx->state = STATE_OUTPUT_TOP_LEVEL_DATA;
}

static inline void CHECK_STATE(sign_tx_output_state_t expected)
{
	TRACE("Output submachine state: current %d, expected %d", subctx->state, expected);
	VALIDATE(subctx->state == expected, ERR_INVALID_STATE);
}

static inline void advanceState()
{
	TRACE("Advancing output state from: %d", subctx->state);

	switch (subctx->state) {

	case STATE_OUTPUT_TOP_LEVEL_DATA:
		if (subctx->numAssetGroups > 0) {
			ASSERT(subctx->currentAssetGroup == 0);
			subctx->state = STATE_OUTPUT_ASSET_GROUP;
		} else {
			subctx->state = STATE_OUTPUT_CONFIRM;
		}
		break;

	case STATE_OUTPUT_ASSET_GROUP:
		ASSERT(subctx->currentAssetGroup < subctx->numAssetGroups);

		// we are going to receive token amounts for this group
		ASSERT(subctx->numTokens > 0);
		ASSERT(subctx->currentToken == 0);

		subctx->state = STATE_OUTPUT_TOKEN;
		break;

	case STATE_OUTPUT_TOKEN:
		// we are done with the current token group
		ASSERT(subctx->currentToken == subctx->numTokens);
		subctx->currentToken = 0;
		ASSERT(subctx->currentAssetGroup < subctx->numAssetGroups);
		subctx->currentAssetGroup++;

		if (subctx->currentAssetGroup == subctx->numAssetGroups) {
			// the whole token bundle has been received
			subctx->state = STATE_OUTPUT_CONFIRM;
		} else {
			subctx->state = STATE_OUTPUT_ASSET_GROUP;
		}
		break;

	case STATE_OUTPUT_CONFIRM:
		subctx->state = STATE_OUTPUT_FINISHED;
		break;

	default:
		ASSERT(false);
	}

	TRACE("Advancing output state to: %d", subctx->state);
}

// ============================== TOP LEVEL DATA ==============================

enum {
	HANDLE_OUTPUT_ADDRESS_BYTES_STEP_DISPLAY_ADDRESS = 3100,
	HANDLE_OUTPUT_ADDRESS_BYTES_STEP_DISPLAY_ADA_AMOUNT,
	HANDLE_OUTPUT_ADDRESS_BYTES_STEP_RESPOND,
	HANDLE_OUTPUT_ADDRESS_BYTES_STEP_INVALID,
};

static void signTx_handleOutput_address_ui_runStep()
{
	TRACE("UI step %d", subctx->ui_step);
	ui_callback_fn_t* this_fn = signTx_handleOutput_address_ui_runStep;

	ASSERT(subctx->stateData.output.outputType == OUTPUT_TYPE_ADDRESS_BYTES);

	UI_STEP_BEGIN(subctx->ui_step, this_fn);

	UI_STEP(HANDLE_OUTPUT_ADDRESS_BYTES_STEP_DISPLAY_ADDRESS) {
		ASSERT(subctx->stateData.output.address.size <= SIZEOF(subctx->stateData.output.address.buffer));
		ui_displayAddressScreen(
		        "Send to address",
		        subctx->stateData.output.address.buffer,
		        subctx->stateData.output.address.size,
		        this_fn
		);
	}
	UI_STEP(HANDLE_OUTPUT_ADDRESS_BYTES_STEP_DISPLAY_ADA_AMOUNT) {
		ui_displayAdaAmountScreen("Send", subctx->stateData.output.adaAmount, this_fn);
	}
	UI_STEP(HANDLE_OUTPUT_ADDRESS_BYTES_STEP_RESPOND) {
		respondSuccessEmptyMsg();

		advanceState();
	}
	UI_STEP_END(HANDLE_OUTPUT_ADDRESS_BYTES_STEP_INVALID);
}

static void signTx_handleOutput_addressBytes()
{
	ASSERT(subctx->stateData.output.outputType == OUTPUT_TYPE_ADDRESS_BYTES);

	security_policy_t policy = policyForSignTxOutputAddressBytes(
	                                   commonTxData->signTxUsecase,
	                                   subctx->stateData.output.address.buffer, subctx->stateData.output.address.size,
	                                   commonTxData->networkId, commonTxData->protocolMagic
	                           );
	TRACE("Policy: %d", (int) policy);
	ENSURE_NOT_DENIED(policy);

	subctx->outputSecurityPolicy = policy;

	{
		// add to tx
		ASSERT(subctx->stateData.output.address.size > 0);
		ASSERT(subctx->stateData.output.address.size < BUFFER_SIZE_PARANOIA);

		txHashBuilder_addOutput_topLevelData(
		        txHashBuilder,
		        subctx->stateData.output.address.buffer,
		        subctx->stateData.output.address.size,
		        subctx->stateData.output.adaAmount,
		        subctx->numAssetGroups
		);
	}

	{
		// select UI steps
		switch (policy) {
#	define  CASE(POLICY, UI_STEP) case POLICY: {subctx->ui_step=UI_STEP; break;}
			CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_OUTPUT_ADDRESS_BYTES_STEP_DISPLAY_ADDRESS);
			CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_OUTPUT_ADDRESS_BYTES_STEP_RESPOND);
#	undef   CASE
		default:
			THROW(ERR_NOT_IMPLEMENTED);
		}

		signTx_handleOutput_address_ui_runStep();
	}
}

enum {
	HANDLE_OUTPUT_ADDRESS_PARAMS_STEP_DISPLAY_SPENDING_PATH = 3200,
	HANDLE_OUTPUT_ADDRESS_PARAMS_STEP_DISPLAY_STAKING_INFO,
	HANDLE_OUTPUT_ADDRESS_PARAMS_STEP_DISPLAY_AMOUNT,
	HANDLE_OUTPUT_ADDRESS_PARAMS_STEP_RESPOND,
	HANDLE_OUTPUT_ADDRESS_PARAMS_STEP_INVALID,
};

static void signTx_handleOutput_addressParams_ui_runStep()
{
	TRACE("UI step %d", subctx->ui_step);
	ui_callback_fn_t* this_fn = signTx_handleOutput_addressParams_ui_runStep;

	ASSERT(subctx->stateData.output.outputType == OUTPUT_TYPE_ADDRESS_PARAMS);

	UI_STEP_BEGIN(subctx->ui_step, this_fn);

	UI_STEP(HANDLE_OUTPUT_ADDRESS_PARAMS_STEP_DISPLAY_SPENDING_PATH) {
		ui_displayPathScreen("Send to address", &subctx->stateData.output.params.spendingKeyPath, this_fn);
	}
	UI_STEP(HANDLE_OUTPUT_ADDRESS_PARAMS_STEP_DISPLAY_STAKING_INFO) {
		ui_displayStakingInfoScreen(&subctx->stateData.output.params, this_fn);
	}
	UI_STEP(HANDLE_OUTPUT_ADDRESS_PARAMS_STEP_DISPLAY_AMOUNT) {
		ui_displayAdaAmountScreen("Send", subctx->stateData.output.adaAmount, this_fn);
	}
	UI_STEP(HANDLE_OUTPUT_ADDRESS_PARAMS_STEP_RESPOND) {
		respondSuccessEmptyMsg();

		advanceState();
	}
	UI_STEP_END(HANDLE_OUTPUT_ADDRESS_PARAMS_STEP_INVALID);
}

static void signTx_handleOutput_addressParams()
{
	ASSERT(subctx->stateData.output.outputType == OUTPUT_TYPE_ADDRESS_PARAMS);

	security_policy_t policy = policyForSignTxOutputAddressParams(
	                                   commonTxData->signTxUsecase,
	                                   &subctx->stateData.output.params,
	                                   commonTxData->networkId, commonTxData->protocolMagic
	                           );
	TRACE("Policy: %d", (int) policy);
	ENSURE_NOT_DENIED(policy);

	subctx->outputSecurityPolicy = policy;

	{
		// add to tx
		uint8_t addressBuffer[MAX_ADDRESS_SIZE];
		size_t addressSize = deriveAddress(
		                             &subctx->stateData.output.params,
		                             addressBuffer,
		                             SIZEOF(addressBuffer)
		                     );
		ASSERT(addressSize > 0);
		ASSERT(addressSize < BUFFER_SIZE_PARANOIA);

		txHashBuilder_addOutput_topLevelData(
		        txHashBuilder,
		        addressBuffer, addressSize,
		        subctx->stateData.output.adaAmount,
		        subctx->numAssetGroups
		);
	}

	{
		// select UI steps
		switch (policy) {
#	define  CASE(POLICY, UI_STEP) case POLICY: {subctx->ui_step=UI_STEP; break;}
			CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_OUTPUT_ADDRESS_PARAMS_STEP_DISPLAY_SPENDING_PATH);
			CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_OUTPUT_ADDRESS_PARAMS_STEP_RESPOND);
#	undef   CASE
		default:
			THROW(ERR_NOT_IMPLEMENTED);
		}

		signTx_handleOutput_addressParams_ui_runStep();
	}
}

static void signTxOutput_handleTopLevelDataAPDU(uint8_t* wireDataBuffer, size_t wireDataSize)
{
	{
		// safety checks
		CHECK_STATE(STATE_OUTPUT_TOP_LEVEL_DATA);

		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}

	{
		// parse all APDU data
		TRACE_BUFFER(wireDataBuffer, wireDataSize);

		top_level_output_data_t* output = &subctx->stateData.output;

		read_view_t view = make_read_view(wireDataBuffer, wireDataBuffer + wireDataSize);

		VALIDATE(view_remainingSize(&view) >= 1, ERR_INVALID_DATA);
		output->outputType = parse_u1be(&view);
		TRACE("Output type %d", (int) subctx->stateData.output.outputType);

		switch(output->outputType) {
		case OUTPUT_TYPE_ADDRESS_BYTES: {
			VALIDATE(view_remainingSize(&view) >= 4, ERR_INVALID_DATA);
			STATIC_ASSERT(sizeof(output->address.size) >= 4, "wrong address size type");
			output->address.size = parse_u4be(&view);
			TRACE("Address length %u", output->address.size);
			VALIDATE(output->address.size <= MAX_ADDRESS_SIZE, ERR_INVALID_DATA);
			VALIDATE(view_remainingSize(&view) >= output->address.size, ERR_INVALID_DATA);

			ASSERT(SIZEOF(output->address.buffer) >= output->address.size);
			view_memmove(output->address.buffer, &view, output->address.size);
			TRACE_BUFFER(output->address.buffer, output->address.size);
			break;
		}
		case OUTPUT_TYPE_ADDRESS_PARAMS: {
			view_parseAddressParams(&view, &output->params);
			break;
		}
		default:
			THROW(ERR_INVALID_DATA);
		};

		VALIDATE(view_remainingSize(&view) >= 8, ERR_INVALID_DATA);
		uint64_t adaAmount = parse_u8be(&view);
		output->adaAmount = adaAmount;
		TRACE("Amount: %u.%06u", (unsigned) (adaAmount / 1000000), (unsigned)(adaAmount % 1000000));
		VALIDATE(adaAmount < LOVELACE_MAX_SUPPLY, ERR_INVALID_DATA);

		VALIDATE(view_remainingSize(&view) >= 4, ERR_INVALID_DATA);
		uint32_t numAssetGroups = parse_u4be(&view);
		TRACE("num asset groups %u", numAssetGroups);
		VALIDATE(numAssetGroups <= OUTPUT_ASSET_GROUPS_MAX, ERR_INVALID_DATA);

		STATIC_ASSERT(OUTPUT_ASSET_GROUPS_MAX <= UINT16_MAX, "wrong max token groups");
		ASSERT_TYPE(subctx->numAssetGroups, uint16_t);
		subctx->numAssetGroups = (uint16_t) numAssetGroups;

		VALIDATE(view_remainingSize(&view) == 0, ERR_INVALID_DATA);
	}
	{
		// call the appropriate handler depending on output type
		// the handlers serialize data into the tx hash
		// and take care of user interactions
		switch(subctx->stateData.output.outputType) {

		case OUTPUT_TYPE_ADDRESS_BYTES:
			signTx_handleOutput_addressBytes();
			break;

		case OUTPUT_TYPE_ADDRESS_PARAMS:
			signTx_handleOutput_addressParams();
			break;

		default:
			ASSERT(false);
		};
	}
}

// ============================== ASSET GROUP ==============================

enum {
	HANDLE_ASSET_GROUP_STEP_DISPLAY = 3300,
	HANDLE_ASSET_GROUP_STEP_RESPOND,
	HANDLE_ASSET_GROUP_STEP_INVALID,
};

static void signTxOutput_handleAssetGroup_ui_runStep()
{
	TRACE("UI step %d", subctx->ui_step);
	ui_callback_fn_t* this_fn = signTxOutput_handleAssetGroup_ui_runStep;

	UI_STEP_BEGIN(subctx->ui_step, this_fn);

	UI_STEP(HANDLE_ASSET_GROUP_STEP_RESPOND) {
		respondSuccessEmptyMsg();

		advanceState();
	}
	UI_STEP_END(HANDLE_ASSET_GROUP_STEP_INVALID);
}

static void signTxOutput_handleAssetGroupAPDU(uint8_t* wireDataBuffer, size_t wireDataSize)
{
	{
		// sanity checks
		CHECK_STATE(STATE_OUTPUT_ASSET_GROUP);

		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}
	{
		token_group_t* tokenGroup = &subctx->stateData.tokenGroup;

		// parse data
		TRACE_BUFFER(wireDataBuffer, wireDataSize);
		read_view_t view = make_read_view(wireDataBuffer, wireDataBuffer + wireDataSize);

		VALIDATE(view_remainingSize(&view) >= MINTING_POLICY_ID_SIZE, ERR_INVALID_DATA);
		STATIC_ASSERT(SIZEOF(tokenGroup->policyId) == MINTING_POLICY_ID_SIZE, "wrong policy id size");
		uint8_t candidatePolicyId[MINTING_POLICY_ID_SIZE];
		view_memmove(candidatePolicyId, &view, MINTING_POLICY_ID_SIZE);
		VALIDATE(0 == subctx->currentAssetGroup || cbor_mapKeyFulfillsCanonicalOrdering(
		                 tokenGroup->policyId, MINTING_POLICY_ID_SIZE,
		                 candidatePolicyId, MINTING_POLICY_ID_SIZE), ERR_INVALID_DATA);

		STATIC_ASSERT(SIZEOF(tokenGroup->policyId) >= MINTING_POLICY_ID_SIZE, "wrong policyId length");
		memcpy(tokenGroup->policyId, candidatePolicyId, MINTING_POLICY_ID_SIZE);

		VALIDATE(view_remainingSize(&view) == 4, ERR_INVALID_DATA);
		uint32_t numTokens = parse_u4be(&view);
		VALIDATE(numTokens <= OUTPUT_TOKENS_IN_GROUP_MAX, ERR_INVALID_DATA);
		STATIC_ASSERT(OUTPUT_TOKENS_IN_GROUP_MAX <= UINT16_MAX, "wrong max token amounts in a group");
		ASSERT_TYPE(subctx->numTokens, uint16_t);
		subctx->numTokens = (uint16_t) numTokens;
	}

	{
		// add tokengroup to tx
		TRACE("Adding token group hash to tx hash");
		txHashBuilder_addOutput_tokenGroup(
		        txHashBuilder,
		        subctx->stateData.tokenGroup.policyId, MINTING_POLICY_ID_SIZE,
		        subctx->numTokens
		);
		TRACE();
	}
	subctx->ui_step = HANDLE_ASSET_GROUP_STEP_RESPOND;
	signTxOutput_handleAssetGroup_ui_runStep();
}

// ============================== TOKEN ==============================

enum {
	HANDLE_TOKEN_STEP_DISPLAY_NAME = 3400,
	HANDLE_TOKEN_STEP_DISPLAY_AMOUNT,
	HANDLE_TOKEN_STEP_RESPOND,
	HANDLE_TOKEN_STEP_INVALID,
};

static void signTxOutput_handleToken_ui_runStep()
{
	TRACE("UI step %d", subctx->ui_step);
	ui_callback_fn_t* this_fn = signTxOutput_handleToken_ui_runStep;

	UI_STEP_BEGIN(subctx->ui_step, this_fn);

	UI_STEP(HANDLE_TOKEN_STEP_DISPLAY_NAME) {
		ui_displayAssetFingerprintScreen(
		        &subctx->stateData.tokenGroup,
		        subctx->stateData.token.assetNameBytes, subctx->stateData.token.assetNameSize,
		        this_fn
		);
	}
	UI_STEP(HANDLE_TOKEN_STEP_DISPLAY_AMOUNT) {
		ui_displayUint64Screen(
		        "Token amount",
		        subctx->stateData.token.amount,
		        this_fn
		);
	}
	UI_STEP(HANDLE_TOKEN_STEP_RESPOND) {
		respondSuccessEmptyMsg();

		ASSERT(subctx->currentToken < subctx->numTokens);
		subctx->currentToken++;

		if (subctx->currentToken == subctx->numTokens) {
			advanceState();
		}
	}
	UI_STEP_END(HANDLE_TOKEN_STEP_INVALID);
}

static void signTxOutput_handleTokenAPDU(uint8_t* wireDataBuffer, size_t wireDataSize)
{
	{
		// sanity checks
		CHECK_STATE(STATE_OUTPUT_TOKEN);

		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}
	{
		output_token_amount_t* token = &subctx->stateData.token;

		// parse data
		TRACE_BUFFER(wireDataBuffer, wireDataSize);
		read_view_t view = make_read_view(wireDataBuffer, wireDataBuffer + wireDataSize);

		VALIDATE(view_remainingSize(&view) >= 4, ERR_INVALID_DATA);
		const size_t candidateAssetNameSize = parse_u4be(&view);

		VALIDATE(candidateAssetNameSize <= ASSET_NAME_SIZE_MAX, ERR_INVALID_DATA);
		ASSERT(candidateAssetNameSize <= SIZEOF(token->assetNameBytes));
		uint8_t candidateAssetNameBytes[ASSET_NAME_SIZE_MAX];

		view_memmove(candidateAssetNameBytes, &view, candidateAssetNameSize);
		if (0 < subctx->currentToken) {
			VALIDATE(cbor_mapKeyFulfillsCanonicalOrdering(
			                 token->assetNameBytes, token->assetNameSize,
			                 candidateAssetNameBytes, candidateAssetNameSize
			         ), ERR_INVALID_DATA);
		}

		token->assetNameSize = candidateAssetNameSize;
		ASSERT(sizeof(token->assetNameBytes) >= candidateAssetNameSize);
		memcpy(token->assetNameBytes, candidateAssetNameBytes, candidateAssetNameSize);

		VALIDATE(view_remainingSize(&view) == 8, ERR_INVALID_DATA);
		token->amount = parse_u8be(&view);
		TRACE_UINT64(token->amount);
	}

	{
		// select UI step
		switch (subctx->outputSecurityPolicy) {
#	define  CASE(POLICY, UI_STEP) case POLICY: {subctx->ui_step=UI_STEP; break;}
			CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_TOKEN_STEP_DISPLAY_NAME);
			CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_TOKEN_STEP_RESPOND);
#	undef   CASE
		default:
			THROW(ERR_NOT_IMPLEMENTED);
		}
	}

	{
		// add tokengroup to tx
		TRACE("Adding token group hash to tx hash");
		txHashBuilder_addOutput_token(
		        txHashBuilder,
		        subctx->stateData.token.assetNameBytes, subctx->stateData.token.assetNameSize,
		        subctx->stateData.token.amount
		);
		TRACE();
	}

	signTxOutput_handleToken_ui_runStep();
}

// ============================== CONFIRM ==============================

enum {
	HANDLE_CONFIRM_STEP_FINAL_CONFIRM = 3500,
	HANDLE_CONFIRM_STEP_RESPOND,
	HANDLE_CONFIRM_STEP_INVALID,
};

static void signTxOutput_handleConfirm_ui_runStep()
{
	TRACE("UI step %d", subctx->ui_step);
	ui_callback_fn_t* this_fn = signTxOutput_handleConfirm_ui_runStep;

	UI_STEP_BEGIN(subctx->ui_step, this_fn);

	UI_STEP(HANDLE_CONFIRM_STEP_FINAL_CONFIRM) {
		ui_displayPrompt(
		        "Confirm output?",
		        "",
		        this_fn,
		        respond_with_user_reject
		);
	}
	UI_STEP(HANDLE_CONFIRM_STEP_RESPOND) {
		respondSuccessEmptyMsg();
		advanceState();
	}
	UI_STEP_END(HANDLE_CONFIRM_STEP_INVALID);
}

static void signTxOutput_handleConfirmAPDU(uint8_t* wireDataBuffer MARK_UNUSED, size_t wireDataSize)
{
	{
		//sanity checks
		CHECK_STATE(STATE_OUTPUT_CONFIRM);

		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}

	{
		// no data to receive
		VALIDATE(wireDataSize == 0, ERR_INVALID_DATA);
	}

	security_policy_t policy = policyForSignTxOutputConfirm(
	                                   subctx->outputSecurityPolicy,
	                                   subctx->numAssetGroups
	                           );
	TRACE("Policy: %d", (int) policy);
	ENSURE_NOT_DENIED(policy);

	{
		// select UI step
		switch (policy) {
#	define  CASE(POLICY, UI_STEP) case POLICY: {subctx->ui_step=UI_STEP; break;}
			CASE(POLICY_PROMPT_BEFORE_RESPONSE, HANDLE_CONFIRM_STEP_FINAL_CONFIRM);
			CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_CONFIRM_STEP_RESPOND);
#	undef   CASE
		default:
			THROW(ERR_NOT_IMPLEMENTED);
		}
	}

	signTxOutput_handleConfirm_ui_runStep();
}


// ============================== main APDU handler ==============================

enum {
	APDU_INSTRUCTION_TOP_LEVEL_DATA = 0x30,
	APDU_INSTRUCTION_ASSET_GROUP = 0x31,
	APDU_INSTRUCTION_TOKEN = 0x32,
	APDU_INSTRUCTION_CONFIRM = 0x33,
};

bool signTxOutput_isValidInstruction(uint8_t p2)
{
	switch (p2) {
	case APDU_INSTRUCTION_TOP_LEVEL_DATA:
	case APDU_INSTRUCTION_ASSET_GROUP:
	case APDU_INSTRUCTION_TOKEN:
	case APDU_INSTRUCTION_CONFIRM:
		return true;

	default:
		return false;
	}
}

void signTxOutput_handleAPDU(uint8_t p2, uint8_t* wireDataBuffer, size_t wireDataSize)
{
	switch (p2) {
	case APDU_INSTRUCTION_TOP_LEVEL_DATA:
		signTxOutput_handleTopLevelDataAPDU(wireDataBuffer, wireDataSize);
		break;

	case APDU_INSTRUCTION_ASSET_GROUP:
		signTxOutput_handleAssetGroupAPDU(wireDataBuffer, wireDataSize);
		break;

	case APDU_INSTRUCTION_TOKEN:
		signTxOutput_handleTokenAPDU(wireDataBuffer, wireDataSize);
		break;

	case APDU_INSTRUCTION_CONFIRM:
		signTxOutput_handleConfirmAPDU(wireDataBuffer, wireDataSize);
		break;

	default:
		// this is not supposed to be called with invalid p2
		ASSERT(false);
	}
}
