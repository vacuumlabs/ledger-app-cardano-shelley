#include "signTxOutput.h"
#include "state.h"
// #include "cardano.h"
// #include "addressUtilsShelley.h"
#include "uiHelpers.h"
#include "signTxUtils.h"
#include "uiScreens.h"
#include "txHashBuilder.h"
#include "textUtils.h"
// #include "hexUtils.h"
// #include "messageSigning.h"
#include "bufView.h"
#include "securityPolicy.h"

// we want to distinguish the two state machines to avoid potential confusion:
// ctx / subctx
// stage / state
// from ctx, we only make the necessary parts available to avoid mistaken overwrites
static output_context_t* subctx = &(instructionState.signTxContext.stageContext.output_subctx);
static common_tx_data_t* commonTxData = &(instructionState.signTxContext.commonTxData);
static tx_hash_builder_t* txHashBuilder = &(instructionState.signTxContext.txHashBuilder);

bool signTxOutput_isFinished()
{
	TRACE("Output submachine state: %d", subctx->state);
	// we are also asserting that the state is valid
	switch (subctx->state) {
	case STATE_OUTPUT_FINISHED:
		return true;

	case STATE_OUTPUT_BASIC_DATA:
	case STATE_OUTPUT_TOKEN_GROUP:
	case STATE_OUTPUT_TOKEN_AMOUNT:
	case STATE_OUTPUT_CONFIRM:
		return false;

	default:
		ASSERT(false);
	}
}

void signTxOutput_init()
{
	explicit_bzero(subctx, SIZEOF(*subctx));

	subctx->state = STATE_OUTPUT_BASIC_DATA;
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

	case STATE_OUTPUT_BASIC_DATA:
		if (subctx->numTokenGroups > 0) {
			ASSERT(subctx->currentTokenGroup == 0);
			subctx->state = STATE_OUTPUT_TOKEN_GROUP;
		} else {
			subctx->state = STATE_OUTPUT_CONFIRM;
		}
		break;

	case STATE_OUTPUT_TOKEN_GROUP:
		ASSERT(subctx->currentTokenGroup < subctx->numTokenGroups);

		// we are going to receive token amounts for this group
		ASSERT(subctx->numTokenAmounts > 0);

		subctx->state = STATE_OUTPUT_TOKEN_AMOUNT;
		break;

	case STATE_OUTPUT_TOKEN_AMOUNT:
		if (subctx->currentTokenAmount == subctx->numTokenAmounts) {
			// we are done with the current token group
			subctx->currentTokenGroup++;

			if (subctx->currentTokenGroup == subctx->numTokenGroups) {
				// all of the token bundle has been received
				subctx->state = STATE_OUTPUT_CONFIRM;
			} else {
				subctx->state = STATE_OUTPUT_TOKEN_GROUP;
			}
		} else {
			// no need to change the state, more token amounts to receive
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

// ============================== BASIC_DATA ==============================

enum {
	HANDLE_OUTPUT_ADDRESS_BYTES_STEP_DISPLAY_ADDRESS = 300,
	HANDLE_OUTPUT_ADDRESS_BYTES_STEP_DISPLAY_ADA_AMOUNT,
	HANDLE_OUTPUT_ADDRESS_BYTES_STEP_RESPOND,
	HANDLE_OUTPUT_ADDRESS_BYTES_STEP_INVALID,
};

static void signTx_handleOutput_address_ui_runStep()
{
	TRACE("UI step %d", subctx->ui_step);
	ui_callback_fn_t* this_fn = signTx_handleOutput_address_ui_runStep;

	ASSERT(subctx->stateData.output.outputType == OUTPUT_TYPE_ADDRESS_BYTES);

	UI_STEP_BEGIN(subctx->ui_step);

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
		ui_displayAmountScreen("Send", subctx->stateData.output.adaAmount, this_fn);
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

	security_policy_t policy = policyForSignTxOutputAddress(
	                                   commonTxData->isSigningPoolRegistrationAsOwner,
	                                   subctx->stateData.output.address.buffer, subctx->stateData.output.address.size,
	                                   commonTxData->networkId, commonTxData->protocolMagic
	                           );
	TRACE("Policy: %d", (int) policy);
	ENSURE_NOT_DENIED(policy);

	{
		// add to tx
		ASSERT(subctx->stateData.output.address.size > 0);
		ASSERT(subctx->stateData.output.address.size < BUFFER_SIZE_PARANOIA);

		txHashBuilder_addOutput_basicData(
		        txHashBuilder,
		        subctx->stateData.output.address.buffer,
		        subctx->stateData.output.address.size,
		        subctx->stateData.output.adaAmount,
		        subctx->numTokenGroups
		);
	}

	{
		// select UI steps
		switch (policy) {
#	define  CASE(POLICY, UI_STEP) case POLICY: {subctx->ui_step=UI_STEP; break;}
			CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_OUTPUT_ADDRESS_BYTES_STEP_DISPLAY_ADA_AMOUNT);
			CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_OUTPUT_ADDRESS_BYTES_STEP_RESPOND);
#	undef   CASE
		default:
			THROW(ERR_NOT_IMPLEMENTED);
		}

		signTx_handleOutput_address_ui_runStep();
	}
}

enum {
	HANDLE_OUTPUT_ADDRESS_PARAMS_STEP_DISPLAY_SPENDING_PATH = 350,
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

	UI_STEP_BEGIN(subctx->ui_step);

	UI_STEP(HANDLE_OUTPUT_ADDRESS_PARAMS_STEP_DISPLAY_SPENDING_PATH) {
		ui_displayPathScreen("Send to address", &subctx->stateData.output.params.spendingKeyPath, this_fn);
	}
	UI_STEP(HANDLE_OUTPUT_ADDRESS_PARAMS_STEP_DISPLAY_STAKING_INFO) {
		ui_displayStakingInfoScreen(&subctx->stateData.output.params, this_fn);
	}
	UI_STEP(HANDLE_OUTPUT_ADDRESS_PARAMS_STEP_DISPLAY_AMOUNT) {
		ui_displayAmountScreen("Send", subctx->stateData.output.adaAmount, this_fn);
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
	                                   commonTxData->isSigningPoolRegistrationAsOwner,
	                                   &subctx->stateData.output.params,
	                                   commonTxData->networkId, commonTxData->protocolMagic
	                           );
	TRACE("Policy: %d", (int) policy);
	ENSURE_NOT_DENIED(policy);

	{
		// add to tx
		uint8_t addressBuffer[MAX_ADDRESS_SIZE];
		size_t addressSize;
		addressSize = deriveAddress(
		                      &subctx->stateData.output.params,
		                      addressBuffer,
		                      SIZEOF(addressBuffer)
		              );
		ASSERT(addressSize > 0);
		ASSERT(addressSize < BUFFER_SIZE_PARANOIA);

		txHashBuilder_addOutput_basicData(
		        txHashBuilder,
		        addressBuffer, addressSize,
		        subctx->stateData.output.adaAmount,
		        subctx->numTokenGroups
		);
	}

	{
		// select UI steps
		switch (policy) {
#	define  CASE(POLICY, UI_STEP) case POLICY: {subctx->ui_step=UI_STEP; break;}
			CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_OUTPUT_ADDRESS_PARAMS_STEP_DISPLAY_AMOUNT);
			CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_OUTPUT_ADDRESS_PARAMS_STEP_RESPOND);
#	undef   CASE
		default:
			THROW(ERR_NOT_IMPLEMENTED);
		}

		signTx_handleOutput_addressParams_ui_runStep();
	}
}

static void signTxOutput_handleBasicDataAPDU(uint8_t* wireDataBuffer, size_t wireDataSize)
{
	{
		// safety checks
		CHECK_STATE(STATE_OUTPUT_BASIC_DATA);

		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}

	{
		// parse all APDU data
		TRACE_BUFFER(wireDataBuffer, wireDataSize);

		basic_output_data_t* output = &subctx->stateData.output;

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
		uint32_t numTokenGroups = parse_u4be(&view);
		TRACE("num token groups %u", subctx->numTokenGroups);
		VALIDATE(subctx->numTokenGroups <= OUTPUT_NUM_TOKEN_GROUPS_MAX, ERR_INVALID_DATA);

		STATIC_ASSERT(OUTPUT_NUM_TOKEN_GROUPS_MAX <= UINT16_MAX, "wrong max token groups");
		ASSERT_TYPE(subctx->numTokenGroups, uint16_t);
		subctx->numTokenGroups = (uint16_t) numTokenGroups;

		TRACE("remaining %u", view_remainingSize(&view));
		TRACE_BUFFER(view.ptr, view_remainingSize(&view));
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

// ============================== TOKEN GROUP ==============================

enum {
	HANDLE_TOKEN_GROUP_STEP_DISPLAY = 800, // TODO
	HANDLE_TOKEN_GROUP_STEP_RESPOND,
	HANDLE_TOKEN_GROUP_STEP_INVALID,
};

static void signTxOutput_handleTokenGroup_ui_runStep()
{
	TRACE("UI step %d", subctx->ui_step);
	ui_callback_fn_t* this_fn = signTxOutput_handleTokenGroup_ui_runStep;

	UI_STEP_BEGIN(subctx->ui_step);

	UI_STEP(HANDLE_TOKEN_GROUP_STEP_DISPLAY) {
		STATIC_ASSERT(SIZEOF(subctx->stateData.tokenGroup.policyId) == MINTING_POLICY_ID_SIZE, "inconsistent minting policy id size");

		ui_displayHexBufferScreen(
		        "Token policy id",
		        subctx->stateData.tokenGroup.policyId, MINTING_POLICY_ID_SIZE,
		        this_fn
		);
	}
	UI_STEP(HANDLE_TOKEN_GROUP_STEP_RESPOND) {
		respondSuccessEmptyMsg();
		advanceState();
	}
	UI_STEP_END(HANDLE_TOKEN_GROUP_STEP_INVALID);
}

static void signTxOutput_handleTokenGroupAPDU(uint8_t* wireDataBuffer, size_t wireDataSize)
{
	{
		// sanity checks
		CHECK_STATE(STATE_OUTPUT_TOKEN_GROUP);

		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}
	{
		token_group_t* tokenGroup = &subctx->stateData.tokenGroup;

		// parse data
		TRACE_BUFFER(wireDataBuffer, wireDataSize);
		read_view_t view = make_read_view(wireDataBuffer, wireDataBuffer + wireDataSize);

		VALIDATE(view_remainingSize(&view) >= MINTING_POLICY_ID_SIZE, ERR_INVALID_DATA);
		STATIC_ASSERT(SIZEOF(tokenGroup->policyId) == MINTING_POLICY_ID_SIZE, "inconsistent policy id size");
		view_memmove(tokenGroup->policyId, &view, MINTING_POLICY_ID_SIZE);

		VALIDATE(view_remainingSize(&view) == 4, ERR_INVALID_DATA);
		uint32_t numTokenAmounts = parse_u4be(&view);
		VALIDATE(numTokenAmounts <= OUTPUT_TOKEN_GROUP_NUM_TOKENS_MAX, ERR_INVALID_DATA);
		STATIC_ASSERT(OUTPUT_TOKEN_GROUP_NUM_TOKENS_MAX <= UINT16_MAX, "wrong max token amounts in a group");
		ASSERT_TYPE(subctx->numTokenAmounts, uint16_t);
		subctx->numTokenAmounts = (uint16_t) numTokenAmounts;
	}

	security_policy_t policy = policyForSignTxOutputTokenGroup(&subctx->stateData.tokenGroup);
	TRACE("Policy: %d", (int) policy);
	ENSURE_NOT_DENIED(policy);

	{
		// select UI step
		switch (policy) {
#	define  CASE(POLICY, UI_STEP) case POLICY: {subctx->ui_step=UI_STEP; break;}
			CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_TOKEN_GROUP_STEP_DISPLAY);
			CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_TOKEN_GROUP_STEP_RESPOND);
#	undef   CASE
		default:
			THROW(ERR_NOT_IMPLEMENTED);
		}
	}

	{
		// add tokengroup to tx
		TRACE("Adding token group hash to tx hash");
		txHashBuilder_addOutput_tokenGroup(
		        txHashBuilder,
		        subctx->stateData.tokenGroup.policyId, MINTING_POLICY_ID_SIZE,
		        subctx->numTokenAmounts
		);
		TRACE();
	}

	signTxOutput_handleTokenGroup_ui_runStep();
}

// ============================== TOKEN AMOUNT ==============================

enum {
	HANDLE_TOKEN_AMOUNT_STEP_DISPLAY_NAME = 800, // TODO
	HANDLE_TOKEN_AMOUNT_STEP_DISPLAY_AMOUNT,
	HANDLE_TOKEN_AMOUNT_STEP_RESPOND,
	HANDLE_TOKEN_AMOUNT_STEP_INVALID,
};

static void signTxOutput_handleTokenAmount_ui_runStep()
{
	TRACE("UI step %d", subctx->ui_step);
	ui_callback_fn_t* this_fn = signTxOutput_handleTokenAmount_ui_runStep;

	UI_STEP_BEGIN(subctx->ui_step);

	UI_STEP(HANDLE_TOKEN_AMOUNT_STEP_DISPLAY_NAME) {
		token_amount_t* tokenAmount = &subctx->stateData.tokenAmount;
		if (str_isTextPrintable(tokenAmount->assetName, tokenAmount->assetNameSize)) {
			char name[ASSET_NAME_SIZE_MAX + 1];
			ASSERT(tokenAmount->assetNameSize + 1 <= SIZEOF(name));
			for (size_t i = 0; i < tokenAmount->assetNameSize; i++)
				name[i] = tokenAmount->assetName[i];
			name[tokenAmount->assetNameSize] = '\0';

			ui_displayPaginatedText(
			        "Token name",
			        name,
			        this_fn
			);
		} else {
			ui_displayHexBufferScreen(
			        "Token name",
			        subctx->stateData.tokenAmount.assetName, subctx->stateData.tokenAmount.assetNameSize,
			        this_fn
			);
		}
	}
	UI_STEP(HANDLE_TOKEN_AMOUNT_STEP_DISPLAY_AMOUNT) {
		ui_displayUint64Screen(
		        "Token amount",
		        subctx->stateData.tokenAmount.amount,
		        this_fn
		);
	}
	UI_STEP(HANDLE_TOKEN_AMOUNT_STEP_RESPOND) {
		respondSuccessEmptyMsg();
		advanceState();
	}
	UI_STEP_END(HANDLE_TOKEN_AMOUNT_STEP_INVALID);
}

static void signTxOutput_handleTokenAmountAPDU(uint8_t* wireDataBuffer, size_t wireDataSize)
{
	{
		// sanity checks
		CHECK_STATE(STATE_OUTPUT_TOKEN_AMOUNT);

		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}
	{
		token_amount_t* tokenAmount = &subctx->stateData.tokenAmount;

		// parse data
		TRACE_BUFFER(wireDataBuffer, wireDataSize);
		read_view_t view = make_read_view(wireDataBuffer, wireDataBuffer + wireDataSize);

		VALIDATE(view_remainingSize(&view) >= 4, ERR_INVALID_DATA);
		tokenAmount->assetNameSize = parse_u4be(&view);
		VALIDATE(tokenAmount->assetNameSize > 0, ERR_INVALID_DATA);
		VALIDATE(tokenAmount->assetNameSize <= ASSET_NAME_SIZE_MAX, ERR_INVALID_DATA);

		ASSERT(tokenAmount->assetNameSize <= SIZEOF(tokenAmount->assetName));
		view_memmove(tokenAmount->assetName, &view, tokenAmount->assetNameSize);

		VALIDATE(view_remainingSize(&view) == 8, ERR_INVALID_DATA);
		tokenAmount->amount = parse_u8be(&view);
		TRACE_UINT64(tokenAmount->amount);
		// TODO validate something?
	}

	security_policy_t policy = policyForSignTxOutputTokenAmount(&subctx->stateData.tokenAmount);
	TRACE("Policy: %d", (int) policy);
	ENSURE_NOT_DENIED(policy);

	{
		// select UI step
		switch (policy) {
#	define  CASE(POLICY, UI_STEP) case POLICY: {subctx->ui_step=UI_STEP; break;}
			CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_TOKEN_AMOUNT_STEP_DISPLAY_NAME);
			CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_TOKEN_AMOUNT_STEP_RESPOND);
#	undef   CASE
		default:
			THROW(ERR_NOT_IMPLEMENTED);
		}
	}

	{
		// add tokengroup to tx
		TRACE("Adding token group hash to tx hash");
		txHashBuilder_addOutput_tokenAmount(
		        txHashBuilder,
		        subctx->stateData.tokenAmount.assetName, subctx->stateData.tokenAmount.assetNameSize,
		        subctx->stateData.tokenAmount.amount
		);
		TRACE();
	}

	signTxOutput_handleTokenAmount_ui_runStep();
}

// ============================== CONFIRM ==============================

enum {
	HANDLE_CONFIRM_STEP_FINAL_CONFIRM = 6360,
	HANDLE_CONFIRM_STEP_RESPOND,
	HANDLE_CONFIRM_STEP_INVALID,
};

static void signTxOutput_handleConfirm_ui_runStep()
{
	TRACE("UI step %d", subctx->ui_step);
	ui_callback_fn_t* this_fn = signTxOutput_handleConfirm_ui_runStep;

	UI_STEP_BEGIN(subctx->ui_step);

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

	security_policy_t policy = policyForSignTxOutputConfirm(subctx->numTokenGroups);
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
	APDU_INSTRUCTION_BASIC_DATA = 0x30,
	APDU_INSTRUCTION_TOKEN_GROUP = 0x31,
	APDU_INSTRUCTION_TOKEN_AMOUNT = 0x32,
	APDU_INSTRUCTION_CONFIRM = 0x33,
};

bool signTxOutput_isValidInstruction(uint8_t p2)
{
	switch (p2) {
	case APDU_INSTRUCTION_BASIC_DATA:
	case APDU_INSTRUCTION_TOKEN_GROUP:
	case APDU_INSTRUCTION_TOKEN_AMOUNT:
	case APDU_INSTRUCTION_CONFIRM:
		return true;

	default:
		return false;
	}
}

void signTxOutput_handleAPDU(uint8_t p2, uint8_t* wireDataBuffer, size_t wireDataSize)
{
	TRACE("p2 = %d", p2);

	switch (p2) {
	case APDU_INSTRUCTION_BASIC_DATA:
		signTxOutput_handleBasicDataAPDU(wireDataBuffer, wireDataSize);
		break;

	case APDU_INSTRUCTION_TOKEN_GROUP:
		signTxOutput_handleTokenGroupAPDU(wireDataBuffer, wireDataSize);
		break;

	case APDU_INSTRUCTION_TOKEN_AMOUNT:
		signTxOutput_handleTokenAmountAPDU(wireDataBuffer, wireDataSize);
		break;

	case APDU_INSTRUCTION_CONFIRM:
		signTxOutput_handleConfirmAPDU(wireDataBuffer, wireDataSize);
		break;

	default:
		// this is not supposed to be called with invalid p2
		ASSERT(false);
	}
}
