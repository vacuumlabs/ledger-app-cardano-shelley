#include "signTxMint.h"
#include "signTxUtils.h"
#include "state.h"
#include "uiHelpers.h"
#include "utils.h"
#include "uiScreens.h"
#include "textUtils.h"
#include "securityPolicy.h"

static mint_context_t* subctx = &(instructionState.signTxContext.txPartCtx.body_ctx.stageContext.mint_subctx);
static common_tx_data_t* commonTxData = &(instructionState.signTxContext.commonTxData);
static tx_hash_builder_t* txHashBuilder = &(instructionState.signTxContext.txPartCtx.body_ctx.txHashBuilder);

static inline void CHECK_STATE(sign_tx_mint_state_t expected)
{
	TRACE("Mint submachine state: current %d, expected %d", subctx->state, expected);
	VALIDATE(subctx->state == expected, ERR_INVALID_STATE);
}

static inline void advanceState()
{
	TRACE("Advancing mint state from: %d", subctx->state);

	switch (subctx->state) {

	case STATE_MINT_TOP_LEVEL_DATA:
		ASSERT(subctx->numAssetGroups > 0);
		ASSERT(subctx->currentAssetGroup == 0);
		subctx->state = STATE_MINT_ASSET_GROUP;
		break;

	case STATE_MINT_ASSET_GROUP:
		ASSERT(subctx->currentAssetGroup < subctx->numAssetGroups);

		// we are going to receive token amounts for this group
		ASSERT(subctx->numTokens > 0);
		ASSERT(subctx->currentToken == 0);

		subctx->state = STATE_MINT_TOKEN;
		break;

	case STATE_MINT_TOKEN:
		// we are done with the current token group
		ASSERT(subctx->currentToken == subctx->numTokens);
		subctx->currentToken = 0;
		ASSERT(subctx->currentAssetGroup < subctx->numAssetGroups);
		subctx->currentAssetGroup++;

		if (subctx->currentAssetGroup == subctx->numAssetGroups) {
			// the whole token bundle has been received
			subctx->state = STATE_MINT_CONFIRM;
		} else {
			subctx->state = STATE_MINT_ASSET_GROUP;
		}
		break;

	case STATE_MINT_CONFIRM:
		subctx->state = STATE_MINT_FINISHED;
		break;

	default:
		ASSERT(false);
	}

	TRACE("Advancing mint state to: %d", subctx->state);
}

static void signTxMint_handleTopLevelDataAPDU(uint8_t* wireDataBuffer, size_t wireDataSize)
{
	{
		// safety checks
		CHECK_STATE(STATE_MINT_TOP_LEVEL_DATA);
		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}
	TRACE_BUFFER(wireDataBuffer, wireDataSize);
	{
		read_view_t view = make_read_view(wireDataBuffer, wireDataBuffer + wireDataSize);
		VALIDATE(view_remainingSize(&view) >= 4, ERR_INVALID_DATA);
		uint32_t numAssetGroups = parse_u4be(&view);
		TRACE("num asset groups %u", numAssetGroups);
		VALIDATE(numAssetGroups <= OUTPUT_ASSET_GROUPS_MAX, ERR_INVALID_DATA);

		STATIC_ASSERT(OUTPUT_ASSET_GROUPS_MAX <= UINT16_MAX, "wrong max token groups");
		ASSERT_TYPE(subctx->numAssetGroups, uint16_t);
		subctx->numAssetGroups = (uint16_t) numAssetGroups;

		VALIDATE(view_remainingSize(&view) == 0, ERR_INVALID_DATA);
	}
	txHashBuilder_addMint_topLevelData(txHashBuilder, subctx->numAssetGroups);
	subctx->mintSecurityPolicy = policyForSignTxMintInit(commonTxData->signTxUsecase);
	ENSURE_NOT_DENIED(subctx->mintSecurityPolicy);

	respondSuccessEmptyMsg();
	advanceState();
}

enum {
	HANDLE_ASSET_GROUP_STEP_DISPLAY = 800, // TODO
	HANDLE_ASSET_GROUP_STEP_RESPOND,
	HANDLE_ASSET_GROUP_STEP_INVALID,
};

static void signTxMint_handleAssetGroup_ui_runStep()
{
	TRACE("UI step %d", subctx->ui_step);

	ui_callback_fn_t* this_fn = signTxMint_handleAssetGroup_ui_runStep;

	UI_STEP_BEGIN(subctx->ui_step, this_fn);

	UI_STEP(HANDLE_ASSET_GROUP_STEP_RESPOND) {
		respondSuccessEmptyMsg();

		advanceState();
	}
	UI_STEP_END(HANDLE_ASSET_GROUP_STEP_INVALID);
}

static void signTxMint_handleAssetGroupAPDU(uint8_t* wireDataBuffer, size_t wireDataSize)
{
	{
		// sanity checks
		CHECK_STATE(STATE_MINT_ASSET_GROUP);

		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}
	{
		token_group_t* tokenGroup = &subctx->stateData.tokenGroup;

		// parse data
		TRACE_BUFFER(wireDataBuffer, wireDataSize);
		read_view_t view = make_read_view(wireDataBuffer, wireDataBuffer + wireDataSize);

		VALIDATE(view_remainingSize(&view) >= MINTING_POLICY_ID_SIZE, ERR_INVALID_DATA);
		STATIC_ASSERT(SIZEOF(tokenGroup->policyId) == MINTING_POLICY_ID_SIZE, "wrong policy id size");
		view_memmove(tokenGroup->policyId, &view, MINTING_POLICY_ID_SIZE);

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
		txHashBuilder_addMint_tokenGroup(
		        txHashBuilder,
		        subctx->stateData.tokenGroup.policyId, MINTING_POLICY_ID_SIZE,
		        subctx->numTokens
		);
		TRACE();
	}

	subctx->ui_step = HANDLE_ASSET_GROUP_STEP_RESPOND;
	signTxMint_handleAssetGroup_ui_runStep();
}

enum {
	HANDLE_TOKEN_STEP_DISPLAY_NAME = 800, // TODO
	HANDLE_TOKEN_STEP_DISPLAY_AMOUNT,
	HANDLE_TOKEN_STEP_RESPOND,
	HANDLE_TOKEN_STEP_INVALID,
};


static void signTxMint_handleToken_ui_runStep()
{
	TRACE("UI step %d", subctx->ui_step);
	ui_callback_fn_t* this_fn = signTxMint_handleToken_ui_runStep;

	UI_STEP_BEGIN(subctx->ui_step, this_fn);

	UI_STEP(HANDLE_TOKEN_STEP_DISPLAY_NAME) {
		ui_displayAssetFingerprintScreen(
		        &subctx->stateData.tokenGroup,
		        subctx->stateData.token.assetNameBytes, subctx->stateData.token.assetNameSize,
		        this_fn
		);
	}
	UI_STEP(HANDLE_TOKEN_STEP_DISPLAY_AMOUNT) {
		ui_displayInt64Screen(
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

static void signTxMint_handleTokenAPDU(uint8_t* wireDataBuffer, size_t wireDataSize)
{
	{
		// sanity checks
		CHECK_STATE(STATE_MINT_TOKEN);

		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}
	{
		mint_token_amount_t* token = &subctx->stateData.token;

		// parse data
		TRACE_BUFFER(wireDataBuffer, wireDataSize);
		read_view_t view = make_read_view(wireDataBuffer, wireDataBuffer + wireDataSize);

		VALIDATE(view_remainingSize(&view) >= 4, ERR_INVALID_DATA);
		token->assetNameSize = parse_u4be(&view);
		VALIDATE(token->assetNameSize <= ASSET_NAME_SIZE_MAX, ERR_INVALID_DATA);

		ASSERT(token->assetNameSize <= SIZEOF(token->assetNameBytes));
		view_memmove(token->assetNameBytes, &view, token->assetNameSize);

		VALIDATE(view_remainingSize(&view) == 8, ERR_INVALID_DATA);
		token->amount = (int64_t)parse_u8be(&view);
		TRACE_INT64(token->amount);
	}

	{
		// select UI step
		switch (subctx->mintSecurityPolicy) {	//TODO where
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
		txHashBuilder_addMint_token(
		        txHashBuilder,
		        subctx->stateData.token.assetNameBytes, subctx->stateData.token.assetNameSize,
		        subctx->stateData.token.amount
		);
		TRACE();
	}

	signTxMint_handleToken_ui_runStep();
}

enum {
	HANDLE_CONFIRM_STEP_FINAL_CONFIRM = 6360,
	HANDLE_CONFIRM_STEP_RESPOND,
	HANDLE_CONFIRM_STEP_INVALID,
};

static void signTxMint_handleConfirm_ui_runStep()
{
	TRACE("UI step %d", subctx->ui_step);
	ui_callback_fn_t* this_fn = signTxMint_handleConfirm_ui_runStep;

	UI_STEP_BEGIN(subctx->ui_step, this_fn);

	UI_STEP(HANDLE_CONFIRM_STEP_FINAL_CONFIRM) {
		ui_displayPrompt(
		        "Confirm mint?",
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

static void signTxMint_handleConfirmAPDU(uint8_t* wireDataBuffer MARK_UNUSED, size_t wireDataSize)
{
	{
		//sanity checks
		CHECK_STATE(STATE_MINT_CONFIRM);

		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}

	{
		// no data to receive
		VALIDATE(wireDataSize == 0, ERR_INVALID_DATA);
	}

	security_policy_t policy = policyForSignTxMintConfirm(subctx->mintSecurityPolicy);
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

	signTxMint_handleConfirm_ui_runStep();
}

enum {
	APDU_INSTRUCTION_TOP_LEVEL_DATA = 0x30,
	APDU_INSTRUCTION_ASSET_GROUP = 0x31,
	APDU_INSTRUCTION_TOKEN = 0x32,
	APDU_INSTRUCTION_CONFIRM = 0x33,
};

bool signTxMint_isValidInstruction(uint8_t p2)
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

void signTxMint_init()
{
	{
		ins_sign_tx_body_context_t* txBodyCtx = &(instructionState.signTxContext.txPartCtx.body_ctx);
		explicit_bzero(&txBodyCtx->stageContext, SIZEOF(txBodyCtx->stageContext));
	}

	subctx->state = STATE_MINT_TOP_LEVEL_DATA;
}

void signTxMint_handleAPDU(uint8_t p2, uint8_t* wireDataBuffer, size_t wireDataSize)
{
	switch (p2) {
	case APDU_INSTRUCTION_TOP_LEVEL_DATA:
		signTxMint_handleTopLevelDataAPDU(wireDataBuffer, wireDataSize);
		break;

	case APDU_INSTRUCTION_ASSET_GROUP:
		signTxMint_handleAssetGroupAPDU(wireDataBuffer, wireDataSize);
		break;

	case APDU_INSTRUCTION_TOKEN:
		signTxMint_handleTokenAPDU(wireDataBuffer, wireDataSize);
		break;

	case APDU_INSTRUCTION_CONFIRM:
		signTxMint_handleConfirmAPDU(wireDataBuffer, wireDataSize);
		break;

	default:
		// this is not supposed to be called with invalid p2
		ASSERT(false);
	}
}

bool signTxMint_isFinished()
{
	TRACE("Mint submachine state: %d", subctx->state);
	// we are also asserting that the state is valid
	switch (subctx->state) {
	case STATE_MINT_FINISHED:
		return true;

	case STATE_MINT_TOP_LEVEL_DATA:
	case STATE_MINT_ASSET_GROUP:
	case STATE_MINT_TOKEN:
	case STATE_MINT_CONFIRM:
		return false;

	default:
		ASSERT(false);
	}
}
