#include "signTxMint.h"
#include "signTxMint_ui.h"
#include "signTxUtils.h"
#include "state.h"
#include "uiHelpers.h"
#include "utils.h"
#include "textUtils.h"
#include "securityPolicy.h"
#include "tokens.h"

#ifdef HAVE_BAGL
#include "uiScreens_bagl.h"
#elif defined(HAVE_NBGL)
#include "uiScreens_nbgl.h"
#endif

static common_tx_data_t* commonTxData = &(instructionState.signTxContext.commonTxData);

static mint_context_t* accessSubcontext()
{
	return &BODY_CTX->stageContext.mint_subctx;
}

static inline void CHECK_STATE(sign_tx_mint_state_t expected)
{
	mint_context_t* subctx = accessSubcontext();
	TRACE("Mint submachine state: current %d, expected %d", subctx->state, expected);
	VALIDATE(subctx->state == expected, ERR_INVALID_STATE);
}

static void signTxMint_handleTopLevelDataAPDU(const uint8_t* wireDataBuffer, size_t wireDataSize)
{
	{
		// safety checks
		CHECK_STATE(STATE_MINT_TOP_LEVEL_DATA);
		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}
	TRACE_BUFFER(wireDataBuffer, wireDataSize);
	mint_context_t* subctx = accessSubcontext();
	{
		read_view_t view = make_read_view(wireDataBuffer, wireDataBuffer + wireDataSize);

		uint32_t numAssetGroups = parse_u4be(&view);
		TRACE("num asset groups %u", numAssetGroups);
		VALIDATE(numAssetGroups <= OUTPUT_ASSET_GROUPS_MAX, ERR_INVALID_DATA);
		VALIDATE(numAssetGroups > 0, ERR_INVALID_DATA);

		STATIC_ASSERT(OUTPUT_ASSET_GROUPS_MAX <= UINT16_MAX, "wrong max token groups");
		ASSERT_TYPE(subctx->numAssetGroups, uint16_t);
		subctx->numAssetGroups = (uint16_t) numAssetGroups;

		VALIDATE(view_remainingSize(&view) == 0, ERR_INVALID_DATA);
	}
	subctx->mintSecurityPolicy = policyForSignTxMintInit(commonTxData->txSigningMode);
	ENSURE_NOT_DENIED(subctx->mintSecurityPolicy);

	txHashBuilder_addMint_topLevelData(&BODY_CTX->txHashBuilder, subctx->numAssetGroups);

	subctx->ui_step = HANDLE_MINT_TOP_LEVEL_DATA_DISPLAY;
	signTxMint_handleTopLevelData_ui_runStep();
}

static void signTxMint_handleAssetGroupAPDU(const uint8_t* wireDataBuffer, size_t wireDataSize)
{
	{
		// sanity checks
		CHECK_STATE(STATE_MINT_ASSET_GROUP);

		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}
	mint_context_t* subctx = accessSubcontext();
	{
		token_group_t* tokenGroup = &subctx->stateData.tokenGroup;

		// parse data
		TRACE_BUFFER(wireDataBuffer, wireDataSize);
		read_view_t view = make_read_view(wireDataBuffer, wireDataBuffer + wireDataSize);

		uint8_t candidatePolicyId[MINTING_POLICY_ID_SIZE] = {0};
		view_parseBuffer(candidatePolicyId, &view, MINTING_POLICY_ID_SIZE);

		if (subctx->currentAssetGroup > 0) {
			// compare with previous value before overwriting it
			VALIDATE(cbor_mapKeyFulfillsCanonicalOrdering(
			                 tokenGroup->policyId, MINTING_POLICY_ID_SIZE,
			                 candidatePolicyId, MINTING_POLICY_ID_SIZE
			         ), ERR_INVALID_DATA);
		}

		STATIC_ASSERT(SIZEOF(tokenGroup->policyId) >= MINTING_POLICY_ID_SIZE, "wrong policyId length");
		memmove(tokenGroup->policyId, candidatePolicyId, MINTING_POLICY_ID_SIZE);

		uint32_t numTokens = parse_u4be(&view);
		VALIDATE(numTokens <= OUTPUT_TOKENS_IN_GROUP_MAX, ERR_INVALID_DATA);
		VALIDATE(numTokens > 0, ERR_INVALID_DATA);
		STATIC_ASSERT(OUTPUT_TOKENS_IN_GROUP_MAX <= UINT16_MAX, "wrong max token amounts in a group");
		ASSERT_TYPE(subctx->numTokens, uint16_t);
		subctx->numTokens = (uint16_t) numTokens;

		VALIDATE(view_remainingSize(&view) == 0, ERR_INVALID_DATA);
	}

	{
		// add token group to tx
		TRACE("Adding token group hash to tx hash");
		txHashBuilder_addMint_tokenGroup(
		        &BODY_CTX->txHashBuilder,
		        subctx->stateData.tokenGroup.policyId, MINTING_POLICY_ID_SIZE,
		        subctx->numTokens
		);
		TRACE();
	}

	subctx->ui_step = HANDLE_ASSET_GROUP_STEP_RESPOND;
	signTxMint_handleAssetGroup_ui_runStep();
}

static void signTxMint_handleTokenAPDU(const uint8_t* wireDataBuffer, size_t wireDataSize)
{
	{
		// sanity checks
		CHECK_STATE(STATE_MINT_TOKEN);

		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}
	mint_context_t* subctx = accessSubcontext();
	{
		mint_token_amount_t* token = &subctx->stateData.token;

		// parse data
		TRACE_BUFFER(wireDataBuffer, wireDataSize);
		read_view_t view = make_read_view(wireDataBuffer, wireDataBuffer + wireDataSize);

		const size_t candidateAssetNameSize = parse_u4be(&view);
		VALIDATE(candidateAssetNameSize <= ASSET_NAME_SIZE_MAX, ERR_INVALID_DATA);
		uint8_t candidateAssetNameBytes[ASSET_NAME_SIZE_MAX] = {0};
		view_parseBuffer(candidateAssetNameBytes, &view, candidateAssetNameSize);

		if (subctx->currentToken > 0) {
			// compare with previous value before overwriting it
			VALIDATE(cbor_mapKeyFulfillsCanonicalOrdering(
			                 token->assetNameBytes, token->assetNameSize,
			                 candidateAssetNameBytes, candidateAssetNameSize
			         ), ERR_INVALID_DATA);
		}

		token->assetNameSize = candidateAssetNameSize;
		STATIC_ASSERT(SIZEOF(token->assetNameBytes) >= ASSET_NAME_SIZE_MAX, "wrong asset name buffer size");
		memmove(token->assetNameBytes, candidateAssetNameBytes, candidateAssetNameSize);

		token->amount = parse_int64be(&view);
		TRACE_INT64(token->amount);

		VALIDATE(view_remainingSize(&view) == 0, ERR_INVALID_DATA);
	}

	{
		// select UI step
		switch (subctx->mintSecurityPolicy) {
#define  CASE(POLICY, UI_STEP) case POLICY: {subctx->ui_step=UI_STEP; break;}
			CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_TOKEN_STEP_DISPLAY_NAME);
			CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_TOKEN_STEP_RESPOND);
#undef   CASE
		default:
			THROW(ERR_NOT_IMPLEMENTED);
		}
	}

	{
		// add token group to tx
		TRACE("Adding token group hash to tx hash");
		txHashBuilder_addMint_token(
		        &BODY_CTX->txHashBuilder,
		        subctx->stateData.token.assetNameBytes, subctx->stateData.token.assetNameSize,
		        subctx->stateData.token.amount
		);
		TRACE();
	}

	signTxMint_handleToken_ui_runStep();
}

static void signTxMint_handleConfirmAPDU(const uint8_t* wireDataBuffer MARK_UNUSED, size_t wireDataSize)
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

	mint_context_t* subctx = accessSubcontext();
	security_policy_t policy = policyForSignTxMintConfirm(subctx->mintSecurityPolicy);
	TRACE("Policy: %d", (int) policy);
	ENSURE_NOT_DENIED(policy);

	{
		// select UI step
		switch (policy) {
#define  CASE(POLICY, UI_STEP) case POLICY: {subctx->ui_step=UI_STEP; break;}
			CASE(POLICY_PROMPT_BEFORE_RESPONSE, HANDLE_CONFIRM_STEP_FINAL_CONFIRM);
			CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_CONFIRM_STEP_RESPOND);
#undef   CASE
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
		explicit_bzero(&BODY_CTX->stageContext, SIZEOF(BODY_CTX->stageContext));
	}

	accessSubcontext()->state = STATE_MINT_TOP_LEVEL_DATA;
}

void signTxMint_handleAPDU(uint8_t p2, const uint8_t* wireDataBuffer, size_t wireDataSize)
{
	ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);

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
	mint_context_t* subctx = accessSubcontext();
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
