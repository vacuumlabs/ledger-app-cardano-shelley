#include "signTx.h"
#include "state.h"
#include "cardano.h"
#include "addressUtilsShelley.h"
#include "keyDerivation.h"
#include "uiHelpers.h"
#include "signTxUtils.h"
#include "uiScreens.h"
#include "txHashBuilder.h"
#include "textUtils.h"
#include "hexUtils.h"
#include "bufView.h"
#include "securityPolicy.h"
#include "signTxPoolRegistration.h"

// we want to distinguish the two state machines to avoid potential confusion:
// ctx / subctx
// stage / state
// from ctx, we only make the necessary parts available to avoid mistaken overwrites
static pool_registration_context_t* subctx = &(instructionState.signTxContext.stageContext.pool_registration_subctx);
static common_tx_data_t* commonTxData = &(instructionState.signTxContext.commonTxData);
static tx_hash_builder_t* txHashBuilder = &(instructionState.signTxContext.txHashBuilder);

bool signTxPoolRegistration_isFinished()
{
	// we are also asserting that the state is valid
	switch (subctx->state) {
	case STAKE_POOL_REGISTRATION_FINISHED:
		return true;

	case STAKE_POOL_REGISTRATION_INIT:
	case STAKE_POOL_REGISTRATION_POOL_KEY:
	case STAKE_POOL_REGISTRATION_VRF_KEY:
	case STAKE_POOL_REGISTRATION_FINANCIALS:
	case STAKE_POOL_REGISTRATION_REWARD_ACCOUNT:
	case STAKE_POOL_REGISTRATION_OWNERS:
	case STAKE_POOL_REGISTRATION_RELAYS:
	case STAKE_POOL_REGISTRATION_METADATA:
	case STAKE_POOL_REGISTRATION_CONFIRM:
		return false;

	default:
		ASSERT(false);
	}
}

void signTxPoolRegistration_init()
{
	{
		ins_sign_tx_context_t* ctx = &(instructionState.signTxContext);
		explicit_bzero(&ctx->stageContext.pool_registration_subctx, SIZEOF(ctx->stageContext.pool_registration_subctx));
	}
	subctx->state = STAKE_POOL_REGISTRATION_INIT;
}

static inline void CHECK_STATE(sign_tx_pool_registration_state_t expected)
{
	TRACE("Pool registration certificate stage: current %d, expected %d", subctx->state, expected);
	VALIDATE(subctx->state == expected, ERR_INVALID_STATE);
}

static inline void advanceState()
{
	TRACE("Advancing pool registration certificate state from: %d", subctx->state);

	switch (subctx->state) {

	case STAKE_POOL_REGISTRATION_INIT:
		subctx->state = STAKE_POOL_REGISTRATION_POOL_KEY;
		break;

	case STAKE_POOL_REGISTRATION_POOL_KEY:
		subctx->state = STAKE_POOL_REGISTRATION_VRF_KEY;
		break;

	case STAKE_POOL_REGISTRATION_VRF_KEY:
		subctx->state = STAKE_POOL_REGISTRATION_FINANCIALS;
		break;

	case STAKE_POOL_REGISTRATION_FINANCIALS:
		subctx->state = STAKE_POOL_REGISTRATION_REWARD_ACCOUNT;
		break;

	case STAKE_POOL_REGISTRATION_REWARD_ACCOUNT:
		txHashBuilder_addPoolRegistrationCertificate_enterOwners(txHashBuilder);
		subctx->state = STAKE_POOL_REGISTRATION_OWNERS;

		if (subctx->numOwners > 0) {
			break;
		}

	// intentional fallthrough

	case STAKE_POOL_REGISTRATION_OWNERS:
		ASSERT(subctx->currentOwner == subctx->numOwners);

		txHashBuilder_addPoolRegistrationCertificate_enterRelays(txHashBuilder);
		subctx->state = STAKE_POOL_REGISTRATION_RELAYS;

		if (subctx->numRelays > 0) {
			break;
		}

	// intentional fallthrough

	case STAKE_POOL_REGISTRATION_RELAYS:
		ASSERT(subctx->currentRelay == subctx->numRelays);

		subctx->state = STAKE_POOL_REGISTRATION_METADATA;
		break;

	case STAKE_POOL_REGISTRATION_METADATA:
		subctx->state = STAKE_POOL_REGISTRATION_CONFIRM;
		break;

	case STAKE_POOL_REGISTRATION_CONFIRM:
		subctx->state = STAKE_POOL_REGISTRATION_FINISHED;
		break;

	default:
		ASSERT(false);
	}

	TRACE("Advancing pool registration certificate state to: %d", subctx->state);
}


// ============================== INIT ==============================

enum {
	HANDLE_POOL_INIT_STEP_DISPLAY = 6100,
	HANDLE_POOL_INIT_STEP_RESPOND,
	HANDLE_POOL_INIT_STEP_INVALID,
} ;

static void handlePoolInit_ui_runStep()
{
	TRACE("UI step %d", subctx->ui_step);
	TRACE_STACK_USAGE();
	ui_callback_fn_t* this_fn = handlePoolInit_ui_runStep;

	UI_STEP_BEGIN(subctx->ui_step, this_fn);

	UI_STEP(HANDLE_POOL_INIT_STEP_DISPLAY) {
		ui_displayPaginatedText(
		        "Pool registration",
		        "certificate",
		        this_fn
		);
	}
	UI_STEP(HANDLE_POOL_INIT_STEP_RESPOND) {
		respondSuccessEmptyMsg();
		advanceState();
	}
	UI_STEP_END(HANDLE_POOL_INIT_STEP_INVALID);
}

__noinline_due_to_stack__
static void signTxPoolRegistration_handleInitAPDU(uint8_t* wireDataBuffer, size_t wireDataSize)
{
	TRACE_STACK_USAGE();
	{
		// sanity checks
		CHECK_STATE(STAKE_POOL_REGISTRATION_INIT);

		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}
	{
		// initialization
		subctx->currentOwner = 0;
		subctx->currentRelay = 0;

		explicit_bzero(&subctx->stateData, SIZEOF(subctx->stateData));
	}
	{
		// parse data
		TRACE_BUFFER(wireDataBuffer, wireDataSize);

		struct {
			uint8_t numOwners[4];
			uint8_t numRelays[4];
		}* wireHeader = (void*) wireDataBuffer;

		VALIDATE(wireDataSize == SIZEOF(*wireHeader), ERR_INVALID_DATA);

		uint64_t numOwners = u4be_read(wireHeader->numOwners);
		uint64_t numRelays = u4be_read(wireHeader->numRelays);
		TRACE(
		        "num owners, relays: %d %d",
		        subctx->numOwners, subctx->numRelays
		);

		VALIDATE(subctx->numOwners <= POOL_MAX_OWNERS, ERR_INVALID_DATA);
		VALIDATE(subctx->numRelays <= POOL_MAX_RELAYS, ERR_INVALID_DATA);
		ASSERT_TYPE(subctx->numOwners, uint16_t);
		ASSERT_TYPE(subctx->numRelays, uint16_t);
		subctx->numOwners = (uint16_t) numOwners;
		subctx->numRelays = (uint16_t) numRelays;

		switch (commonTxData->signTxUsecase) {
		case SIGN_TX_USECASE_POOL_REGISTRATION_OWNER:
			// there should be exactly one owner given by path for which we provide a witness
			VALIDATE(subctx->numOwners >= 1, ERR_INVALID_DATA);
			break;

		default:
			// nothing to validate in other cases
			break;
		}
	}
	{
		txHashBuilder_poolRegistrationCertificate_enter(
		        txHashBuilder,
		        subctx->numOwners, subctx->numRelays
		);
	}

	subctx->ui_step = HANDLE_POOL_INIT_STEP_DISPLAY;
	handlePoolInit_ui_runStep();
}

// ============================== POOL KEY HASH / ID ==============================

__noinline_due_to_stack__
static void _calculatePooKeyHash(const pool_id_t* poolId, uint8_t* poolKeyHash)
{
	switch (poolId->keyReferenceType) {

	case KEY_REFERENCE_HASH: {
		STATIC_ASSERT(SIZEOF(poolId->hash) == POOL_KEY_HASH_LENGTH, "wrong pool key hash length");
		os_memmove(poolKeyHash, poolId->hash, POOL_KEY_HASH_LENGTH);
		break;
	}
	case KEY_REFERENCE_PATH: {
		extendedPublicKey_t extPubKey;
		deriveExtendedPublicKey(&poolId->path, &extPubKey);

		STATIC_ASSERT(POOL_KEY_HASH_LENGTH * 8 == 224, "wrong pool key hash length");
		blake2b_224_hash(
		        extPubKey.pubKey, SIZEOF(extPubKey.pubKey),
		        poolKeyHash, POOL_KEY_HASH_LENGTH
		);
		break;
	}
	default:
		ASSERT(false);
	}
}

enum {
	HANDLE_POOL_KEY_STEP_DISPLAY_POOL_PATH = 6200,
	HANDLE_POOL_KEY_STEP_DISPLAY_POOL_ID,
	HANDLE_POOL_KEY_STEP_RESPOND,
	HANDLE_POOL_KEY_STEP_INVALID,
} ;

static void handlePoolKey_ui_runStep()
{
	TRACE("UI step %d", subctx->ui_step);
	TRACE_STACK_USAGE();
	ui_callback_fn_t* this_fn = handlePoolKey_ui_runStep;

	UI_STEP_BEGIN(subctx->ui_step, this_fn);

	UI_STEP(HANDLE_POOL_KEY_STEP_DISPLAY_POOL_PATH) {
		ui_displayPathScreen(
		        "Pool ID path",
		        &subctx->stateData.poolId.path,
		        this_fn
		);
	}
	UI_STEP(HANDLE_POOL_KEY_STEP_DISPLAY_POOL_ID) {
		uint8_t poolKeyHash[POOL_KEY_HASH_LENGTH];
		_calculatePooKeyHash(&subctx->stateData.poolId, poolKeyHash);

		ui_displayBech32Screen(
		        "Pool ID",
		        "pool_vk",
		        poolKeyHash, SIZEOF(poolKeyHash),
		        this_fn
		);
	}
	UI_STEP(HANDLE_POOL_KEY_STEP_RESPOND) {
		respondSuccessEmptyMsg();
		advanceState();
	}
	UI_STEP_END(HANDLE_POOL_KEY_STEP_INVALID);
}

static void _parsePoolId(read_view_t* view)
{
	pool_id_t* key = &subctx->stateData.poolId;

	VALIDATE(view_remainingSize(view) >= 1, ERR_INVALID_DATA);
	key->keyReferenceType = parse_u1be(view);

	switch (key->keyReferenceType) {

	case KEY_REFERENCE_HASH:
		VALIDATE(view_remainingSize(view) >= POOL_KEY_HASH_LENGTH, ERR_INVALID_DATA);
		STATIC_ASSERT(SIZEOF(key->hash) == POOL_KEY_HASH_LENGTH, "wrong pool id key hash size");
		view_memmove(key->hash, view, POOL_KEY_HASH_LENGTH);
		TRACE_BUFFER(key->hash, SIZEOF(key->hash));
		break;

	case KEY_REFERENCE_PATH:
		VALIDATE(view_remainingSize(view) > 0, ERR_INVALID_DATA);
		view_skipBytes(view, bip44_parseFromWire(&key->path, VIEW_REMAINING_TO_TUPLE_BUF_SIZE(view)));
		BIP44_PRINTF(&key->path);
		PRINTF("\n");
		break;

	default:
		THROW(ERR_INVALID_DATA);
	}
}

__noinline_due_to_stack__
static void signTxPoolRegistration_handlePoolKeyAPDU(uint8_t* wireDataBuffer, size_t wireDataSize)
{
	TRACE_STACK_USAGE();
	{
		// sanity checks
		CHECK_STATE(STAKE_POOL_REGISTRATION_POOL_KEY);

		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}
	{
		// parse data

		TRACE_BUFFER(wireDataBuffer, wireDataSize);

		read_view_t view = make_read_view(wireDataBuffer, wireDataBuffer + wireDataSize);

		_parsePoolId(&view);

		VALIDATE(view_remainingSize(&view) == 0, ERR_INVALID_DATA);
	}

	security_policy_t policy = policyForSignTxStakePoolRegistrationPoolId(
	                                   commonTxData->signTxUsecase,
	                                   &subctx->stateData.poolId
	                           );
	TRACE("Policy: %d", (int) policy);
	ENSURE_NOT_DENIED(policy);

	{
		// key derivation must not be done before DENY security policy is enforced
		uint8_t poolKeyHash[POOL_KEY_HASH_LENGTH];
		_calculatePooKeyHash(&subctx->stateData.poolId, poolKeyHash);

		txHashBuilder_poolRegistrationCertificate_poolKeyHash(
		        txHashBuilder,
		        poolKeyHash, SIZEOF(poolKeyHash)
		);
	}
	{
		// ui step depends not only on security policy, but also on usecase
		int displayUiStep = HANDLE_POOL_KEY_STEP_INVALID;
		switch (commonTxData->signTxUsecase) {
		case SIGN_TX_USECASE_POOL_REGISTRATION_OWNER:
			displayUiStep = HANDLE_POOL_KEY_STEP_DISPLAY_POOL_ID;
			break;

		case SIGN_TX_USECASE_POOL_REGISTRATION_OPERATOR:
			displayUiStep = HANDLE_POOL_KEY_STEP_DISPLAY_POOL_PATH;
			break;

		default:
			ASSERT(false);
		}
		ASSERT(displayUiStep != HANDLE_POOL_KEY_STEP_INVALID);

		// select UI steps
		switch (policy) {
#	define  CASE(POLICY, UI_STEP) case POLICY: {subctx->ui_step=UI_STEP; break;}
			CASE(POLICY_SHOW_BEFORE_RESPONSE, displayUiStep);
			CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_POOL_KEY_STEP_RESPOND);
#	undef   CASE
		default:
			THROW(ERR_NOT_IMPLEMENTED);
		}
	}

	handlePoolKey_ui_runStep();
}

// ============================== VRF KEY HASH ==============================

enum {
	HANDLE_POOL_VRF_KEY_STEP_DISPLAY = 6300,
	HANDLE_POOL_VRF_KEY_STEP_RESPOND,
	HANDLE_POOL_VRF_KEY_STEP_INVALID,
} ;

static void handlePoolVrfKey_ui_runStep()
{
	TRACE("UI step %d", subctx->ui_step);
	TRACE_STACK_USAGE();
	ui_callback_fn_t* this_fn = handlePoolVrfKey_ui_runStep;

	UI_STEP_BEGIN(subctx->ui_step, this_fn);

	UI_STEP(HANDLE_POOL_VRF_KEY_STEP_DISPLAY) {
		ui_displayBech32Screen(
		        "VRF key hash",
		        "vrf_vk",
		        subctx->stateData.vrfKeyHash, SIZEOF(subctx->stateData.vrfKeyHash),
		        this_fn
		);
	}
	UI_STEP(HANDLE_POOL_VRF_KEY_STEP_RESPOND) {
		respondSuccessEmptyMsg();
		advanceState();
	}
	UI_STEP_END(HANDLE_POOL_VRF_KEY_STEP_INVALID);
}

__noinline_due_to_stack__
static void signTxPoolRegistration_handleVrfKeyAPDU(uint8_t* wireDataBuffer, size_t wireDataSize)
{
	TRACE_STACK_USAGE();
	{
		// sanity checks
		CHECK_STATE(STAKE_POOL_REGISTRATION_VRF_KEY);

		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}
	{
		// parse data

		TRACE_BUFFER(wireDataBuffer, wireDataSize);

		VALIDATE(wireDataSize == SIZEOF(subctx->stateData.vrfKeyHash), ERR_INVALID_DATA);

		{
			STATIC_ASSERT(SIZEOF(subctx->stateData.vrfKeyHash) == VRF_KEY_HASH_LENGTH, "wrong vrfKeyHash size");
			os_memmove(subctx->stateData.vrfKeyHash, wireDataBuffer, VRF_KEY_HASH_LENGTH);
			// nothing to validate, all values are valid
		}
	}

	security_policy_t policy = policyForSignTxStakePoolRegistrationVrfKey(
	                                   commonTxData->signTxUsecase
	                           );
	TRACE("Policy: %d", (int) policy);
	ENSURE_NOT_DENIED(policy);

	txHashBuilder_poolRegistrationCertificate_vrfKeyHash(
	        txHashBuilder,
	        subctx->stateData.vrfKeyHash, SIZEOF(subctx->stateData.vrfKeyHash)
	);

	{
		// select UI steps
		switch (policy) {
#	define  CASE(POLICY, UI_STEP) case POLICY: {subctx->ui_step=UI_STEP; break;}
			CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_POOL_VRF_KEY_STEP_DISPLAY);
			CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_POOL_VRF_KEY_STEP_RESPOND);
#	undef   CASE
		default:
			THROW(ERR_NOT_IMPLEMENTED);
		}
	}

	handlePoolVrfKey_ui_runStep();
}

// ============================== POOL FINANCIALS ==============================

enum {
	HANDLE_POOL_FINANCIALS_STEP_DISPLAY_PLEDGE = 6400,
	HANDLE_POOL_FINANCIALS_STEP_DISPLAY_COST,
	HANDLE_POOL_FINANCIALS_STEP_DISPLAY_MARGIN,
	HANDLE_POOL_FINANCIALS_STEP_RESPOND,
	HANDLE_POOL_FINANCIALS_STEP_INVALID,
} ;

static void handlePoolFinancials_ui_runStep()
{
	TRACE("UI step %d", subctx->ui_step);
	TRACE_STACK_USAGE();
	ui_callback_fn_t* this_fn = handlePoolFinancials_ui_runStep;

	UI_STEP_BEGIN(subctx->ui_step, this_fn);

	UI_STEP(HANDLE_POOL_FINANCIALS_STEP_DISPLAY_PLEDGE) {
		ui_displayAdaAmountScreen(
		        "Pledge",
		        subctx->stateData.pledge,
		        this_fn
		);
	}
	UI_STEP(HANDLE_POOL_FINANCIALS_STEP_DISPLAY_COST) {
		ui_displayAdaAmountScreen(
		        "Cost",
		        subctx->stateData.cost,
		        this_fn
		);
	}
	UI_STEP(HANDLE_POOL_FINANCIALS_STEP_DISPLAY_MARGIN) {
		ui_displayPoolMarginScreen(
		        subctx->stateData.marginNumerator,
		        subctx->stateData.marginDenominator,
		        this_fn
		);
	}
	UI_STEP(HANDLE_POOL_FINANCIALS_STEP_RESPOND) {
		respondSuccessEmptyMsg();
		advanceState();
	}
	UI_STEP_END(HANDLE_POOL_FINANCIALS_STEP_INVALID);
}

__noinline_due_to_stack__
static void signTxPoolRegistration_handlePoolFinancialsAPDU(uint8_t* wireDataBuffer, size_t wireDataSize)
{
	TRACE_STACK_USAGE();
	{
		// sanity checks
		CHECK_STATE(STAKE_POOL_REGISTRATION_FINANCIALS);

		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}
	{
		// parse data

		TRACE_BUFFER(wireDataBuffer, wireDataSize);

		struct {
			uint8_t pledge[8];
			uint8_t cost[8];
			uint8_t marginNumerator[8];
			uint8_t marginDenominator[8];
		}* wireHeader = (void*) wireDataBuffer;

		VALIDATE(wireDataSize == SIZEOF(*wireHeader), ERR_INVALID_DATA);

		{
			ASSERT_TYPE(subctx->stateData.pledge, uint64_t);
			subctx->stateData.pledge = u8be_read(wireHeader->pledge);
			TRACE_ADA_AMOUNT("pledge ", subctx->stateData.pledge);
			VALIDATE(subctx->stateData.pledge < LOVELACE_MAX_SUPPLY, ERR_INVALID_DATA);

			ASSERT_TYPE(subctx->stateData.cost, uint64_t);
			subctx->stateData.cost = u8be_read(wireHeader->cost);
			TRACE_ADA_AMOUNT("cost ", subctx->stateData.cost);
			VALIDATE(subctx->stateData.cost < LOVELACE_MAX_SUPPLY, ERR_INVALID_DATA);

			ASSERT_TYPE(subctx->stateData.marginNumerator, uint64_t);
			subctx->stateData.marginNumerator = u8be_read(wireHeader->marginNumerator);
			TRACE_BUFFER((uint8_t *) &subctx->stateData.marginNumerator, 8);
			VALIDATE(subctx->stateData.marginNumerator <= MARGIN_DENOMINATOR_MAX, ERR_INVALID_DATA);

			ASSERT_TYPE(subctx->stateData.marginDenominator, uint64_t);
			subctx->stateData.marginDenominator = u8be_read(wireHeader->marginDenominator);
			TRACE_BUFFER((uint8_t *) &subctx->stateData.marginDenominator, 8);
			VALIDATE(subctx->stateData.marginDenominator != 0, ERR_INVALID_DATA);
			VALIDATE(subctx->stateData.marginDenominator <= MARGIN_DENOMINATOR_MAX, ERR_INVALID_DATA);
			VALIDATE(subctx->stateData.marginNumerator <= subctx->stateData.marginDenominator, ERR_INVALID_DATA);
		}
	}
	{
		txHashBuilder_poolRegistrationCertificate_financials(
		        txHashBuilder,
		        subctx->stateData.pledge, subctx->stateData.cost,
		        subctx->stateData.marginNumerator, subctx->stateData.marginDenominator
		);
	}

	subctx->ui_step = HANDLE_POOL_FINANCIALS_STEP_DISPLAY_PLEDGE;
	handlePoolFinancials_ui_runStep();
}

// ============================== POOL REWARD ACCOUNT ==============================

__noinline_due_to_stack__
static void _calculateRewardAccount(
        const pool_reward_account_t* rewardAccount,
        uint8_t* rewardAccountBuffer
)
{
	switch (rewardAccount->keyReferenceType) {

	case KEY_REFERENCE_HASH: {
		STATIC_ASSERT(SIZEOF(rewardAccount->buffer) == REWARD_ACCOUNT_SIZE, "wrong reward account size");
		os_memmove(rewardAccountBuffer, rewardAccount->buffer, REWARD_ACCOUNT_SIZE);
		break;
	}
	case KEY_REFERENCE_PATH: {
		constructRewardAddressFromKeyPath(
		        &rewardAccount->path, commonTxData->networkId,
		        rewardAccountBuffer, REWARD_ACCOUNT_SIZE
		);
		break;
	}
	default:
		ASSERT(false);
	}
}

enum {
	HANDLE_POOL_REWARD_ACCOUNT_STEP_DISPLAY_PATH = 6500,
	HANDLE_POOL_REWARD_ACCOUNT_STEP_DISPLAY_HASH,
	HANDLE_POOL_REWARD_ACCOUNT_STEP_RESPOND,
	HANDLE_POOL_REWARD_ACCOUNT_STEP_INVALID,
};

static void handlePoolRewardAccount_ui_runStep()
{
	TRACE("UI step %d", subctx->ui_step);
	TRACE_STACK_USAGE();
	ui_callback_fn_t* this_fn = handlePoolRewardAccount_ui_runStep;

	UI_STEP_BEGIN(subctx->ui_step, this_fn);

	UI_STEP(HANDLE_POOL_REWARD_ACCOUNT_STEP_DISPLAY_PATH) {
		ASSERT(subctx->stateData.poolRewardAccount.keyReferenceType == KEY_REFERENCE_PATH);

		ui_displayPathScreen(
		        "Reward account",
		        &subctx->stateData.poolRewardAccount.path,
		        this_fn
		);
	}
	UI_STEP(HANDLE_POOL_REWARD_ACCOUNT_STEP_DISPLAY_HASH) {
		uint8_t rewardAccountBuffer[REWARD_ACCOUNT_SIZE];
		_calculateRewardAccount(&subctx->stateData.poolRewardAccount, rewardAccountBuffer);

		ui_displayAddressScreen(
		        "Reward account",
		        rewardAccountBuffer,
		        SIZEOF(rewardAccountBuffer),
		        this_fn
		);
	}
	UI_STEP(HANDLE_POOL_REWARD_ACCOUNT_STEP_RESPOND) {
		respondSuccessEmptyMsg();
		advanceState();
	}
	UI_STEP_END(HANDLE_POOL_REWARD_ACCOUNT_STEP_INVALID);
}

static void _parsePoolRewardAccount(read_view_t* view)
{
	pool_reward_account_t* rewardAccount = &subctx->stateData.poolRewardAccount;

	VALIDATE(view_remainingSize(view) >= 1, ERR_INVALID_DATA);
	rewardAccount->keyReferenceType = parse_u1be(view);

	switch (rewardAccount->keyReferenceType) {

	case KEY_REFERENCE_HASH:
		VALIDATE(view_remainingSize(view) >= REWARD_ACCOUNT_SIZE, ERR_INVALID_DATA);
		STATIC_ASSERT(SIZEOF(rewardAccount->buffer) == REWARD_ACCOUNT_SIZE, "wrong reward account size");
		view_memmove(rewardAccount->buffer, view, REWARD_ACCOUNT_SIZE);
		TRACE_BUFFER(rewardAccount->buffer, SIZEOF(rewardAccount->buffer));

		const uint8_t header = getAddressHeader(rewardAccount->buffer, SIZEOF(rewardAccount->buffer));
		VALIDATE(getAddressType(header) == REWARD, ERR_INVALID_DATA);
		VALIDATE(getNetworkId(header) == commonTxData->networkId, ERR_INVALID_DATA);
		break;

	case KEY_REFERENCE_PATH:
		VALIDATE(view_remainingSize(view) > 0, ERR_INVALID_DATA);
		view_skipBytes(view, bip44_parseFromWire(&rewardAccount->path, VIEW_REMAINING_TO_TUPLE_BUF_SIZE(view)));
		BIP44_PRINTF(&rewardAccount->path);
		PRINTF("\n");
		break;

	default:
		THROW(ERR_INVALID_DATA);
	}
}

__noinline_due_to_stack__
static void signTxPoolRegistration_handleRewardAccountAPDU(uint8_t* wireDataBuffer, size_t wireDataSize)
{
	TRACE_STACK_USAGE();
	{
		// sanity checks
		CHECK_STATE(STAKE_POOL_REGISTRATION_REWARD_ACCOUNT);

		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}
	{
		// parse data

		TRACE_BUFFER(wireDataBuffer, wireDataSize);

		read_view_t view = make_read_view(wireDataBuffer, wireDataBuffer + wireDataSize);

		_parsePoolRewardAccount(&view);

		VALIDATE(view_remainingSize(&view) == 0, ERR_INVALID_DATA);
	}

	security_policy_t policy = policyForSignTxStakePoolRegistrationRewardAccount(
	                                   commonTxData->signTxUsecase,
	                                   &subctx->stateData.poolRewardAccount
	                           );
	TRACE("Policy: %d", (int) policy);
	ENSURE_NOT_DENIED(policy);

	{
		// key derivation must not be done before DENY security policy is enforced
		uint8_t rewardAccountBuffer[REWARD_ACCOUNT_SIZE];
		_calculateRewardAccount(&subctx->stateData.poolRewardAccount, rewardAccountBuffer);

		txHashBuilder_poolRegistrationCertificate_rewardAccount(
		        txHashBuilder,
		        rewardAccountBuffer, SIZEOF(rewardAccountBuffer)
		);
	}

	{
		// select UI steps
		int displayStep = HANDLE_POOL_REWARD_ACCOUNT_STEP_INVALID;
		switch (subctx->stateData.poolRewardAccount.keyReferenceType) {
		case KEY_REFERENCE_PATH:
			displayStep = HANDLE_POOL_REWARD_ACCOUNT_STEP_DISPLAY_PATH;
			break;
		case KEY_REFERENCE_HASH:
			displayStep = HANDLE_POOL_REWARD_ACCOUNT_STEP_DISPLAY_HASH;
			break;
		default:
			ASSERT(false);
		}
		ASSERT(displayStep != HANDLE_POOL_REWARD_ACCOUNT_STEP_INVALID);

		switch (policy) {
#	define  CASE(POLICY, UI_STEP) case POLICY: {subctx->ui_step=UI_STEP; break;}
			CASE(POLICY_SHOW_BEFORE_RESPONSE, displayStep);
			CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_POOL_REWARD_ACCOUNT_STEP_RESPOND);
#	undef   CASE
		default:
			THROW(ERR_NOT_IMPLEMENTED);
		}
	}

	handlePoolRewardAccount_ui_runStep();
}

// ============================== OWNER ==============================

enum {
	HANDLE_OWNER_STEP_DISPLAY = 6600,
	HANDLE_OWNER_STEP_RESPOND,
	HANDLE_OWNER_STEP_INVALID,
};

static void handleOwner_ui_runStep()
{
	TRACE("UI step %d", subctx->ui_step);
	TRACE_STACK_USAGE();
	ui_callback_fn_t* this_fn = handleOwner_ui_runStep;

	UI_STEP_BEGIN(subctx->ui_step, this_fn);

	UI_STEP(HANDLE_OWNER_STEP_DISPLAY) {
		ui_displayPoolOwnerScreen(&subctx->stateData.owner, subctx->currentOwner, commonTxData->networkId, this_fn);
	}
	UI_STEP(HANDLE_OWNER_STEP_RESPOND) {
		respondSuccessEmptyMsg();

		subctx->currentOwner++;
		if (subctx->currentOwner == subctx->numOwners) {
			switch (commonTxData->signTxUsecase) {
			case SIGN_TX_USECASE_POOL_REGISTRATION_OWNER:
				VALIDATE(subctx->numOwnersGivenByPath == 1, ERR_INVALID_DATA);
				break;

			case SIGN_TX_USECASE_POOL_REGISTRATION_OPERATOR:
				ASSERT(subctx->numOwnersGivenByPath == 0);
				break;

			default:
				ASSERT(false);
			}

			advanceState();
		}
	}
	UI_STEP_END(HANDLE_OWNER_STEP_INVALID);
}

__noinline_due_to_stack__
static void _addOwnerToTxHash()
{
	pool_owner_t* owner = &subctx->stateData.owner;

	uint8_t ownerKeyHash[ADDRESS_KEY_HASH_LENGTH];

	switch (owner->keyReferenceType) {
	case KEY_REFERENCE_PATH: {
		extendedPublicKey_t extPubKey;
		deriveExtendedPublicKey(&owner->path, &extPubKey);

		STATIC_ASSERT(SIZEOF(ownerKeyHash) * 8 == 224, "wrong owner key hash length");
		blake2b_224_hash(
		        extPubKey.pubKey, SIZEOF(extPubKey.pubKey),
		        ownerKeyHash, SIZEOF(ownerKeyHash)
		);
		break;
	}
	case KEY_REFERENCE_HASH: {
		os_memmove(ownerKeyHash, owner->keyHash, SIZEOF(ownerKeyHash));
		break;
	}
	default:
		ASSERT(false);
	}

	// add data to tx
	TRACE("Adding owner to tx hash");
	txHashBuilder_addPoolRegistrationCertificate_addOwner(
	        txHashBuilder,
	        ownerKeyHash, SIZEOF(ownerKeyHash)
	);
	TRACE();
}

__noinline_due_to_stack__
static void signTxPoolRegistration_handleOwnerAPDU(uint8_t* wireDataBuffer, size_t wireDataSize)
{
	TRACE_STACK_USAGE();
	{
		// sanity checks
		CHECK_STATE(STAKE_POOL_REGISTRATION_OWNERS);

		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}

	pool_owner_t* owner = &subctx->stateData.owner;

	explicit_bzero(owner, SIZEOF(*owner));

	{
		// parse data
		TRACE_BUFFER(wireDataBuffer, wireDataSize);

		read_view_t view = make_read_view(wireDataBuffer, wireDataBuffer + wireDataSize);

		VALIDATE(view_remainingSize(&view) >= 1, ERR_INVALID_DATA);
		owner->keyReferenceType = parse_u1be(&view);
		switch (owner->keyReferenceType) {

		case KEY_REFERENCE_HASH:
			VALIDATE(view_remainingSize(&view) == ADDRESS_KEY_HASH_LENGTH, ERR_INVALID_DATA);
			STATIC_ASSERT(SIZEOF(owner->keyHash) == ADDRESS_KEY_HASH_LENGTH, "wrong owner.keyHash size");
			os_memmove(owner->keyHash, VIEW_REMAINING_TO_TUPLE_BUF_SIZE(&view));
			TRACE_BUFFER(owner->keyHash, SIZEOF(owner->keyHash));
			break;

		case KEY_REFERENCE_PATH:
			view_skipBytes(&view, bip44_parseFromWire(&owner->path, VIEW_REMAINING_TO_TUPLE_BUF_SIZE(&view)));
			// further validation of the path in security policy below
			TRACE("Owner given by path:");
			BIP44_PRINTF(&owner->path);
			PRINTF("\n");
			VALIDATE(view_remainingSize(&view) == 0, ERR_INVALID_DATA);

			subctx->numOwnersGivenByPath++;
			VALIDATE(subctx->numOwnersGivenByPath <= 1, ERR_INVALID_DATA);

			break;

		default:
			THROW(ERR_INVALID_DATA);
		}
	}

	security_policy_t policy = policyForSignTxStakePoolRegistrationOwner(commonTxData->signTxUsecase, owner);
	TRACE("Policy: %d", (int) policy);
	ENSURE_NOT_DENIED(policy);

	_addOwnerToTxHash();

	{
		// select UI steps
		switch (policy) {
#	define  CASE(POLICY, UI_STEP) case POLICY: {subctx->ui_step=UI_STEP; break;}
			CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_OWNER_STEP_DISPLAY);
			CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_OWNER_STEP_RESPOND);
#	undef   CASE
		default:
			THROW(ERR_NOT_IMPLEMENTED);
		}
	}

	handleOwner_ui_runStep();
}


// ============================== RELAY ==============================

enum {
	HANDLE_RELAY_IP_STEP_DISPLAY_NUMBER = 6700,
	HANDLE_RELAY_IP_STEP_DISPLAY_IPV4,
	HANDLE_RELAY_IP_STEP_DISPLAY_IPV6,
	HANDLE_RELAY_IP_STEP_DISPLAY_PORT,
	HANDLE_RELAY_IP_STEP_RESPOND,
	HANDLE_RELAY_IP_STEP_INVALID,
};

static void handleRelay_ip_ui_runStep()
{
	TRACE("UI step %d", subctx->ui_step);
	TRACE_STACK_USAGE();
	ui_callback_fn_t* this_fn = handleRelay_ip_ui_runStep;

	pool_relay_t* relay = &subctx->stateData.relay;

	UI_STEP_BEGIN(subctx->ui_step, this_fn);

	UI_STEP(HANDLE_RELAY_IP_STEP_DISPLAY_NUMBER) {
		ui_displayRelaycreen(
			relay,
			subctx->currentRelay,
			this_fn
		);
	}
	UI_STEP(HANDLE_RELAY_IP_STEP_DISPLAY_IPV4) {
		ui_displayIpv4Screen(
		        &relay->ipv4,
		        this_fn
		);
	}
	UI_STEP(HANDLE_RELAY_IP_STEP_DISPLAY_IPV6) {
		ui_displayIpv6Screen(
		        &relay->ipv6,
		        this_fn
		);
	}
	UI_STEP(HANDLE_RELAY_IP_STEP_DISPLAY_PORT) {
		ui_displayIpPortScreen(
		        &relay->port,
		        this_fn
		);
	}
	UI_STEP(HANDLE_RELAY_IP_STEP_RESPOND) {
		respondSuccessEmptyMsg();

		subctx->currentRelay++;
		TRACE("current relay %d", subctx->currentRelay);

		if (subctx->currentRelay == subctx->numRelays) {
			advanceState();
		}
	}
	UI_STEP_END(HANDLE_RELAY_IP_STEP_INVALID);
}

enum {
	HANDLE_RELAY_DNS_STEP_DISPLAY_NUMBER = 6800,
	HANDLE_RELAY_DNS_STEP_DISPLAY_PORT,
	HANDLE_RELAY_DNS_STEP_DISPLAY_DNSNAME,
	HANDLE_RELAY_DNS_STEP_RESPOND,
	HANDLE_RELAY_DNS_STEP_INVALID,
};

static void handleRelay_dns_ui_runStep()
{
	TRACE("UI step %d", subctx->ui_step);
	TRACE_STACK_USAGE();
	ui_callback_fn_t* this_fn = handleRelay_dns_ui_runStep;

	pool_relay_t* relay = &subctx->stateData.relay;

	UI_STEP_BEGIN(subctx->ui_step, this_fn);

	UI_STEP(HANDLE_RELAY_DNS_STEP_DISPLAY_NUMBER) {
		ui_displayRelaycreen(
			relay,
			subctx->currentRelay,
			this_fn
		);
	}
	UI_STEP(HANDLE_RELAY_DNS_STEP_DISPLAY_PORT) {
		if (relay->format == RELAY_MULTIPLE_HOST_NAME) {
			// nothing to display in this step, so we skip it
			UI_STEP_JUMP(HANDLE_RELAY_DNS_STEP_DISPLAY_DNSNAME);
		}

		ui_displayIpPortScreen(
		        &relay->port,
		        this_fn
		);
	}
	UI_STEP(HANDLE_RELAY_DNS_STEP_DISPLAY_DNSNAME) {
		char dnsNameStr[1 + DNS_NAME_SIZE_MAX];
		ASSERT(relay->dnsNameSize <= DNS_NAME_SIZE_MAX);
		os_memcpy(dnsNameStr, relay->dnsName, relay->dnsNameSize);
		dnsNameStr[relay->dnsNameSize] = '\0';
		ASSERT(strlen(dnsNameStr) == relay->dnsNameSize);

		ui_displayPaginatedText(
		        "Dns name",
		        dnsNameStr,
		        this_fn
		);
	}
	UI_STEP(HANDLE_RELAY_DNS_STEP_RESPOND) {
		respondSuccessEmptyMsg();

		subctx->currentRelay++;
		TRACE("current relay %d", subctx->currentRelay);

		if (subctx->currentRelay == subctx->numRelays) {
			advanceState();
		}
	}
	UI_STEP_END(HANDLE_RELAY_DNS_STEP_INVALID);
}

static void _parsePort(ipport_t* port, read_view_t* view)
{
	VALIDATE(view_remainingSize(view) >= 1, ERR_INVALID_DATA);
	uint8_t isPortGiven = parse_u1be(view);
	if (isPortGiven == ITEM_INCLUDED_YES) {
		port->isNull = false;
		ASSERT_TYPE(port->number, uint16_t);
		port->number = parse_u2be(view);
		TRACE("Port: %u", port->number);
	} else {
		VALIDATE(isPortGiven == ITEM_INCLUDED_NO, ERR_INVALID_DATA);
		port->isNull = true;
	}
}

static void _parseIpv4(ipv4_t* ipv4, read_view_t* view)
{
	VALIDATE(view_remainingSize(view) >= 1, ERR_INVALID_DATA);
	uint8_t isIpv4Given = parse_u1be(view);
	if (isIpv4Given == ITEM_INCLUDED_YES) {
		ipv4->isNull = false;
		VALIDATE(view_remainingSize(view) >= IPV4_SIZE, ERR_INVALID_DATA);
		STATIC_ASSERT(sizeof(ipv4->ip) == IPV4_SIZE, "wrong ipv4 size"); // SIZEOF does not work for 4-byte buffers
		view_memmove(ipv4->ip, view, IPV4_SIZE);
		TRACE("ipv4");
		TRACE_BUFFER(ipv4->ip, IPV4_SIZE);
	} else {
		VALIDATE(isIpv4Given == ITEM_INCLUDED_NO, ERR_INVALID_DATA);
		ipv4->isNull = true;
	}
}

static void _parseIpv6(ipv6_t* ipv6, read_view_t* view)
{
	VALIDATE(view_remainingSize(view) >= 1, ERR_INVALID_DATA);
	uint8_t isIpv6Given = parse_u1be(view);
	if (isIpv6Given == ITEM_INCLUDED_YES) {
		ipv6->isNull = false;
		VALIDATE(view_remainingSize(view) >= IPV6_SIZE, ERR_INVALID_DATA);
		STATIC_ASSERT(SIZEOF(ipv6->ip) == IPV6_SIZE, "wrong ipv6 size");
		view_memmove(ipv6->ip, view, IPV6_SIZE);
		TRACE("ipv6");
		TRACE_BUFFER(ipv6->ip, IPV6_SIZE);
	} else {
		VALIDATE(isIpv6Given == ITEM_INCLUDED_NO, ERR_INVALID_DATA);
		ipv6->isNull = true;
	}
}

static void _parseDnsName(pool_relay_t* relay, read_view_t* view)
{
	relay->dnsNameSize = view_remainingSize(view);
	VALIDATE(relay->dnsNameSize <= DNS_NAME_SIZE_MAX, ERR_INVALID_DATA);
	VALIDATE(str_isAllowedDnsName(VIEW_REMAINING_TO_TUPLE_BUF_SIZE(view)), ERR_INVALID_DATA);

	view_memmove(relay->dnsName, view, relay->dnsNameSize);
}

/*
wire data:
1B relay format

format 0 single_host_addr:
1B + [2B port] + 1B + [4B ipv4] + 1B + [16B ipv6]

format 1 single_host_name:
1B + [2B port] + [0-64B dns_name]

format 2 multi_host_name:
[0-64B dns_name]
*/
__noinline_due_to_stack__
static void signTxPoolRegistration_handleRelayAPDU(uint8_t* wireDataBuffer, size_t wireDataSize)
{
	TRACE_STACK_USAGE();
	{
		// sanity checks
		CHECK_STATE(STAKE_POOL_REGISTRATION_RELAYS);

		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}

	pool_relay_t* relay = &subctx->stateData.relay;
	{
		// parse data
		TRACE_BUFFER(wireDataBuffer, wireDataSize);

		read_view_t view = make_read_view(wireDataBuffer, wireDataBuffer + wireDataSize);

		VALIDATE(view_remainingSize(&view) >= 1, ERR_INVALID_DATA);
		relay->format = parse_u1be(&view);
		TRACE("Relay format %u", relay->format);
		switch (relay->format) {

		// validation differs from the CDDL spec
		// the CDDL spec allows combinations of parameters that lead
		// to meaningless relays that are ignored by nodes
		// so we only allow meaningful relays

		case RELAY_SINGLE_HOST_IP: {
			_parsePort(&relay->port, &view);
			VALIDATE(!relay->port.isNull, ERR_INVALID_DATA);
			_parseIpv4(&relay->ipv4, &view);
			_parseIpv6(&relay->ipv6, &view);
			VALIDATE(!relay->ipv4.isNull || !relay->ipv6.isNull, ERR_INVALID_DATA);
			break;
		}

		case RELAY_SINGLE_HOST_NAME: {
			_parsePort(&relay->port, &view);
			VALIDATE(!relay->port.isNull, ERR_INVALID_DATA);
			_parseDnsName(relay, &view);
			VALIDATE(relay->dnsNameSize > 0, ERR_INVALID_DATA);
			break;
		}

		case RELAY_MULTIPLE_HOST_NAME: {
			_parseDnsName(relay, &view);
			VALIDATE(relay->dnsNameSize > 0, ERR_INVALID_DATA);
			break;
		}

		default:
			THROW(ERR_INVALID_DATA);
		}

		VALIDATE(view_remainingSize(&view) == 0, ERR_INVALID_DATA);
	}

	security_policy_t policy = policyForSignTxStakePoolRegistrationRelay(commonTxData->signTxUsecase, relay);
	TRACE("Policy: %d", (int) policy);
	ENSURE_NOT_DENIED(policy);

	TRACE("Adding relay format %d to tx hash", (int) relay->format);
	txHashBuilder_addPoolRegistrationCertificate_addRelay(txHashBuilder, relay);

	{
		int respondStep = -1;
		int displayStep = -1;
		void (*uiFn)() = NULL;

		switch (relay->format) {

		case RELAY_SINGLE_HOST_IP: {
			respondStep = HANDLE_RELAY_IP_STEP_RESPOND;
			displayStep = HANDLE_RELAY_IP_STEP_DISPLAY_NUMBER;
			uiFn = handleRelay_ip_ui_runStep;
			break;
		}

		case RELAY_SINGLE_HOST_NAME:
		case RELAY_MULTIPLE_HOST_NAME: {
			respondStep = HANDLE_RELAY_DNS_STEP_RESPOND;
			displayStep = HANDLE_RELAY_DNS_STEP_DISPLAY_NUMBER;
			uiFn = handleRelay_dns_ui_runStep;
			break;
		}

		default:
			THROW(ERR_INVALID_DATA);
		}

		ASSERT(respondStep != -1);
		ASSERT(displayStep != -1);
		ASSERT(uiFn != NULL);

		// select UI steps and call ui handler
		switch (policy) {
#	define  CASE(POLICY, UI_STEP) case POLICY: {subctx->ui_step=UI_STEP; break;}
			CASE(POLICY_ALLOW_WITHOUT_PROMPT, respondStep);
			CASE(POLICY_SHOW_BEFORE_RESPONSE, displayStep);
#	undef   CASE
		default:
			THROW(ERR_NOT_IMPLEMENTED);
		}

		uiFn();
	}
}


// ============================== METADATA ==============================

enum {
	HANDLE_NULL_METADATA_STEP_DISPLAY = 6900,
	HANDLE_NULL_METADATA_STEP_RESPOND,
	HANDLE_NULL_METADATA_STEP_INVALID,
};

static void handleNullMetadata_ui_runStep()
{
	TRACE("UI step %d", subctx->ui_step);
	TRACE_STACK_USAGE();
	ui_callback_fn_t* this_fn = handleNullMetadata_ui_runStep;

	UI_STEP_BEGIN(subctx->ui_step, this_fn);

	UI_STEP(HANDLE_NULL_METADATA_STEP_DISPLAY) {
		ui_displayPaginatedText(
		        "No metadata",
		        "(anonymous pool)",
		        this_fn
		);
	}
	UI_STEP(HANDLE_NULL_METADATA_STEP_RESPOND) {
		respondSuccessEmptyMsg();
		advanceState();
	}
	UI_STEP_END(HANDLE_NULL_METADATA_STEP_INVALID);
}

enum {
	HANDLE_METADATA_STEP_DISPLAY_URL = 7000,
	HANDLE_METADATA_STEP_DISPLAY_HASH,
	HANDLE_METADATA_STEP_RESPOND,
	HANDLE_METADATA_STEP_INVALID,
};

static void handleMetadata_ui_runStep()
{
	TRACE("UI step %d", subctx->ui_step);
	TRACE_STACK_USAGE();
	ui_callback_fn_t* this_fn = handleMetadata_ui_runStep;

	pool_metadata_t* md = &subctx->stateData.metadata;

	UI_STEP_BEGIN(subctx->ui_step, this_fn);

	UI_STEP(HANDLE_METADATA_STEP_DISPLAY_URL) {
		char metadataUrlStr[1 + POOL_METADATA_URL_LENGTH_MAX];
		ASSERT(md->urlSize <= POOL_METADATA_URL_LENGTH_MAX);
		os_memcpy(metadataUrlStr, md->url, md->urlSize);
		metadataUrlStr[md->urlSize] = '\0';
		ASSERT(strlen(metadataUrlStr) == md->urlSize);

		ui_displayPaginatedText(
		        "Pool metadata url",
		        metadataUrlStr,
		        this_fn
		);
	}
	UI_STEP(HANDLE_METADATA_STEP_DISPLAY_HASH) {
		char metadataHashHex[1 + 2 * METADATA_HASH_LENGTH];
		size_t len = str_formatMetadata(
		                     md->hash, SIZEOF(md->hash),
		                     metadataHashHex, SIZEOF(metadataHashHex)
		             );
		ASSERT(len + 1 == SIZEOF(metadataHashHex));

		ui_displayPaginatedText(
		        "Pool metadata hash",
		        metadataHashHex,
		        this_fn
		);
	}
	UI_STEP(HANDLE_METADATA_STEP_RESPOND) {
		respondSuccessEmptyMsg();
		advanceState();
	}
	UI_STEP_END(HANDLE_METADATA_STEP_INVALID);
}

static void handleNullMetadata()
{
	{
		security_policy_t policy = policyForSignTxStakePoolRegistrationNoMetadata();
		TRACE("Policy: %d", (int) policy);
		ENSURE_NOT_DENIED(policy);

		// select UI step
		switch (policy) {
#	define  CASE(POLICY, UI_STEP) case POLICY: {subctx->ui_step=UI_STEP; break;}
			CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_NULL_METADATA_STEP_DISPLAY);
			CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_NULL_METADATA_STEP_RESPOND);
#	undef   CASE
		default:
			THROW(ERR_NOT_IMPLEMENTED);
		}
	}
	{
		// add null metadata to certificate
		TRACE("Adding null pool metadata to tx hash");
		txHashBuilder_addPoolRegistrationCertificate_addPoolMetadata_null(txHashBuilder);
	}

	handleNullMetadata_ui_runStep();
}

__noinline_due_to_stack__
static void signTxPoolRegistration_handlePoolMetadataAPDU(uint8_t* wireDataBuffer, size_t wireDataSize)
{
	TRACE_STACK_USAGE();
	{
		// sanity checks
		CHECK_STATE(STAKE_POOL_REGISTRATION_METADATA);

		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}

	explicit_bzero(&subctx->stateData.metadata, SIZEOF(subctx->stateData.metadata));

	{
		// parse data
		TRACE_BUFFER(wireDataBuffer, wireDataSize);

		pool_metadata_t* md = &subctx->stateData.metadata;

		read_view_t view = make_read_view(wireDataBuffer, wireDataBuffer + wireDataSize);

		{
			// deal with null metadata

			VALIDATE(view_remainingSize(&view) >= 1, ERR_INVALID_DATA);

			uint8_t includeMetadataByte = parse_u1be(&view);
			int includeMetadata = signTx_parseIncluded(includeMetadataByte);

			if (!includeMetadata) {
				VALIDATE(view_remainingSize(&view) == 0, ERR_INVALID_DATA);
				handleNullMetadata();
				return;
			}
		}
		{
			VALIDATE(view_remainingSize(&view) >= METADATA_HASH_LENGTH, ERR_INVALID_DATA);
			ASSERT(SIZEOF(md->hash) == METADATA_HASH_LENGTH);
			view_memmove(md->hash, &view, METADATA_HASH_LENGTH);
		}
		{
			md->urlSize = view_remainingSize(&view);
			VALIDATE(md->urlSize <= POOL_METADATA_URL_LENGTH_MAX, ERR_INVALID_DATA);
			ASSERT(SIZEOF(md->url) >= md->urlSize);
			view_memmove(md->url, &view, md->urlSize);

			// whitespace not allowed
			VALIDATE(str_isPrintableAsciiWithoutSpaces(md->url, md->urlSize), ERR_INVALID_DATA);
		}

		VALIDATE(view_remainingSize(&view) == 0, ERR_INVALID_DATA);
	}

	{
		security_policy_t policy = policyForSignTxStakePoolRegistrationMetadata();
		TRACE("Policy: %d", (int) policy);
		ENSURE_NOT_DENIED(policy);

		// select UI step
		switch (policy) {
#	define  CASE(POLICY, UI_STEP) case POLICY: {subctx->ui_step=UI_STEP; break;}
			CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_METADATA_STEP_DISPLAY_URL);
			CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_METADATA_STEP_RESPOND);
#	undef   CASE
		default:
			THROW(ERR_NOT_IMPLEMENTED);
		}
	}

	{
		// add metadata to tx
		TRACE("Adding metadata hash to tx hash");
		txHashBuilder_addPoolRegistrationCertificate_addPoolMetadata(
		        txHashBuilder,
		        subctx->stateData.metadata.url, subctx->stateData.metadata.urlSize,
		        subctx->stateData.metadata.hash, SIZEOF(subctx->stateData.metadata.hash)
		);
	}

	handleMetadata_ui_runStep();
}

// ============================== CONFIRM ==============================

enum {
	HANDLE_CONFIRM_STEP_FINAL_CONFIRM = 7100,
	HANDLE_CONFIRM_STEP_RESPOND,
	HANDLE_CONFIRM_STEP_INVALID,
};

static void signTxPoolRegistration_handleConfirm_ui_runStep()
{
	TRACE("UI step %d", subctx->ui_step);
	TRACE_STACK_USAGE();
	ui_callback_fn_t* this_fn = signTxPoolRegistration_handleConfirm_ui_runStep;

	UI_STEP_BEGIN(subctx->ui_step, this_fn);

	UI_STEP(HANDLE_CONFIRM_STEP_FINAL_CONFIRM) {
		ui_displayPrompt(
		        "Confirm stake",
		        "pool registration?",
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

__noinline_due_to_stack__
static void signTxPoolRegistration_handleConfirmAPDU(uint8_t* wireDataBuffer MARK_UNUSED, size_t wireDataSize)
{
	TRACE_STACK_USAGE();
	{
		//sanity checks
		CHECK_STATE(STAKE_POOL_REGISTRATION_CONFIRM);

		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}

	{
		// no data to receive
		VALIDATE(wireDataSize == 0, ERR_INVALID_DATA);
	}

	security_policy_t policy = policyForSignTxStakePoolRegistrationConfirm();
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

	signTxPoolRegistration_handleConfirm_ui_runStep();
}


// ============================== main APDU handler ==============================

enum {
	APDU_INSTRUCTION_INIT = 0x30,
	APDU_INSTRUCTION_POOL_KEY = 0x31,
	APDU_INSTRUCTION_VRF_KEY = 0x32,
	APDU_INSTRUCTION_FINANCIALS = 0x33,
	APDU_INSTRUCTION_REWARD_ACCOUNT = 0x34,
	APDU_INSTRUCTION_OWNERS = 0x35,
	APDU_INSTRUCTION_RELAYS = 0x36,
	APDU_INSTRUCTION_METADATA = 0x37,
	APDU_INSTRUCTION_CONFIRMATION = 0x38
};

bool signTxPoolRegistration_isValidInstruction(uint8_t p2)
{
	switch (p2) {
	case APDU_INSTRUCTION_INIT:
	case APDU_INSTRUCTION_POOL_KEY:
	case APDU_INSTRUCTION_VRF_KEY:
	case APDU_INSTRUCTION_FINANCIALS:
	case APDU_INSTRUCTION_REWARD_ACCOUNT:
	case APDU_INSTRUCTION_OWNERS:
	case APDU_INSTRUCTION_RELAYS:
	case APDU_INSTRUCTION_METADATA:
	case APDU_INSTRUCTION_CONFIRMATION:
		return true;

	default:
		return false;
	}
}

void signTxPoolRegistration_handleAPDU(uint8_t p2, uint8_t* wireDataBuffer, size_t wireDataSize)
{
	TRACE_STACK_USAGE();
	TRACE("p2 = 0x%x", p2);

	explicit_bzero(&subctx->stateData, SIZEOF(subctx->stateData));

	switch (p2) {
	case APDU_INSTRUCTION_INIT:
		signTxPoolRegistration_handleInitAPDU(wireDataBuffer, wireDataSize);
		break;

	case APDU_INSTRUCTION_POOL_KEY:
		signTxPoolRegistration_handlePoolKeyAPDU(wireDataBuffer, wireDataSize);
		break;

	case APDU_INSTRUCTION_VRF_KEY:
		signTxPoolRegistration_handleVrfKeyAPDU(wireDataBuffer, wireDataSize);
		break;

	case APDU_INSTRUCTION_FINANCIALS:
		signTxPoolRegistration_handlePoolFinancialsAPDU(wireDataBuffer, wireDataSize);
		break;

	case APDU_INSTRUCTION_REWARD_ACCOUNT:
		signTxPoolRegistration_handleRewardAccountAPDU(wireDataBuffer, wireDataSize);
		break;

	case APDU_INSTRUCTION_OWNERS:
		signTxPoolRegistration_handleOwnerAPDU(wireDataBuffer, wireDataSize);
		break;

	case APDU_INSTRUCTION_RELAYS:
		signTxPoolRegistration_handleRelayAPDU(wireDataBuffer, wireDataSize);
		break;

	case APDU_INSTRUCTION_METADATA:
		signTxPoolRegistration_handlePoolMetadataAPDU(wireDataBuffer, wireDataSize);
		break;

	case APDU_INSTRUCTION_CONFIRMATION:
		signTxPoolRegistration_handleConfirmAPDU(wireDataBuffer, wireDataSize);
		break;

	default:
		// this is not supposed to be called with invalid p2
		ASSERT(false);
	}
}
