#include "signTxCatalystRegistration.h"
#include "state.h"
#include "uiHelpers.h"
#include "signTxUtils.h"
#include "uiScreens.h"
#include "auxDataHashBuilder.h"
#include "txHashBuilder.h"
#include "textUtils.h"
#include "bufView.h"
#include "securityPolicy.h"
#include "messageSigning.h"

// we want to distinguish the two state machines to avoid potential confusion:
// ctx / subctx
// stage / state
// from ctx, we only make the necessary parts available to avoid mistaken overwrites
static ins_sign_tx_context_t* ctx = &(instructionState.signTxContext);
static catalyst_registration_context_t* subctx = &(instructionState.signTxContext.txPartCtx.aux_data_ctx.stageContext.catalyst_registration_subctx);
static common_tx_data_t* commonTxData = &(instructionState.signTxContext.commonTxData);
static aux_data_hash_builder_t* auxDataHashBuilder = &(instructionState.signTxContext.txPartCtx.aux_data_ctx.auxDataHashBuilder);

bool signTxCatalystRegistration_isFinished()
{
	TRACE("Catalyst registration submachine state: %d", subctx->state);
	// we are also asserting that the state is valid
	switch (subctx->state) {
	case STATE_CATALYST_REGISTRATION_FINISHED:
		return true;

	case STATE_CATALYST_REGISTRATION_VOTING_KEY:
	case STATE_CATALYST_REGISTRATION_STAKING_KEY:
	case STATE_CATALYST_REGISTRATION_VOTING_REWARDS_ADDRESS:
	case STATE_CATALYST_REGISTRATION_NONCE:
	case STATE_CATALYST_REGISTRATION_CONFIRM:
		return false;

	default:
		ASSERT(false);
	}
}

void signTxCatalystRegistration_init()
{
	explicit_bzero(subctx, SIZEOF(*subctx));
	auxDataHashBuilder_init(auxDataHashBuilder);

	subctx->state = STATE_CATALYST_REGISTRATION_VOTING_KEY;
}

static inline void CHECK_STATE(sign_tx_catalyst_registration_state_t expected)
{
	TRACE("Catalyst voting registration submachine state: current %d, expected %d", subctx->state, expected);
	VALIDATE(subctx->state == expected, ERR_INVALID_STATE);
}

static inline void advanceState()
{
	TRACE("Advancing Catalyst registration state from: %d", subctx->state);

	switch (subctx->state) {

	case STATE_CATALYST_REGISTRATION_VOTING_KEY:
		subctx->state = STATE_CATALYST_REGISTRATION_STAKING_KEY;
		break;

	case STATE_CATALYST_REGISTRATION_STAKING_KEY:
		subctx->state = STATE_CATALYST_REGISTRATION_VOTING_REWARDS_ADDRESS;
		break;

	case STATE_CATALYST_REGISTRATION_VOTING_REWARDS_ADDRESS:
		subctx->state = STATE_CATALYST_REGISTRATION_NONCE;
		break;

	case STATE_CATALYST_REGISTRATION_NONCE:
		subctx->state = STATE_CATALYST_REGISTRATION_CONFIRM;
		break;

	case STATE_CATALYST_REGISTRATION_CONFIRM:
		subctx->state = STATE_CATALYST_REGISTRATION_FINISHED;
		break;

	default:
		ASSERT(false);
	}

	TRACE("Advancing Catalyst registration state to: %d", subctx->state);
}

// ============================== VOTING KEY ==============================

enum {
	HANDLE_VOTING_KEY_STEP_DISPLAY = 8200,
	HANDLE_VOTING_KEY_STEP_RESPOND,
	HANDLE_VOTING_KEY_STEP_INVALID,
};

static void signTxCatalystRegistration_handleVotingKey_ui_runStep()
{
	TRACE("UI step %d", subctx->ui_step);
	TRACE_STACK_USAGE();
	ui_callback_fn_t* this_fn = signTxCatalystRegistration_handleVotingKey_ui_runStep;

	UI_STEP_BEGIN(subctx->ui_step);

	UI_STEP(HANDLE_VOTING_KEY_STEP_DISPLAY) {
		STATIC_ASSERT(SIZEOF(subctx->stateData.votingPubKey) == CATALYST_VOTING_PUBLIC_KEY_LENGTH, "wrong voting public key size");

		// Jormungandr public key, hence the "ed25519_pk" prefix
		// https://github.com/input-output-hk/jormungandr/blob/a057af27493d823be02480bb20258c25ff979e2a/jormungandr-lib/src/crypto/key.rs#L126
		ui_displayBech32Screen(
		        "Voting public key",
		        "ed25519_pk",
		        subctx->stateData.votingPubKey, CATALYST_VOTING_PUBLIC_KEY_LENGTH,
		        this_fn
		);
	}
	UI_STEP(HANDLE_VOTING_KEY_STEP_RESPOND) {
		respondSuccessEmptyMsg();
		advanceState();
	}
	UI_STEP_END(HANDLE_VOTING_KEY_STEP_INVALID);
}

__noinline_due_to_stack__
static void signTxCatalystRegistration_handleVotingKeyAPDU(uint8_t* wireDataBuffer, size_t wireDataSize)
{
	{
		CHECK_STATE(STATE_CATALYST_REGISTRATION_VOTING_KEY);

		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}
	{
		explicit_bzero(&subctx->stateData, SIZEOF(subctx->stateData));
	}
	{
		TRACE_BUFFER(wireDataBuffer, wireDataSize);

		VALIDATE(wireDataSize == SIZEOF(subctx->stateData.votingPubKey), ERR_INVALID_DATA);

		{
			STATIC_ASSERT(SIZEOF(subctx->stateData.votingPubKey) == CATALYST_VOTING_PUBLIC_KEY_LENGTH, "wrong voting public key size");
			os_memmove(subctx->stateData.votingPubKey, wireDataBuffer, CATALYST_VOTING_PUBLIC_KEY_LENGTH);
		}
	}
	{
		auxDataHashBuilder_catalystRegistration_enter(auxDataHashBuilder);
		auxDataHashBuilder_catalystRegistration_enterPayload(auxDataHashBuilder);
		auxDataHashBuilder_catalystRegistration_addVotingKey(
		        auxDataHashBuilder, subctx->stateData.votingPubKey, CATALYST_VOTING_PUBLIC_KEY_LENGTH
		);
	}

	// TODO - is it worth declaring a policy for this?
	subctx->ui_step = HANDLE_VOTING_KEY_STEP_DISPLAY;
	signTxCatalystRegistration_handleVotingKey_ui_runStep();
}

// ============================== STAKING KEY ==============================

enum {
	HANDLE_STAKING_KEY_STEP_WARNING = 8300,
	HANDLE_STAKING_KEY_STEP_DISPLAY,
	HANDLE_STAKING_KEY_STEP_RESPOND,
	HANDLE_STAKING_KEY_STEP_INVALID,
};

static void signTxCatalystRegistration_handleStakingKey_ui_runStep()
{
	TRACE("UI step %d", subctx->ui_step);
	TRACE_STACK_USAGE();
	ui_callback_fn_t* this_fn = signTxCatalystRegistration_handleStakingKey_ui_runStep;

	UI_STEP_BEGIN(subctx->ui_step);

	UI_STEP(HANDLE_STAKING_KEY_STEP_WARNING) {
		ui_displayPaginatedText(
		        "Unusual request",
		        "Proceed with care",
		        this_fn
		);
	}s
	UI_STEP(HANDLE_STAKING_KEY_STEP_DISPLAY) {
		ui_displayStakingKeyScreen(
		        &subctx->stakingKeyPath,
		        this_fn
		);
	}
	UI_STEP(HANDLE_STAKING_KEY_STEP_RESPOND) {
		respondSuccessEmptyMsg();
		advanceState();
	}
	UI_STEP_END(HANDLE_STAKING_KEY_STEP_INVALID);
}

__noinline_due_to_stack__
static void signTxCatalystRegistration_handleStakingKeyAPDU(uint8_t* wireDataBuffer, size_t wireDataSize)
{
	TRACE_STACK_USAGE();
	{
		// sanity checks
		CHECK_STATE(STATE_CATALYST_REGISTRATION_STAKING_KEY);
		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}
	{
		explicit_bzero(&subctx->stakingKeyPath, SIZEOF(subctx->stakingKeyPath));
	}
	{
		// parse input
		TRACE_BUFFER(wireDataBuffer, wireDataSize);

		read_view_t view = make_read_view(wireDataBuffer, wireDataBuffer + wireDataSize);

		view_skipBytes(
		        &view,
		        bip44_parseFromWire(&subctx->stakingKeyPath, VIEW_REMAINING_TO_TUPLE_BUF_SIZE(&view))
		);

		VALIDATE(view_remainingSize(&view) == 0, ERR_INVALID_DATA);

	}

	security_policy_t policy = policyForCatalystRegistrationStakingKey(
	                                   &subctx->stakingKeyPath
	                           );
	TRACE("Policy: %d", (int) policy);
	ENSURE_NOT_DENIED(policy);

	{
		extendedPublicKey_t extStakingPubKey;
		deriveExtendedPublicKey(&subctx->stakingKeyPath, &extStakingPubKey);
		auxDataHashBuilder_catalystRegistration_addStakingKey(
		        auxDataHashBuilder, extStakingPubKey.pubKey, SIZEOF(extStakingPubKey.pubKey)
		);
	}

	{
		// select UI step
		switch (policy) {
#	define  CASE(POLICY, UI_STEP) case POLICY: {subctx->ui_step=UI_STEP; break;}
			CASE(POLICY_PROMPT_WARN_UNUSUAL, HANDLE_STAKING_KEY_STEP_WARNING);
			CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_STAKING_KEY_STEP_DISPLAY);
			CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_STAKING_KEY_STEP_RESPOND);
#	undef   CASE
		default:
			THROW(ERR_NOT_IMPLEMENTED);
		}
	}

	signTxCatalystRegistration_handleStakingKey_ui_runStep();
}

// ============================== VOTING REWARDS ADDRESS ==============================

enum {
	HANDLE_VOTING_REWARDS_ADDRESS_PARAMS_STEP_WARNING = 8500,
	HANDLE_VOTING_REWARDS_ADDRESS_PARAMS_STEP_DISPLAY_ADDRESS,
	HANDLE_VOTING_REWARDS_ADDRESS_PARAMS_STEP_RESPOND,
	HANDLE_VOTING_REWARDS_ADDRESS_PARAMS_STEP_INVALID
};

__noinline_due_to_stack__
static void signTxCatalystRegistration_handleVotingRewardsAddress_addressParams_ui_runStep()
{
	TRACE("UI step %d", subctx->ui_step);
	TRACE_STACK_USAGE();
	ui_callback_fn_t* this_fn = signTxCatalystRegistration_handleVotingRewardsAddress_addressParams_ui_runStep;

	UI_STEP_BEGIN(subctx->ui_step);

	UI_STEP(HANDLE_VOTING_REWARDS_ADDRESS_PARAMS_STEP_WARNING) {
		ui_displayPaginatedText(
		        "Unusual request",
		        "Proceed with care",
		        this_fn
		);
	}
	UI_STEP(HANDLE_VOTING_REWARDS_ADDRESS_PARAMS_STEP_DISPLAY_ADDRESS) {
		uint8_t addressBuffer[MAX_ADDRESS_SIZE];
		size_t addressSize;
		addressSize = deriveAddress(
		                      &subctx->stateData.votingRewardsAddressParams,
		                      addressBuffer,
		                      SIZEOF(addressBuffer)
		              );
		ASSERT(addressSize > 0);
		ASSERT(addressSize < BUFFER_SIZE_PARANOIA);

		ui_displayAddressScreen(
		        "Rewards go to",
		        addressBuffer,
		        addressSize,
		        this_fn
		);
	}
	UI_STEP(HANDLE_VOTING_REWARDS_ADDRESS_PARAMS_STEP_RESPOND) {
		respondSuccessEmptyMsg();
		advanceState();
	}
	UI_STEP_END(HANDLE_VOTING_REWARDS_ADDRESS_PARAMS_STEP_INVALID);
}

__noinline_due_to_stack__
static void signTxCatalystRegistration_handleVotingRewardsAddressAPDU(uint8_t* wireDataBuffer, size_t wireDataSize)
{
	{
		// safety checks
		CHECK_STATE(STATE_CATALYST_REGISTRATION_VOTING_REWARDS_ADDRESS);

		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}
	{
		explicit_bzero(
		        &subctx->stateData.votingRewardsAddressParams,
		        SIZEOF(subctx->stateData.votingRewardsAddressParams)
		);
	}
	{
		TRACE_BUFFER(wireDataBuffer, wireDataSize);

		read_view_t view = make_read_view(wireDataBuffer, wireDataBuffer + wireDataSize);

		view_parseAddressParams(&view, &subctx->stateData.votingRewardsAddressParams);

		VALIDATE(view_remainingSize(&view) == 0, ERR_INVALID_DATA);
	}

	security_policy_t policy = policyForCatalystRegistrationVotingRewardsAddressParams(
	                                   &subctx->stateData.votingRewardsAddressParams,
	                                   commonTxData->networkId
	                           );
	TRACE("Policy: %d", (int) policy);
	ENSURE_NOT_DENIED(policy);

	{
		ASSERT(isShelleyAddressType(subctx->stateData.votingRewardsAddressParams.type));
		uint8_t addressBuffer[MAX_ADDRESS_SIZE];
		size_t addressSize;
		addressSize = deriveAddress(
		                      &subctx->stateData.votingRewardsAddressParams,
		                      addressBuffer,
		                      SIZEOF(addressBuffer)
		              );
		ASSERT(addressSize > 0);
		ASSERT(addressSize < BUFFER_SIZE_PARANOIA);

		auxDataHashBuilder_catalystRegistration_addVotingRewardsAddress(
		        auxDataHashBuilder, addressBuffer, addressSize
		);
	}

	{
		// select UI steps
		switch (policy) {
#	define  CASE(POLICY, UI_STEP) case POLICY: {subctx->ui_step=UI_STEP; break;}
			CASE(POLICY_PROMPT_WARN_UNUSUAL, HANDLE_VOTING_REWARDS_ADDRESS_PARAMS_STEP_WARNING);
			CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_VOTING_REWARDS_ADDRESS_PARAMS_STEP_DISPLAY_ADDRESS);
			CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_VOTING_REWARDS_ADDRESS_PARAMS_STEP_RESPOND);
#	undef   CASE
		default:
			THROW(ERR_NOT_IMPLEMENTED);
		}

		signTxCatalystRegistration_handleVotingRewardsAddress_addressParams_ui_runStep();
	}
}

// ============================== NONCE ==============================

enum {
	HANDLE_NONCE_STEP_DISPLAY = 8600,
	HANDLE_NONCE_STEP_RESPOND,
	HANDLE_NONCE_STEP_INVALID,
};

static void signTxCatalystRegistration_handleNonce_ui_runStep()
{
	TRACE("UI step %d", subctx->ui_step);
	TRACE_STACK_USAGE();
	ui_callback_fn_t* this_fn = signTxCatalystRegistration_handleNonce_ui_runStep;

	UI_STEP_BEGIN(subctx->ui_step);

	UI_STEP(HANDLE_NONCE_STEP_DISPLAY) {
		ui_displayUint64Screen(
		        "Nonce",
		        subctx->stateData.nonce,
		        this_fn
		);
	}
	UI_STEP(HANDLE_NONCE_STEP_RESPOND) {
		respondSuccessEmptyMsg();
		advanceState();
	}
	UI_STEP_END(HANDLE_NONCE_STEP_INVALID);
}

__noinline_due_to_stack__
static void signTxCatalystRegistration_handleNonceAPDU(uint8_t* wireDataBuffer, size_t wireDataSize)
{
	{
		// sanity checks
		CHECK_STATE(STATE_CATALYST_REGISTRATION_NONCE);

		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}
	{
		explicit_bzero(&subctx->stateData, SIZEOF(subctx->stateData));
	}
	{
		// parse data
		TRACE_BUFFER(wireDataBuffer, wireDataSize);
		VALIDATE(wireDataSize == 8, ERR_INVALID_DATA);
		subctx->stateData.nonce = u8be_read(wireDataBuffer);
		TRACE(
		        "Catalyst registration nonce: %d",
		        subctx->stateData.nonce
		);
	}
	{
		auxDataHashBuilder_catalystRegistration_addNonce(auxDataHashBuilder, subctx->stateData.nonce);
	}

	// TODO - is it worth declaring a policy for this?
	subctx->ui_step = HANDLE_NONCE_STEP_DISPLAY;
	signTxCatalystRegistration_handleNonce_ui_runStep();
}

// ============================== CONFIRM ==============================

enum {
	HANDLE_CONFIRM_STEP_FINAL_CONFIRM,
	HANDLE_CONFIRM_STEP_DISPLAY_HASH,
	HANDLE_CONFIRM_STEP_RESPOND,
	HANDLE_CONFIRM_STEP_INVALID,
};

static void signTxCatalystRegistration_handleConfirm_ui_runStep()
{
	TRACE("UI step %d", subctx->ui_step);
	TRACE_STACK_USAGE();
	ui_callback_fn_t* this_fn = signTxCatalystRegistration_handleConfirm_ui_runStep;

	UI_STEP_BEGIN(subctx->ui_step);
	UI_STEP(HANDLE_CONFIRM_STEP_FINAL_CONFIRM) {
		ui_displayPrompt(
		        "Confirm voting key",
		        "registration?",
		        this_fn,
		        respond_with_user_reject
		);
	}
	UI_STEP(HANDLE_CONFIRM_STEP_DISPLAY_HASH) {
		ui_displayHexBufferScreen(
		        "Auxiliary data hash",
		        (uint8_t*) &ctx->auxDataHash,
		        SIZEOF(ctx->auxDataHash),
		        this_fn
		);
	}
	UI_STEP(HANDLE_CONFIRM_STEP_RESPOND) {
		struct {
			uint8_t auxDataHash[AUX_DATA_HASH_LENGTH];
			uint8_t signature[ED25519_SIGNATURE_LENGTH];
		} wireResponse;

		ASSERT(SIZEOF(ctx->auxDataHash) == AUX_DATA_HASH_LENGTH);
		os_memmove(wireResponse.auxDataHash, ctx->auxDataHash, AUX_DATA_HASH_LENGTH);

		ASSERT(SIZEOF(subctx->stateData.registrationSignature) == ED25519_SIGNATURE_LENGTH);
		os_memmove(wireResponse.signature, subctx->stateData.registrationSignature, ED25519_SIGNATURE_LENGTH);

		io_send_buf(SUCCESS, (uint8_t*) &wireResponse, SIZEOF(wireResponse));
		advanceState();
	}
	UI_STEP_END(HANDLE_CONFIRM_STEP_INVALID);
}

__noinline_due_to_stack__
static void signTxCatalystRegistration_handleConfirmAPDU(uint8_t* wireDataBuffer MARK_UNUSED, size_t wireDataSize)
{
	{
		//sanity checks
		CHECK_STATE(STATE_CATALYST_REGISTRATION_CONFIRM);

		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}

	{
		explicit_bzero(&subctx->stateData, SIZEOF(subctx->stateData));
	}

	{
		// no data to receive
		VALIDATE(wireDataSize == 0, ERR_INVALID_DATA);
	}

	{
		{
			uint8_t votingPayloadHashBuffer[CATALYST_REGISTRATION_PAYLOAD_HASH_LENGTH];
			auxDataHashBuilder_catalystRegistration_finalizePayload(auxDataHashBuilder, votingPayloadHashBuffer, AUX_DATA_HASH_LENGTH);
			getCatalystVotingRegistrationSignature(
			        &subctx->stakingKeyPath,
			        votingPayloadHashBuffer, CATALYST_REGISTRATION_PAYLOAD_HASH_LENGTH,
			        (uint8_t*) &subctx->stateData.registrationSignature, ED25519_SIGNATURE_LENGTH
			);
		}
		auxDataHashBuilder_catalystRegistration_addSignature(auxDataHashBuilder, (uint8_t*) &subctx->stateData.registrationSignature, ED25519_SIGNATURE_LENGTH);
		auxDataHashBuilder_catalystRegistration_addAuxiliaryScripts(auxDataHashBuilder);

		auxDataHashBuilder_finalize(auxDataHashBuilder, (uint8_t*) &ctx->auxDataHash, AUX_DATA_HASH_LENGTH);
	}

	// TODO - is it worth declaring a policy for this?
	subctx->ui_step = HANDLE_CONFIRM_STEP_FINAL_CONFIRM;
	signTxCatalystRegistration_handleConfirm_ui_runStep();
}


// ============================== main APDU handler ==============================

enum {
	APDU_INSTRUCTION_VOTING_KEY = 0x30,
	APDU_INSTRUCTION_STAKING_KEY = 0x31,
	APDU_INSTRUCTION_VOTING_REWARDS_ADDRESS = 0x32,
	APDU_INSTRUCTION_NONCE = 0x33,
	APDU_INSTRUCTION_CONFIRM = 0x34
};

bool signTxCatalystRegistration_isValidInstruction(uint8_t p2)
{
	switch (p2) {
	case APDU_INSTRUCTION_VOTING_KEY:
	case APDU_INSTRUCTION_STAKING_KEY:
	case APDU_INSTRUCTION_VOTING_REWARDS_ADDRESS:
	case APDU_INSTRUCTION_NONCE:
	case APDU_INSTRUCTION_CONFIRM:
		return true;

	default:
		return false;
	}
}

void signTxCatalystRegistration_handleAPDU(uint8_t p2, uint8_t* wireDataBuffer, size_t wireDataSize)
{
	switch (p2) {
	case APDU_INSTRUCTION_VOTING_KEY:
		signTxCatalystRegistration_handleVotingKeyAPDU(wireDataBuffer, wireDataSize);
		break;

	case APDU_INSTRUCTION_STAKING_KEY:
		signTxCatalystRegistration_handleStakingKeyAPDU(wireDataBuffer, wireDataSize);
		break;

	case APDU_INSTRUCTION_VOTING_REWARDS_ADDRESS:
		signTxCatalystRegistration_handleVotingRewardsAddressAPDU(wireDataBuffer, wireDataSize);
		break;

	case APDU_INSTRUCTION_NONCE:
		signTxCatalystRegistration_handleNonceAPDU(wireDataBuffer, wireDataSize);
		break;

	case APDU_INSTRUCTION_CONFIRM:
		signTxCatalystRegistration_handleConfirmAPDU(wireDataBuffer, wireDataSize);
		break;

	default:
		// this is not supposed to be called with invalid p2
		ASSERT(false);
	}
}
