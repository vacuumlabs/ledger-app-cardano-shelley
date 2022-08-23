#include "app_mode.h"
#include "signTxGovernanceVotingRegistration.h"
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

static common_tx_data_t* commonTxData = &(instructionState.signTxContext.commonTxData);

static inline governance_voting_registration_context_t* accessSubContext()
{
	return &AUX_DATA_CTX->stageContext.governance_voting_registration_subctx;
}

bool signTxGovernanceVotingRegistration_isFinished()
{
	const governance_voting_registration_context_t* subctx = accessSubContext();
	TRACE("Governance voting registration submachine state: %d", subctx->state);
	// we are also asserting that the state is valid
	switch (subctx->state) {
	case STATE_GOVERNANCE_VOTING_REGISTRATION_FINISHED:
		return true;

	case STATE_GOVERNANCE_VOTING_REGISTRATION_VOTING_KEY:
	case STATE_GOVERNANCE_VOTING_REGISTRATION_STAKING_KEY:
	case STATE_GOVERNANCE_VOTING_REGISTRATION_VOTING_REWARDS_ADDRESS:
	case STATE_GOVERNANCE_VOTING_REGISTRATION_NONCE:
	case STATE_GOVERNANCE_VOTING_REGISTRATION_CONFIRM:
		return false;

	default:
		ASSERT(false);
	}
}

void signTxGovernanceVotingRegistration_init()
{
	explicit_bzero(&AUX_DATA_CTX->stageContext, SIZEOF(AUX_DATA_CTX->stageContext));
	auxDataHashBuilder_init(&AUX_DATA_CTX->auxDataHashBuilder);

	accessSubContext()->state = STATE_GOVERNANCE_VOTING_REGISTRATION_VOTING_KEY;
}

static inline void CHECK_STATE(sign_tx_governance_voting_registration_state_t expected)
{
	TRACE("Governance voting registration submachine state: current %d, expected %d", accessSubContext()->state, expected);
	VALIDATE(accessSubContext()->state == expected, ERR_INVALID_STATE);
}

static inline void advanceState()
{
	governance_voting_registration_context_t* subctx = accessSubContext();
	TRACE("Advancing governance voting registration state from: %d", subctx->state);

	switch (subctx->state) {

	case STATE_GOVERNANCE_VOTING_REGISTRATION_VOTING_KEY:
		subctx->state = STATE_GOVERNANCE_VOTING_REGISTRATION_STAKING_KEY;
		break;

	case STATE_GOVERNANCE_VOTING_REGISTRATION_STAKING_KEY:
		subctx->state = STATE_GOVERNANCE_VOTING_REGISTRATION_VOTING_REWARDS_ADDRESS;
		break;

	case STATE_GOVERNANCE_VOTING_REGISTRATION_VOTING_REWARDS_ADDRESS:
		subctx->state = STATE_GOVERNANCE_VOTING_REGISTRATION_NONCE;
		break;

	case STATE_GOVERNANCE_VOTING_REGISTRATION_NONCE:
		subctx->state = STATE_GOVERNANCE_VOTING_REGISTRATION_CONFIRM;
		break;

	case STATE_GOVERNANCE_VOTING_REGISTRATION_CONFIRM:
		subctx->state = STATE_GOVERNANCE_VOTING_REGISTRATION_FINISHED;
		break;

	default:
		ASSERT(false);
	}

	TRACE("Advancing governance voting registration state to: %d", subctx->state);
}

// ============================== VOTING KEY ==============================

enum {
	HANDLE_VOTING_KEY_STEP_DISPLAY = 8200,
	HANDLE_VOTING_KEY_STEP_RESPOND,
	HANDLE_VOTING_KEY_STEP_INVALID,
};

static void signTxGovernanceVotingRegistration_handleVotingKey_ui_runStep()
{
	governance_voting_registration_context_t* subctx = accessSubContext();
	TRACE("UI step %d", subctx->ui_step);
	TRACE_STACK_USAGE();
	ui_callback_fn_t* this_fn = signTxGovernanceVotingRegistration_handleVotingKey_ui_runStep;

	UI_STEP_BEGIN(subctx->ui_step, this_fn);

	UI_STEP(HANDLE_VOTING_KEY_STEP_DISPLAY) {
		STATIC_ASSERT(SIZEOF(subctx->stateData.votingPubKey) == GOVERNANCE_VOTING_PUBLIC_KEY_LENGTH, "wrong voting public key size");

		// Jormungandr public key, hence the "ed25519_pk" prefix
		// https://github.com/input-output-hk/jormungandr/blob/a057af27493d823be02480bb20258c25ff979e2a/jormungandr-lib/src/crypto/key.rs#L126
		ui_displayBech32Screen(
		        "Voting public key",
		        "ed25519_pk",
		        subctx->stateData.votingPubKey, GOVERNANCE_VOTING_PUBLIC_KEY_LENGTH,
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
static void signTxGovernanceVotingRegistration_handleVotingKeyAPDU(const uint8_t* wireDataBuffer, size_t wireDataSize)
{
	{
		CHECK_STATE(STATE_GOVERNANCE_VOTING_REGISTRATION_VOTING_KEY);

		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}
	governance_voting_registration_context_t* subctx = accessSubContext();
	{
		explicit_bzero(&subctx->stateData, SIZEOF(subctx->stateData));
	}
	{
		TRACE_BUFFER(wireDataBuffer, wireDataSize);

		{
			VALIDATE(wireDataSize == SIZEOF(subctx->stateData.votingPubKey), ERR_INVALID_DATA);
			read_view_t view = make_read_view(wireDataBuffer, wireDataBuffer + wireDataSize);

			STATIC_ASSERT(SIZEOF(subctx->stateData.votingPubKey) == GOVERNANCE_VOTING_PUBLIC_KEY_LENGTH, "wrong voting public key size");
			view_parseBuffer(subctx->stateData.votingPubKey, &view, GOVERNANCE_VOTING_PUBLIC_KEY_LENGTH);

			VALIDATE(view_remainingSize(&view) == 0, ERR_INVALID_DATA);
		}
	}

	security_policy_t policy = policyForGovernanceVotingRegistrationVotingKey();
	TRACE("Policy: %d", (int) policy);
	ENSURE_NOT_DENIED(policy);

	{
		aux_data_hash_builder_t* auxDataHashBuilder = &AUX_DATA_CTX->auxDataHashBuilder;
		auxDataHashBuilder_governanceVotingRegistration_enter(auxDataHashBuilder);
		auxDataHashBuilder_governanceVotingRegistration_enterPayload(auxDataHashBuilder);
		auxDataHashBuilder_governanceVotingRegistration_addVotingKey(
		        auxDataHashBuilder, subctx->stateData.votingPubKey, GOVERNANCE_VOTING_PUBLIC_KEY_LENGTH
		);
	}

	{
		// select UI steps
		switch (policy) {
#define  CASE(POLICY, UI_STEP) case POLICY: {subctx->ui_step=UI_STEP; break;}
			CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_VOTING_KEY_STEP_DISPLAY);
			CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_VOTING_KEY_STEP_RESPOND);
#undef   CASE
		default:
			THROW(ERR_NOT_IMPLEMENTED);
		}
	}

	signTxGovernanceVotingRegistration_handleVotingKey_ui_runStep();
}

// ============================== STAKING KEY ==============================

enum {
	HANDLE_STAKING_KEY_STEP_WARNING = 8300,
	HANDLE_STAKING_KEY_STEP_DISPLAY,
	HANDLE_STAKING_KEY_STEP_RESPOND,
	HANDLE_STAKING_KEY_STEP_INVALID,
};

static void signTxGovernanceVotingRegistration_handleStakingKey_ui_runStep()
{
	governance_voting_registration_context_t* subctx = accessSubContext();
	TRACE("UI step %d", subctx->ui_step);
	TRACE_STACK_USAGE();
	ui_callback_fn_t* this_fn = signTxGovernanceVotingRegistration_handleStakingKey_ui_runStep;

	UI_STEP_BEGIN(subctx->ui_step, this_fn);

	UI_STEP(HANDLE_STAKING_KEY_STEP_WARNING) {
		ui_displayPaginatedText(
		        "Unusual request",
		        "Proceed with care",
		        this_fn
		);
	}
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
static void signTxGovernanceVotingRegistration_handleStakingKeyAPDU(const uint8_t* wireDataBuffer, size_t wireDataSize)
{
	TRACE_STACK_USAGE();
	{
		// sanity checks
		CHECK_STATE(STATE_GOVERNANCE_VOTING_REGISTRATION_STAKING_KEY);
		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}
	governance_voting_registration_context_t* subctx = accessSubContext();
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

	security_policy_t policy = policyForGovernanceVotingRegistrationStakingKey(
	                                   &subctx->stakingKeyPath
	                           );
	TRACE("Policy: %d", (int) policy);
	ENSURE_NOT_DENIED(policy);

	{
		extendedPublicKey_t extStakingPubKey;
		deriveExtendedPublicKey(&subctx->stakingKeyPath, &extStakingPubKey);
		auxDataHashBuilder_governanceVotingRegistration_addStakingKey(
		        &AUX_DATA_CTX->auxDataHashBuilder, extStakingPubKey.pubKey, SIZEOF(extStakingPubKey.pubKey)
		);
	}

	{
		// select UI step
		switch (policy) {
#define  CASE(POLICY, UI_STEP) case POLICY: {subctx->ui_step=UI_STEP; break;}
			CASE(POLICY_PROMPT_WARN_UNUSUAL, HANDLE_STAKING_KEY_STEP_WARNING);
			CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_STAKING_KEY_STEP_DISPLAY);
			CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_STAKING_KEY_STEP_RESPOND);
#undef   CASE
		default:
			THROW(ERR_NOT_IMPLEMENTED);
		}
	}

	signTxGovernanceVotingRegistration_handleStakingKey_ui_runStep();
}

// ============================== VOTING REWARDS ADDRESS ==============================

enum {
	HANDLE_VOTING_REWARDS_ADDRESS_PARAMS_STEP_WARNING = 8500,
	HANDLE_VOTING_REWARDS_ADDRESS_PARAMS_STEP_DISPLAY_ADDRESS,
	HANDLE_VOTING_REWARDS_ADDRESS_PARAMS_STEP_RESPOND,
	HANDLE_VOTING_REWARDS_ADDRESS_PARAMS_STEP_INVALID
};

__noinline_due_to_stack__
static void signTxGovernanceVotingRegistration_handleVotingRewardsAddress_addressParams_ui_runStep()
{
	governance_voting_registration_context_t* subctx = accessSubContext();
	TRACE("UI step %d", subctx->ui_step);
	TRACE_STACK_USAGE();
	ui_callback_fn_t* this_fn = signTxGovernanceVotingRegistration_handleVotingRewardsAddress_addressParams_ui_runStep;

	UI_STEP_BEGIN(subctx->ui_step, this_fn);

	UI_STEP(HANDLE_VOTING_REWARDS_ADDRESS_PARAMS_STEP_WARNING) {
		ui_displayPaginatedText(
		        "Unusual request",
		        "Proceed with care",
		        this_fn
		);
	}
	UI_STEP(HANDLE_VOTING_REWARDS_ADDRESS_PARAMS_STEP_DISPLAY_ADDRESS) {
		uint8_t addressBuffer[MAX_ADDRESS_SIZE] = {0};
		size_t addressSize = deriveAddress(
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
static void signTxGovernanceVotingRegistration_handleVotingRewardsAddressAPDU(const uint8_t* wireDataBuffer, size_t wireDataSize)
{
	{
		// safety checks
		CHECK_STATE(STATE_GOVERNANCE_VOTING_REGISTRATION_VOTING_REWARDS_ADDRESS);

		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}
	governance_voting_registration_context_t* subctx = accessSubContext();
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

	security_policy_t policy = policyForGovernanceVotingRegistrationVotingRewardsAddressParams(
	                                   &subctx->stateData.votingRewardsAddressParams,
	                                   commonTxData->networkId
	                           );
	TRACE("Policy: %d", (int) policy);
	ENSURE_NOT_DENIED(policy);

	{
		ASSERT(isShelleyAddressType(subctx->stateData.votingRewardsAddressParams.type));
		uint8_t addressBuffer[MAX_ADDRESS_SIZE] = {0};
		size_t addressSize = deriveAddress(
		                             &subctx->stateData.votingRewardsAddressParams,
		                             addressBuffer,
		                             SIZEOF(addressBuffer)
		                     );
		ASSERT(addressSize > 0);
		ASSERT(addressSize < BUFFER_SIZE_PARANOIA);

		auxDataHashBuilder_governanceVotingRegistration_addVotingRewardsAddress(
		        &AUX_DATA_CTX->auxDataHashBuilder, addressBuffer, addressSize
		);
	}

	{
		// select UI steps
		switch (policy) {
#define  CASE(POLICY, UI_STEP) case POLICY: {subctx->ui_step=UI_STEP; break;}
			CASE(POLICY_PROMPT_WARN_UNUSUAL, HANDLE_VOTING_REWARDS_ADDRESS_PARAMS_STEP_WARNING);
			CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_VOTING_REWARDS_ADDRESS_PARAMS_STEP_DISPLAY_ADDRESS);
			CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_VOTING_REWARDS_ADDRESS_PARAMS_STEP_RESPOND);
#undef   CASE
		default:
			THROW(ERR_NOT_IMPLEMENTED);
		}

		signTxGovernanceVotingRegistration_handleVotingRewardsAddress_addressParams_ui_runStep();
	}
}

// ============================== NONCE ==============================

enum {
	HANDLE_NONCE_STEP_DISPLAY = 8600,
	HANDLE_NONCE_STEP_RESPOND,
	HANDLE_NONCE_STEP_INVALID,
};

static void signTxGovernanceVotingRegistration_handleNonce_ui_runStep()
{
	governance_voting_registration_context_t* subctx = accessSubContext();
	TRACE("UI step %d", subctx->ui_step);
	TRACE_STACK_USAGE();
	ui_callback_fn_t* this_fn = signTxGovernanceVotingRegistration_handleNonce_ui_runStep;

	UI_STEP_BEGIN(subctx->ui_step, this_fn);

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
static void signTxGovernanceVotingRegistration_handleNonceAPDU(const uint8_t* wireDataBuffer, size_t wireDataSize)
{
	{
		// sanity checks
		CHECK_STATE(STATE_GOVERNANCE_VOTING_REGISTRATION_NONCE);

		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}
	governance_voting_registration_context_t* subctx = accessSubContext();
	{
		explicit_bzero(&subctx->stateData, SIZEOF(subctx->stateData));
	}
	{
		// parse data
		TRACE_BUFFER(wireDataBuffer, wireDataSize);
		VALIDATE(wireDataSize == 8, ERR_INVALID_DATA);
		subctx->stateData.nonce = u8be_read(wireDataBuffer);
		TRACE(
		        "Governance voting registration nonce: %d",
		        subctx->stateData.nonce
		);
	}

	security_policy_t policy = policyForGovernanceVotingRegistrationNonce();
	TRACE("Policy: %d", (int) policy);
	ENSURE_NOT_DENIED(policy);

	{
		auxDataHashBuilder_governanceVotingRegistration_addNonce(&AUX_DATA_CTX->auxDataHashBuilder, subctx->stateData.nonce);
	}

	{
		// select UI steps
		switch (policy) {
#define  CASE(POLICY, UI_STEP) case POLICY: {subctx->ui_step=UI_STEP; break;}
			CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_NONCE_STEP_DISPLAY);
			CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_NONCE_STEP_RESPOND);
#undef   CASE
		default:
			THROW(ERR_NOT_IMPLEMENTED);
		}
	}

	signTxGovernanceVotingRegistration_handleNonce_ui_runStep();
}

// ============================== CONFIRM ==============================

enum {
	HANDLE_CONFIRM_STEP_FINAL_CONFIRM,
	HANDLE_CONFIRM_STEP_DISPLAY_HASH,
	HANDLE_CONFIRM_STEP_RESPOND,
	HANDLE_CONFIRM_STEP_INVALID,
};

static void signTxGovernanceVotingRegistration_handleConfirm_ui_runStep()
{
	governance_voting_registration_context_t* subctx = accessSubContext();
	TRACE("UI step %d", subctx->ui_step);
	TRACE_STACK_USAGE();
	ui_callback_fn_t* this_fn = signTxGovernanceVotingRegistration_handleConfirm_ui_runStep;

	UI_STEP_BEGIN(subctx->ui_step, this_fn);
	UI_STEP(HANDLE_CONFIRM_STEP_FINAL_CONFIRM) {
		// confirming this means the signature being sent out of the device
		// so we want to show it in non-expert mode too
		ui_displayPrompt(
		        "Confirm voting key",
		        "registration?",
		        this_fn,
		        respond_with_user_reject
		);
	}
	UI_STEP(HANDLE_CONFIRM_STEP_DISPLAY_HASH) {
		if (!app_mode_expert()) {
			UI_STEP_JUMP(HANDLE_CONFIRM_STEP_RESPOND);
		}
		ui_displayHexBufferScreen(
		        "Auxiliary data hash",
		        subctx->auxDataHash,
		        SIZEOF(subctx->auxDataHash),
		        this_fn
		);
	}
	UI_STEP(HANDLE_CONFIRM_STEP_RESPOND) {
		struct {
			uint8_t auxDataHash[AUX_DATA_HASH_LENGTH];
			uint8_t signature[ED25519_SIGNATURE_LENGTH];
		} wireResponse = {0};

		STATIC_ASSERT(SIZEOF(subctx->auxDataHash) == AUX_DATA_HASH_LENGTH, "Wrong aux data hash length");
		memmove(wireResponse.auxDataHash, subctx->auxDataHash, AUX_DATA_HASH_LENGTH);

		STATIC_ASSERT(SIZEOF(subctx->stateData.registrationSignature) == ED25519_SIGNATURE_LENGTH, "Wrong governance voting registration signature length");
		memmove(wireResponse.signature, subctx->stateData.registrationSignature, ED25519_SIGNATURE_LENGTH);

		io_send_buf(SUCCESS, (uint8_t*) &wireResponse, SIZEOF(wireResponse));
		advanceState();
	}
	UI_STEP_END(HANDLE_CONFIRM_STEP_INVALID);
}

__noinline_due_to_stack__
static void signTxGovernanceVotingRegistration_handleConfirmAPDU(const uint8_t* wireDataBuffer MARK_UNUSED, size_t wireDataSize)
{
	{
		//sanity checks
		CHECK_STATE(STATE_GOVERNANCE_VOTING_REGISTRATION_CONFIRM);

		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}
	governance_voting_registration_context_t* subctx = accessSubContext();
	{
		explicit_bzero(&subctx->stateData, SIZEOF(subctx->stateData));
	}

	{
		// no data to receive
		VALIDATE(wireDataSize == 0, ERR_INVALID_DATA);
	}

	security_policy_t policy = policyForGovernanceVotingRegistrationConfirm();
	TRACE("Policy: %d", (int) policy);
	ENSURE_NOT_DENIED(policy);

	{
		aux_data_hash_builder_t* auxDataHashBuilder = &AUX_DATA_CTX->auxDataHashBuilder;
		{
			uint8_t votingPayloadHashBuffer[GOVERNANCE_VOTING_REGISTRATION_PAYLOAD_HASH_LENGTH] = {0};
			auxDataHashBuilder_governanceVotingRegistration_finalizePayload(auxDataHashBuilder, votingPayloadHashBuffer, AUX_DATA_HASH_LENGTH);
			getGovernanceVotingRegistrationSignature(
			        &subctx->stakingKeyPath,
			        votingPayloadHashBuffer, GOVERNANCE_VOTING_REGISTRATION_PAYLOAD_HASH_LENGTH,
			        subctx->stateData.registrationSignature, ED25519_SIGNATURE_LENGTH
			);
		}
		auxDataHashBuilder_governanceVotingRegistration_addSignature(auxDataHashBuilder, subctx->stateData.registrationSignature, ED25519_SIGNATURE_LENGTH);
		auxDataHashBuilder_governanceVotingRegistration_addAuxiliaryScripts(auxDataHashBuilder);

		auxDataHashBuilder_finalize(auxDataHashBuilder, subctx->auxDataHash, AUX_DATA_HASH_LENGTH);
	}

	{
		// select UI steps
		switch (policy) {
#define  CASE(POLICY, UI_STEP) case POLICY: {subctx->ui_step=UI_STEP; break;}
			CASE(POLICY_PROMPT_BEFORE_RESPONSE, HANDLE_CONFIRM_STEP_FINAL_CONFIRM);
			CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_CONFIRM_STEP_RESPOND);
#undef   CASE
		default:
			THROW(ERR_NOT_IMPLEMENTED);
		}
	}

	signTxGovernanceVotingRegistration_handleConfirm_ui_runStep();
}


// ============================== main APDU handler ==============================

enum {
	APDU_INSTRUCTION_VOTING_KEY = 0x30,
	APDU_INSTRUCTION_STAKING_KEY = 0x31,
	APDU_INSTRUCTION_VOTING_REWARDS_ADDRESS = 0x32,
	APDU_INSTRUCTION_NONCE = 0x33,
	APDU_INSTRUCTION_CONFIRM = 0x34
};

bool signTxGovernanceVotingRegistration_isValidInstruction(uint8_t p2)
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

void signTxGovernanceVotingRegistration_handleAPDU(uint8_t p2, const uint8_t* wireDataBuffer, size_t wireDataSize)
{
	ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);

	switch (p2) {
	case APDU_INSTRUCTION_VOTING_KEY:
		signTxGovernanceVotingRegistration_handleVotingKeyAPDU(wireDataBuffer, wireDataSize);
		break;

	case APDU_INSTRUCTION_STAKING_KEY:
		signTxGovernanceVotingRegistration_handleStakingKeyAPDU(wireDataBuffer, wireDataSize);
		break;

	case APDU_INSTRUCTION_VOTING_REWARDS_ADDRESS:
		signTxGovernanceVotingRegistration_handleVotingRewardsAddressAPDU(wireDataBuffer, wireDataSize);
		break;

	case APDU_INSTRUCTION_NONCE:
		signTxGovernanceVotingRegistration_handleNonceAPDU(wireDataBuffer, wireDataSize);
		break;

	case APDU_INSTRUCTION_CONFIRM:
		signTxGovernanceVotingRegistration_handleConfirmAPDU(wireDataBuffer, wireDataSize);
		break;

	default:
		// this is not supposed to be called with invalid p2
		ASSERT(false);
	}
}
