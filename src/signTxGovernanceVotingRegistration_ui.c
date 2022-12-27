#include "app_mode.h"
#include "signTxGovernanceVotingRegistration.h"
#include "state.h"
#include "uiHelpers.h"
#include "signTxUtils.h"
#include "auxDataHashBuilder.h"
#include "txHashBuilder.h"
#include "textUtils.h"
#include "bufView.h"
#include "securityPolicy.h"
#include "messageSigning.h"
#include "signTxGovernanceVotingRegistration_ui.h"

static inline governance_voting_registration_context_t* accessSubContext()
{
	return &AUX_DATA_CTX->stageContext.governance_voting_registration_subctx;
}

// ============================== VOTING KEY ==============================

static void _displayVotingKey(ui_callback_fn_t callback)
{
	governance_voting_registration_context_t* subctx = accessSubContext();
	switch (subctx->stateData.delegation.type) {
	case DELEGATION_KEY: {
		STATIC_ASSERT(SIZEOF(subctx->stateData.delegation.votingPubKey) == GOVERNANCE_VOTING_PUBLIC_KEY_LENGTH, "wrong voting public key size");
#ifdef HAVE_BAGL
		ui_displayBech32Screen(
		        "Voting public key",
		        "gov_vk",
		        subctx->stateData.delegation.votingPubKey, GOVERNANCE_VOTING_PUBLIC_KEY_LENGTH,
		        callback
		);
#elif defined(HAVE_NBGL)
        char encodedStr[11 + BECH32_PREFIX_LENGTH_MAX + 2 * BECH32_BUFFER_SIZE_MAX] = {0};
        ui_getBech32Screen(encodedStr, SIZEOF(encodedStr), "gov_vk", subctx->stateData.delegation.votingPubKey, GOVERNANCE_VOTING_PUBLIC_KEY_LENGTH);
        fill_and_display_if_required("Voting public key", encodedStr, callback, respond_with_user_reject);
#endif // HAVE_BAGL
		break;
	}
	case DELEGATION_PATH: {
#ifdef HAVE_BAGL
		ui_displayPathScreen(
		        "Voting public key",
		        &subctx->stateData.delegation.votingPubKeyPath,
		        callback
		);
#elif defined(HAVE_NBGL)
            char pathStr[BIP44_PATH_STRING_SIZE_MAX + 1] = {0};
            ui_getPathScreen(pathStr, SIZEOF(pathStr), &subctx->stateData.delegation.votingPubKeyPath);
            fill_and_display_if_required("Voting public key", pathStr, callback, respond_with_user_reject);
#endif // HAVE_BAGL
		break;
	}
	default:
		ASSERT(false);
	}
}

void signTxGovernanceVotingRegistration_handleVotingKey_ui_runStep()
{
	governance_voting_registration_context_t* subctx = accessSubContext();
	TRACE("UI step %d", subctx->ui_step);
	TRACE_STACK_USAGE();
	ui_callback_fn_t* this_fn = signTxGovernanceVotingRegistration_handleVotingKey_ui_runStep;

	UI_STEP_BEGIN(subctx->ui_step, this_fn);

	UI_STEP(HANDLE_VOTING_KEY_STEP_WARNING) {
#ifdef HAVE_BAGL
		ui_displayPaginatedText(
		        "WARNING:",
		        "unusual voting key",
		        this_fn
		);
#elif defined(HAVE_NBGL)
        display_warning("Unusual\nvoting key", this_fn, respond_with_user_reject);
#endif // HAVE_BAGL
	}
	UI_STEP(HANDLE_VOTING_KEY_STEP_DISPLAY) {
		_displayVotingKey(this_fn);
	}
	UI_STEP(HANDLE_VOTING_KEY_STEP_RESPOND) {
		respondSuccessEmptyMsg();
		voting_registration_advanceState();
	}
	UI_STEP_END(HANDLE_VOTING_KEY_STEP_INVALID);
}

// ============================== DELEGATION ==============================

void signTxGovernanceVotingRegistration_handleDelegation_ui_runStep()
{
	governance_voting_registration_context_t* subctx = accessSubContext();
	TRACE("UI step %d", subctx->ui_step);
	TRACE_STACK_USAGE();
	ui_callback_fn_t* this_fn = signTxGovernanceVotingRegistration_handleDelegation_ui_runStep;

	UI_STEP_BEGIN(subctx->ui_step, this_fn);

	UI_STEP(HANDLE_VOTING_KEY_STEP_WARNING) {
#ifdef HAVE_BAGL
		ui_displayPaginatedText(
		        "WARNING:",
		        "unusual voting key",
		        this_fn
		);
#elif defined(HAVE_NBGL)
        display_warning("Unusual\nvoting key", this_fn, respond_with_user_reject);
#endif // HAVE_BAGL
	}
	UI_STEP(HANDLE_DELEGATION_STEP_VOTING_KEY) {
		_displayVotingKey(this_fn);
	}
	UI_STEP(HANDLE_DELEGATION_STEP_WEIGHT) {
#ifdef HAVE_BAGL
		ui_displayUint64Screen(
		        "Weight",
		        subctx->stateData.delegation.weight,
		        this_fn
		);
#elif defined(HAVE_NBGL)
        char line[30];
		ui_getUint64Screen(
                line,
                SIZEOF(line),
		        subctx->stateData.delegation.weight
		);
        fill_and_display_if_required("Weight", line, this_fn, respond_with_user_reject);
#endif // HAVE_BAGL
	}
	UI_STEP(HANDLE_DELEGATION_STEP_RESPOND) {
		respondSuccessEmptyMsg();
		subctx->currentDelegation++;
		if (subctx->currentDelegation == subctx->numDelegations) {
			voting_registration_advanceState();
		}
	}
	UI_STEP_END(HANDLE_DELEGATION_STEP_INVALID);
}

// ============================== STAKING KEY ==============================

#ifdef HAVE_NBGL
static void signTxGovernanceVotingRegistration_handleStakingKey_ui_cb(void) {
	governance_voting_registration_context_t* subctx = accessSubContext();
    char line1[30] = {0};
    char pathStr[MAX(160,BIP44_PATH_STRING_SIZE_MAX + 1)] = {0};
    ui_getPublicKeyPathScreen(
            line1, SIZEOF(line1),
            pathStr, SIZEOF(pathStr),
            &subctx->stakingKeyPath
            );
    fill_and_display_if_required(line1, pathStr, signTxGovernanceVotingRegistration_handleStakingKey_ui_runStep, respond_with_user_reject);
}
#endif // HAVE_NBGL

void signTxGovernanceVotingRegistration_handleStakingKey_ui_runStep()
{
	governance_voting_registration_context_t* subctx = accessSubContext();
	TRACE("UI step %d", subctx->ui_step);
	TRACE_STACK_USAGE();
	ui_callback_fn_t* this_fn = signTxGovernanceVotingRegistration_handleStakingKey_ui_runStep;

	UI_STEP_BEGIN(subctx->ui_step, this_fn);

	UI_STEP(HANDLE_STAKING_KEY_STEP_WARNING) {
#ifdef HAVE_BAGL
		ui_displayPaginatedText(
		        "Unusual request",
		        "Proceed with care",
		        this_fn
		);
#elif defined(HAVE_NBGL)
        display_warning("Unusual request\nProceed with care", this_fn, respond_with_user_reject);
#endif // HAVE_BAGL
	}
	UI_STEP(HANDLE_STAKING_KEY_STEP_DISPLAY) {
#ifdef HAVE_BAGL
		ui_displayStakingKeyScreen(
		        &subctx->stakingKeyPath,
		        this_fn
		);
#elif defined(HAVE_NBGL)
        bool showAccountDescription = bip44_isPathReasonable(&subctx->stakingKeyPath);
        if (showAccountDescription) {
            char line1[30];
            char line2[30];
            ui_getAccountScreeen(
                    line1,
                    SIZEOF(line1),
                    line2,
                    SIZEOF(line2),
                    &subctx->stakingKeyPath
            );
            fill_and_display_if_required(line1, line2, signTxGovernanceVotingRegistration_handleStakingKey_ui_cb, respond_with_user_reject);
        }
#endif // HAVE_BAGL
	}
	UI_STEP(HANDLE_STAKING_KEY_STEP_RESPOND) {
		respondSuccessEmptyMsg();
		voting_registration_advanceState();
	}
	UI_STEP_END(HANDLE_STAKING_KEY_STEP_INVALID);
}

// ============================== VOTING REWARDS ADDRESS ==============================

__noinline_due_to_stack__
void signTxGovernanceVotingRegistration_handleVotingRewardsAddress_ui_runStep()
{
	governance_voting_registration_context_t* subctx = accessSubContext();
	TRACE("UI step %d", subctx->ui_step);
	TRACE_STACK_USAGE();
	ui_callback_fn_t* this_fn = signTxGovernanceVotingRegistration_handleVotingRewardsAddress_ui_runStep;

	UI_STEP_BEGIN(subctx->ui_step, this_fn);

	UI_STEP(HANDLE_VOTING_REWARDS_ADDRESS_PARAMS_STEP_WARNING) {
#ifdef HAVE_BAGL
		ui_displayPaginatedText(
		        "Unusual request",
		        "Proceed with care",
		        this_fn
		);
#elif defined(HAVE_NBGL)
        display_warning("Unusual request\nProceed with care", this_fn, respond_with_user_reject);
#endif // HAVE_BAGL
	}
	UI_STEP(HANDLE_VOTING_REWARDS_ADDRESS_PARAMS_STEP_DISPLAY_ADDRESS) {
		uint8_t addressBuffer[MAX_ADDRESS_SIZE] = {0};
		size_t addressSize = _destinationToAddress(
		                             &subctx->stateData.rewardDestination,
		                             addressBuffer, SIZEOF(addressBuffer)
		                     );

#ifdef HAVE_BAGL
		ui_displayAddressScreen(
		        "Rewards go to",
		        addressBuffer,
		        addressSize,
		        this_fn
		);
#elif defined(HAVE_NBGL)
        char humanAddress[MAX_HUMAN_ADDRESS_SIZE] = {0};
		ui_getAddressScreen(
                humanAddress,
                SIZEOF(humanAddress),
		        addressBuffer,
		        addressSize
		);
        fill_and_display_if_required("Rewards go to", humanAddress, this_fn, respond_with_user_reject);
#endif // HAVE_BAGL
	}
	UI_STEP(HANDLE_VOTING_REWARDS_ADDRESS_PARAMS_STEP_RESPOND) {
		respondSuccessEmptyMsg();
		voting_registration_advanceState();
	}
	UI_STEP_END(HANDLE_VOTING_REWARDS_ADDRESS_PARAMS_STEP_INVALID);
}

// ============================== NONCE ==============================

void signTxGovernanceVotingRegistration_handleNonce_ui_runStep()
{
	governance_voting_registration_context_t* subctx = accessSubContext();
	TRACE("UI step %d", subctx->ui_step);
	TRACE_STACK_USAGE();
	ui_callback_fn_t* this_fn = signTxGovernanceVotingRegistration_handleNonce_ui_runStep;

	UI_STEP_BEGIN(subctx->ui_step, this_fn);

	UI_STEP(HANDLE_NONCE_STEP_DISPLAY) {
#ifdef HAVE_BAGL
		ui_displayUint64Screen(
		        "Nonce",
		        subctx->stateData.nonce,
		        this_fn
		);
#elif defined(HAVE_NBGL)
        char line[30];
		ui_getUint64Screen(
                line,
                SIZEOF(line),
		        subctx->stateData.nonce
		);
        fill_and_display_if_required("Nonce", line, this_fn, respond_with_user_reject);
#endif // HAVE_BAGL
	}
	UI_STEP(HANDLE_NONCE_STEP_RESPOND) {
		respondSuccessEmptyMsg();
		voting_registration_advanceState();
	}
	UI_STEP_END(HANDLE_NONCE_STEP_INVALID);
}

// ============================== VOTING PURPOSE ==============================

void signTxGovernanceVotingRegistration_handleVotingPurpose_ui_runStep()
{
	governance_voting_registration_context_t* subctx = accessSubContext();
	TRACE("UI step %d", subctx->ui_step);
	TRACE_STACK_USAGE();
	ui_callback_fn_t* this_fn = signTxGovernanceVotingRegistration_handleVotingPurpose_ui_runStep;

	UI_STEP_BEGIN(subctx->ui_step, this_fn);

	UI_STEP(HANDLE_VOTING_PURPOSE_STEP_DISPLAY) {
#ifdef HAVE_BAGL
		ui_displayUint64Screen(
		        "Voting purpose",
		        subctx->stateData.votingPurpose,
		        this_fn
		);
#elif defined(HAVE_NBGL)
        char line[30];
		ui_getUint64Screen(
                line,
                SIZEOF(line),
		        subctx->stateData.votingPurpose
		);
        fill_and_display_if_required("Voting purpose", line, this_fn, respond_with_user_reject);
#endif // HAVE_BAGL
	}
	UI_STEP(HANDLE_VOTING_PURPOSE_STEP_RESPOND) {
		respondSuccessEmptyMsg();
		voting_registration_advanceState();
	}
	UI_STEP_END(HANDLE_VOTING_PURPOSE_STEP_INVALID);
}

// ============================== CONFIRM ==============================

void signTxGovernanceVotingRegistration_handleConfirm_ui_runStep()
{
	governance_voting_registration_context_t* subctx = accessSubContext();
	TRACE("UI step %d", subctx->ui_step);
	TRACE_STACK_USAGE();
	ui_callback_fn_t* this_fn = signTxGovernanceVotingRegistration_handleConfirm_ui_runStep;

	UI_STEP_BEGIN(subctx->ui_step, this_fn);
	UI_STEP(HANDLE_CONFIRM_STEP_FINAL_CONFIRM) {
		// confirming this means the signature being sent out of the device
		// so we want to show it in non-expert mode too
#ifdef HAVE_BAGL
		ui_displayPrompt(
		        "Confirm voting key",
		        "registration?",
		        this_fn,
		        respond_with_user_reject
		);
#elif defined(HAVE_NBGL)
        display_confirmation(
                "Confirm voting key\nregistration",
                "",
                "VOTING KEY\nCONFIRMED",
                "Voting key\nrejected",
                this_fn, 
                respond_with_user_reject
        );
#endif // HAVE_BAGL
	}
	UI_STEP(HANDLE_CONFIRM_STEP_DISPLAY_HASH) {
		if (!app_mode_expert()) {
			UI_STEP_JUMP(HANDLE_CONFIRM_STEP_RESPOND);
		}
#ifdef HAVE_BAGL
		ui_displayHexBufferScreen(
		        "Auxiliary data hash",
		        subctx->auxDataHash,
		        SIZEOF(subctx->auxDataHash),
		        this_fn
		);
#elif defined(HAVE_NBGL)
        char bufferHex[2 * 32 + 1] = {0};
        ui_getHexBufferScreen(bufferHex, SIZEOF(bufferHex), subctx->auxDataHash, SIZEOF(subctx->auxDataHash));
        fill_and_display_if_required("Auxiliary data hash", bufferHex, this_fn, respond_with_user_reject);
#endif // HAVE_BAGL
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
		voting_registration_advanceState();
	}
	UI_STEP_END(HANDLE_CONFIRM_STEP_INVALID);
}

