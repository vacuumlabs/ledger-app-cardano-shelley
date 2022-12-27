#include "app_mode.h"
#include "signTxCVoteRegistration.h"
#include "state.h"
#include "uiHelpers.h"
#include "signTxUtils.h"
#include "auxDataHashBuilder.h"
#include "txHashBuilder.h"
#include "textUtils.h"
#include "bufView.h"
#include "securityPolicy.h"
#include "messageSigning.h"
#include "signTxCVoteRegistration_ui.h"

static inline cvote_registration_context_t* accessSubContext()
{
	return &AUX_DATA_CTX->stageContext.cvote_registration_subctx;
}

// ============================== VOTING KEY ==============================

static void _displayVoteKey(ui_callback_fn_t callback)
{
	cvote_registration_context_t* subctx = accessSubContext();
	switch (subctx->stateData.delegation.type) {
	case DELEGATION_KEY: {
		STATIC_ASSERT(SIZEOF(subctx->stateData.delegation.votePubKey) == CVOTE_PUBLIC_KEY_LENGTH, "wrong vote public key size");
#ifdef HAVE_BAGL
		ui_displayBech32Screen(
		        "Vote public key",
		        "cvote_vk",
		        subctx->stateData.delegation.votePubKey, CVOTE_PUBLIC_KEY_LENGTH,
		        callback
		);
#elif defined(HAVE_NBGL)
        set_light_confirmation(true);
        char encodedStr[11 + BECH32_PREFIX_LENGTH_MAX + 2 * BECH32_BUFFER_SIZE_MAX] = {0};
        ui_getBech32Screen(encodedStr, SIZEOF(encodedStr), "cvote_vk", subctx->stateData.delegation.votePubKey, CVOTE_PUBLIC_KEY_LENGTH);
        fill_and_display_if_required("Vote public key", encodedStr, callback, respond_with_user_reject);
#endif // HAVE_BAGL
		break;
	}
	case DELEGATION_PATH: {
#ifdef HAVE_BAGL
		ui_displayPathScreen(
		        "Vote public key",
		        &subctx->stateData.delegation.votePubKeyPath,
		        callback
		);
#elif defined(HAVE_NBGL)
        set_light_confirmation(true);
        char pathStr[BIP44_PATH_STRING_SIZE_MAX + 1] = {0};
        ui_getPathScreen(pathStr, SIZEOF(pathStr), &subctx->stateData.delegation.votePubKeyPath);
        fill_and_display_if_required("Vote public key", pathStr, callback, respond_with_user_reject);
#endif // HAVE_BAGL
		break;
	}
	default:
		ASSERT(false);
	}
}

void signTxCVoteRegistration_handleVoteKey_ui_runStep()
{
	cvote_registration_context_t* subctx = accessSubContext();
	TRACE("UI step %d", subctx->ui_step);
	TRACE_STACK_USAGE();
	ui_callback_fn_t* this_fn = signTxCVoteRegistration_handleVoteKey_ui_runStep;

	UI_STEP_BEGIN(subctx->ui_step, this_fn);

	UI_STEP(HANDLE_VOTE_KEY_STEP_WARNING) {
#ifdef HAVE_BAGL
		ui_displayPaginatedText(
		        "WARNING:",
		        "unusual vote key",
		        this_fn
		);
#elif defined(HAVE_NBGL)
        set_light_confirmation(true);
        display_warning("Unusual\nvote key", this_fn, respond_with_user_reject);
#endif // HAVE_BAGL
	}
	UI_STEP(HANDLE_VOTE_KEY_STEP_DISPLAY) {
		_displayVoteKey(this_fn);
	}
	UI_STEP(HANDLE_VOTE_KEY_STEP_RESPOND) {
		respondSuccessEmptyMsg();
        voting_registration_advanceState();
	}
	UI_STEP_END(HANDLE_VOTE_KEY_STEP_INVALID);
}

// ============================== DELEGATION ==============================

void signTxCVoteRegistration_handleDelegation_ui_runStep()
{
	cvote_registration_context_t* subctx = accessSubContext();
	TRACE("UI step %d", subctx->ui_step);
	TRACE_STACK_USAGE();
	ui_callback_fn_t* this_fn = signTxCVoteRegistration_handleDelegation_ui_runStep;

	UI_STEP_BEGIN(subctx->ui_step, this_fn);

	UI_STEP(HANDLE_VOTE_KEY_STEP_WARNING) {
#ifdef HAVE_BAGL
		ui_displayPaginatedText(
		        "WARNING:",
		        "unusual vote key",
		        this_fn
		);
#elif defined(HAVE_NBGL)
        set_light_confirmation(true);
        display_warning("Unusual\nvote key", this_fn, respond_with_user_reject);
#endif // HAVE_BAGL
	}
	UI_STEP(HANDLE_DELEGATION_STEP_VOTE_KEY) {
		_displayVoteKey(this_fn);
	}
	UI_STEP(HANDLE_DELEGATION_STEP_WEIGHT) {
#ifdef HAVE_BAGL
		ui_displayUint64Screen(
		        "Weight",
		        subctx->stateData.delegation.weight,
		        this_fn
		);
#elif defined(HAVE_NBGL)
        set_light_confirmation(true);
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
static void signTxCVoteRegistration_handleStakingKey_ui_cb(void) {
	cvote_registration_context_t* subctx = accessSubContext();
    char line1[30] = {0};
    char pathStr[MAX(160,BIP44_PATH_STRING_SIZE_MAX + 1)] = {0};
    ui_getPublicKeyPathScreen(
            line1, SIZEOF(line1),
            pathStr, SIZEOF(pathStr),
            &subctx->stakingKeyPath
            );
    fill_and_display_if_required(line1, pathStr, signTxCVoteRegistration_handleStakingKey_ui_runStep, respond_with_user_reject);
}
#endif // HAVE_NBGL

void signTxCVoteRegistration_handleStakingKey_ui_runStep()
{
	cvote_registration_context_t* subctx = accessSubContext();
	TRACE("UI step %d", subctx->ui_step);
	TRACE_STACK_USAGE();
	ui_callback_fn_t* this_fn = signTxCVoteRegistration_handleStakingKey_ui_runStep;

	UI_STEP_BEGIN(subctx->ui_step, this_fn);

	UI_STEP(HANDLE_STAKING_KEY_STEP_WARNING) {
#ifdef HAVE_BAGL
		ui_displayPaginatedText(
		        "Unusual request",
		        "Proceed with care",
		        this_fn
		);
#elif defined(HAVE_NBGL)
        set_light_confirmation(true);
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
        set_light_confirmation(true);
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
            fill_and_display_if_required(line1, line2, signTxCVoteRegistration_handleStakingKey_ui_cb, respond_with_user_reject);
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
void signTxCVoteRegistration_handlePaymentAddress_ui_runStep()
{
	cvote_registration_context_t* subctx = accessSubContext();
	TRACE("UI step %d", subctx->ui_step);
	TRACE_STACK_USAGE();
	ui_callback_fn_t* this_fn = signTxCVoteRegistration_handlePaymentAddress_ui_runStep;

	UI_STEP_BEGIN(subctx->ui_step, this_fn);

	UI_STEP(HANDLE_PAYMENT_ADDRESS_PARAMS_STEP_WARNING) {
#ifdef HAVE_BAGL
		ui_displayPaginatedText(
		        "Unusual request",
		        "Proceed with care",
		        this_fn
		);
#elif defined(HAVE_NBGL)
        set_light_confirmation(true);
        display_warning("Unusual request\nProceed with care", this_fn, respond_with_user_reject);
#endif // HAVE_BAGL
	}
	UI_STEP(HANDLE_PAYMENT_ADDRESS_PARAMS_STEP_DISPLAY_ADDRESS) {
		uint8_t addressBuffer[MAX_ADDRESS_SIZE] = {0};
		size_t addressSize = _destinationToAddress(
		                             &subctx->stateData.paymentDestination,
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
        set_light_confirmation(true);
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
	UI_STEP(HANDLE_PAYMENT_ADDRESS_PARAMS_STEP_RESPOND) {
		respondSuccessEmptyMsg();
		voting_registration_advanceState();
	}
	UI_STEP_END(HANDLE_PAYMENT_ADDRESS_PARAMS_STEP_INVALID);
}

// ============================== NONCE ==============================

void signTxCVoteRegistration_handleNonce_ui_runStep()
{
	cvote_registration_context_t* subctx = accessSubContext();
	TRACE("UI step %d", subctx->ui_step);
	TRACE_STACK_USAGE();
	ui_callback_fn_t* this_fn = signTxCVoteRegistration_handleNonce_ui_runStep;

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

void signTxCVoteRegistration_handleVotingPurpose_ui_runStep()
{
	cvote_registration_context_t* subctx = accessSubContext();
	TRACE("UI step %d", subctx->ui_step);
	TRACE_STACK_USAGE();
	ui_callback_fn_t* this_fn = signTxCVoteRegistration_handleVotingPurpose_ui_runStep;

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

void signTxCVoteRegistration_handleConfirm_ui_runStep()
{
	cvote_registration_context_t* subctx = accessSubContext();
	TRACE("UI step %d", subctx->ui_step);
	TRACE_STACK_USAGE();
	ui_callback_fn_t* this_fn = signTxCVoteRegistration_handleConfirm_ui_runStep;

	UI_STEP_BEGIN(subctx->ui_step, this_fn);
	UI_STEP(HANDLE_CONFIRM_STEP_FINAL_CONFIRM) {
		// confirming this means the signature being sent out of the device
		// so we want to show it in non-expert mode too
#ifdef HAVE_BAGL
		ui_displayPrompt(
		        "Confirm vote key",
		        "registration?",
		        this_fn,
		        respond_with_user_reject
		);
#elif defined(HAVE_NBGL)
        display_confirmation(
                "Confirm vote key\nregistration",
                "",
                "VOTE KEY\nCONFIRMED",
                "Vote key\nrejected",
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

		STATIC_ASSERT(SIZEOF(subctx->stateData.registrationSignature) == ED25519_SIGNATURE_LENGTH, "Wrong CIP-36 voting registration signature length");
		memmove(wireResponse.signature, subctx->stateData.registrationSignature, ED25519_SIGNATURE_LENGTH);

		io_send_buf(SUCCESS, (uint8_t*) &wireResponse, SIZEOF(wireResponse));
		voting_registration_advanceState();
	}
	UI_STEP_END(HANDLE_CONFIRM_STEP_INVALID);
}

