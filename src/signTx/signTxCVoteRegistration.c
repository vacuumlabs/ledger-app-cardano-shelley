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

static common_tx_data_t* commonTxData = &(instructionState.signTxContext.commonTxData);

static inline cvote_registration_context_t* accessSubContext() {
    return &AUX_DATA_CTX->stageContext.cvote_registration_subctx;
}

bool signTxCVoteRegistration_isFinished() {
    const cvote_registration_context_t* subctx = accessSubContext();
    TRACE("CIP-36 voting registration submachine state: %d", subctx->state);
    // we are also asserting that the state is valid
    switch (subctx->state) {
        case STATE_CVOTE_REGISTRATION_FINISHED:
            return true;

        case STATE_CVOTE_REGISTRATION_INIT:
        case STATE_CVOTE_REGISTRATION_VOTE_KEY:
        case STATE_CVOTE_REGISTRATION_DELEGATIONS:
        case STATE_CVOTE_REGISTRATION_STAKING_KEY:
        case STATE_CVOTE_REGISTRATION_PAYMENT_ADDRESS:
        case STATE_CVOTE_REGISTRATION_NONCE:
        case STATE_CVOTE_REGISTRATION_VOTING_PURPOSE:
        case STATE_CVOTE_REGISTRATION_CONFIRM:
            return false;

        default:
            ASSERT(false);
    }
}

void signTxCVoteRegistration_init() {
    explicit_bzero(&AUX_DATA_CTX->stageContext, SIZEOF(AUX_DATA_CTX->stageContext));
    auxDataHashBuilder_init(&AUX_DATA_CTX->auxDataHashBuilder);

    accessSubContext()->state = STATE_CVOTE_REGISTRATION_INIT;
}

static inline void CHECK_STATE(sign_tx_cvote_registration_state_t expected) {
    TRACE("CIP-36 voting registration submachine state: current %d, expected %d",
          accessSubContext()->state,
          expected);
    VALIDATE(accessSubContext()->state == expected, ERR_INVALID_STATE);
}

void voting_registration_advanceState() {
    cvote_registration_context_t* subctx = accessSubContext();
    TRACE("Advancing CIP-36 voting registration state from: %d", subctx->state);

    switch (subctx->state) {
        case STATE_CVOTE_REGISTRATION_INIT:
            if (subctx->numDelegations > 0) {
                subctx->state = STATE_CVOTE_REGISTRATION_DELEGATIONS;
                auxDataHashBuilder_cVoteRegistration_enterDelegations(
                    &AUX_DATA_CTX->auxDataHashBuilder,
                    subctx->numDelegations);
            } else {
                // we expect a single vote key
                subctx->state = STATE_CVOTE_REGISTRATION_VOTE_KEY;
            }
            break;

        case STATE_CVOTE_REGISTRATION_DELEGATIONS:
            ASSERT(subctx->currentDelegation == subctx->numDelegations);
            subctx->state = STATE_CVOTE_REGISTRATION_STAKING_KEY;
            break;

        case STATE_CVOTE_REGISTRATION_VOTE_KEY:
            subctx->state = STATE_CVOTE_REGISTRATION_STAKING_KEY;
            break;

        case STATE_CVOTE_REGISTRATION_STAKING_KEY:
            subctx->state = STATE_CVOTE_REGISTRATION_PAYMENT_ADDRESS;
            break;

        case STATE_CVOTE_REGISTRATION_PAYMENT_ADDRESS:
            subctx->state = STATE_CVOTE_REGISTRATION_NONCE;
            break;

        case STATE_CVOTE_REGISTRATION_NONCE:
            subctx->state = STATE_CVOTE_REGISTRATION_VOTING_PURPOSE;
            break;

        case STATE_CVOTE_REGISTRATION_VOTING_PURPOSE:
            subctx->state = STATE_CVOTE_REGISTRATION_CONFIRM;
            break;

        case STATE_CVOTE_REGISTRATION_CONFIRM:
            subctx->state = STATE_CVOTE_REGISTRATION_FINISHED;
            break;

        default:
            ASSERT(false);
    }

    TRACE("Advancing CIP-36 voting registration state to: %d", subctx->state);
}

// ============================== INIT ==============================

static void signTxCVoteRegistration_handleInitAPDU(const uint8_t* wireDataBuffer,
                                                   size_t wireDataSize) {
    { CHECK_STATE(STATE_CVOTE_REGISTRATION_INIT); }
    cvote_registration_context_t* subctx = accessSubContext();
    { explicit_bzero(&subctx->stateData, SIZEOF(subctx->stateData)); }
    {
        TRACE_BUFFER(wireDataBuffer, wireDataSize);

        {
            read_view_t view = make_read_view(wireDataBuffer, wireDataBuffer + wireDataSize);

            subctx->format = parse_u1be(&view);
            TRACE("CIP-36 voting registration format = %d", (int) subctx->format);
            switch (subctx->format) {
                case CIP15:
                case CIP36:
                    break;
                default:
                    THROW(ERR_INVALID_DATA);
            }

            subctx->numDelegations = (uint16_t) parse_u4be(&view);
            TRACE("numDelegations = %u", subctx->numDelegations);
            if (subctx->format == CIP15) {
                // delegations only allowed in CIP36
                VALIDATE(subctx->numDelegations == 0, ERR_INVALID_DATA);
            }

            VALIDATE(view_remainingSize(&view) == 0, ERR_INVALID_DATA);
        }
    }
    {
        aux_data_hash_builder_t* auxDataHashBuilder = &AUX_DATA_CTX->auxDataHashBuilder;
        auxDataHashBuilder_cVoteRegistration_enter(auxDataHashBuilder, subctx->format);
        auxDataHashBuilder_cVoteRegistration_enterPayload(auxDataHashBuilder);
    }

    respondSuccessEmptyMsg();
    voting_registration_advanceState();
}

// ============================== VOTING KEY ==============================

static void _parseVoteKey(read_view_t* view) {
    cvote_registration_context_t* subctx = accessSubContext();

    subctx->stateData.delegation.type = parse_u1be(view);
    TRACE("delegation type = %d", (int) subctx->stateData.delegation.type);
    switch (subctx->stateData.delegation.type) {
        case DELEGATION_KEY: {
            STATIC_ASSERT(
                SIZEOF(subctx->stateData.delegation.votePubKey) == CVOTE_PUBLIC_KEY_LENGTH,
                "wrong vote public key size");
            view_parseBuffer(subctx->stateData.delegation.votePubKey,
                             view,
                             CVOTE_PUBLIC_KEY_LENGTH);
            break;
        }

        case DELEGATION_PATH: {
            view_skipBytes(view,
                           bip44_parseFromWire(&subctx->stateData.delegation.votePubKeyPath,
                                               VIEW_REMAINING_TO_TUPLE_BUF_SIZE(view)));
            TRACE();
            BIP44_PRINTF(&subctx->stateData.delegation.votePubKeyPath);
            PRINTF("\n");
            break;
        }

        default:
            THROW(ERR_INVALID_DATA);
    }
}

security_policy_t _determineVoteKeyPolicy() {
    cvote_registration_context_t* subctx = accessSubContext();

    switch (subctx->stateData.delegation.type) {
        case DELEGATION_PATH:
            return policyForCVoteRegistrationVoteKeyPath(
                &subctx->stateData.delegation.votePubKeyPath,
                subctx->format);

        case DELEGATION_KEY:
            return policyForCVoteRegistrationVoteKey();

        default:
            ASSERT(false);
    }
    return POLICY_DENY;
}

__noinline_due_to_stack__ static void signTxCVoteRegistration_handleVoteKeyAPDU(
    const uint8_t* wireDataBuffer,
    size_t wireDataSize) {
    { CHECK_STATE(STATE_CVOTE_REGISTRATION_VOTE_KEY); }
    cvote_registration_context_t* subctx = accessSubContext();
    { explicit_bzero(&subctx->stateData, SIZEOF(subctx->stateData)); }
    {
        TRACE_BUFFER(wireDataBuffer, wireDataSize);
        read_view_t view = make_read_view(wireDataBuffer, wireDataBuffer + wireDataSize);

        _parseVoteKey(&view);

        VALIDATE(view_remainingSize(&view) == 0, ERR_INVALID_DATA);
    }

    security_policy_t policy = _determineVoteKeyPolicy();
    TRACE("Policy: %d", (int) policy);
    ENSURE_NOT_DENIED(policy);

    {
        // add the key to hashbuilder
        aux_data_hash_builder_t* auxDataHashBuilder = &AUX_DATA_CTX->auxDataHashBuilder;

        switch (subctx->stateData.delegation.type) {
            case DELEGATION_KEY: {
                auxDataHashBuilder_cVoteRegistration_addVoteKey(
                    auxDataHashBuilder,
                    subctx->stateData.delegation.votePubKey,
                    CVOTE_PUBLIC_KEY_LENGTH);
                break;
            }

            case DELEGATION_PATH: {
                extendedPublicKey_t extVotePubKey;
                deriveExtendedPublicKey(&subctx->stateData.delegation.votePubKeyPath,
                                        &extVotePubKey);
                auxDataHashBuilder_cVoteRegistration_addVoteKey(auxDataHashBuilder,
                                                                extVotePubKey.pubKey,
                                                                SIZEOF(extVotePubKey.pubKey));
                break;
            }

            default:
                ASSERT(false);
        }
    }

    {
        // select UI steps
        switch (policy) {
#define CASE(POLICY, UI_STEP)      \
    case POLICY: {                 \
        subctx->ui_step = UI_STEP; \
        break;                     \
    }
            CASE(POLICY_PROMPT_WARN_UNUSUAL, HANDLE_VOTE_KEY_STEP_WARNING);
            CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_VOTE_KEY_STEP_DISPLAY);
            CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_VOTE_KEY_STEP_RESPOND);
#undef CASE
            default:
                THROW(ERR_NOT_IMPLEMENTED);
        }
    }

    signTxCVoteRegistration_handleVoteKey_ui_runStep();
}

// ============================== DELEGATION ==============================

__noinline_due_to_stack__ static void signTxCVoteRegistration_handleDelegationAPDU(
    const uint8_t* wireDataBuffer,
    size_t wireDataSize) {
    cvote_registration_context_t* subctx = accessSubContext();
    {
        CHECK_STATE(STATE_CVOTE_REGISTRATION_DELEGATIONS);
        ASSERT(subctx->currentDelegation < subctx->numDelegations);
    }
    { explicit_bzero(&subctx->stateData, SIZEOF(subctx->stateData)); }
    {
        TRACE_BUFFER(wireDataBuffer, wireDataSize);
        read_view_t view = make_read_view(wireDataBuffer, wireDataBuffer + wireDataSize);

        _parseVoteKey(&view);

        subctx->stateData.delegation.weight = parse_u4be(&view);
        TRACE("CIP-36 voting registration delegation weight:");
        TRACE_UINT64(subctx->stateData.delegation.weight);

        VALIDATE(view_remainingSize(&view) == 0, ERR_INVALID_DATA);
    }

    security_policy_t policy = _determineVoteKeyPolicy();
    TRACE("Policy: %d", (int) policy);
    ENSURE_NOT_DENIED(policy);

    {
        // add the key to hashbuilder
        aux_data_hash_builder_t* auxDataHashBuilder = &AUX_DATA_CTX->auxDataHashBuilder;

        switch (subctx->stateData.delegation.type) {
            case DELEGATION_KEY: {
                auxDataHashBuilder_cVoteRegistration_addDelegation(
                    auxDataHashBuilder,
                    subctx->stateData.delegation.votePubKey,
                    CVOTE_PUBLIC_KEY_LENGTH,
                    subctx->stateData.delegation.weight);
                break;
            }

            case DELEGATION_PATH: {
                extendedPublicKey_t extVotePubKey;
                deriveExtendedPublicKey(&subctx->stateData.delegation.votePubKeyPath,
                                        &extVotePubKey);
                auxDataHashBuilder_cVoteRegistration_addDelegation(
                    auxDataHashBuilder,
                    extVotePubKey.pubKey,
                    SIZEOF(extVotePubKey.pubKey),
                    subctx->stateData.delegation.weight);
                break;
            }

            default:
                ASSERT(false);
        }
    }
    {
        // select UI steps
        switch (policy) {
#define CASE(POLICY, UI_STEP)      \
    case POLICY: {                 \
        subctx->ui_step = UI_STEP; \
        break;                     \
    }
            CASE(POLICY_PROMPT_WARN_UNUSUAL, HANDLE_DELEGATION_STEP_WARNING);
            CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_DELEGATION_STEP_VOTE_KEY);
            CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_DELEGATION_STEP_RESPOND);
#undef CASE
            default:
                THROW(ERR_NOT_IMPLEMENTED);
        }
    }

    signTxCVoteRegistration_handleDelegation_ui_runStep();
}

// ============================== STAKE KEY ==============================

__noinline_due_to_stack__ static void signTxCVoteRegistration_handleStakingKeyAPDU(
    const uint8_t* wireDataBuffer,
    size_t wireDataSize) {
    TRACE_STACK_USAGE();
    {
        // sanity checks
        CHECK_STATE(STATE_CVOTE_REGISTRATION_STAKING_KEY);
    }
    cvote_registration_context_t* subctx = accessSubContext();
    { explicit_bzero(&subctx->stakingKeyPath, SIZEOF(subctx->stakingKeyPath)); }
    {
        // parse input
        TRACE_BUFFER(wireDataBuffer, wireDataSize);

        read_view_t view = make_read_view(wireDataBuffer, wireDataBuffer + wireDataSize);

        view_skipBytes(
            &view,
            bip44_parseFromWire(&subctx->stakingKeyPath, VIEW_REMAINING_TO_TUPLE_BUF_SIZE(&view)));

        VALIDATE(view_remainingSize(&view) == 0, ERR_INVALID_DATA);
    }

    security_policy_t policy = policyForCVoteRegistrationStakingKey(&subctx->stakingKeyPath);
    TRACE("Policy: %d", (int) policy);
    ENSURE_NOT_DENIED(policy);

    {
        extendedPublicKey_t extStakingPubKey;
        deriveExtendedPublicKey(&subctx->stakingKeyPath, &extStakingPubKey);
        auxDataHashBuilder_cVoteRegistration_addStakingKey(&AUX_DATA_CTX->auxDataHashBuilder,
                                                           extStakingPubKey.pubKey,
                                                           SIZEOF(extStakingPubKey.pubKey));
    }

    {
        // select UI step
        switch (policy) {
#define CASE(POLICY, UI_STEP)      \
    case POLICY: {                 \
        subctx->ui_step = UI_STEP; \
        break;                     \
    }
            CASE(POLICY_PROMPT_WARN_UNUSUAL, HANDLE_STAKING_KEY_STEP_WARNING);
            CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_STAKING_KEY_STEP_DISPLAY);
            CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_STAKING_KEY_STEP_RESPOND);
#undef CASE
            default:
                THROW(ERR_NOT_IMPLEMENTED);
        }
    }

    signTxCVoteRegistration_handleStakingKey_ui_runStep();
}

// ============================== VOTING REWARDS ADDRESS ==============================

size_t _destinationToAddress(tx_output_destination_storage_t* destination,
                             uint8_t* addressBuffer,
                             size_t addressBufferSize) {
    size_t addressSize = 0;

    switch (destination->type) {
        case DESTINATION_DEVICE_OWNED:
            addressSize = deriveAddress(&destination->params, addressBuffer, addressBufferSize);
            break;

        case DESTINATION_THIRD_PARTY:
            addressSize = destination->address.size;
            ASSERT(addressSize <= addressBufferSize);
            memmove(addressBuffer, destination->address.buffer, addressSize);
            break;

        default:
            ASSERT(false);
    }

    return addressSize;
}

__noinline_due_to_stack__ static void signTxCVoteRegistration_handlePaymentAddressAPDU(
    const uint8_t* wireDataBuffer,
    size_t wireDataSize) {
    {
        // safety checks
        CHECK_STATE(STATE_CVOTE_REGISTRATION_PAYMENT_ADDRESS);
    }
    cvote_registration_context_t* subctx = accessSubContext();
    {
        explicit_bzero(&subctx->stateData.paymentDestination,
                       SIZEOF(subctx->stateData.paymentDestination));
    }
    {
        TRACE_BUFFER(wireDataBuffer, wireDataSize);

        read_view_t view = make_read_view(wireDataBuffer, wireDataBuffer + wireDataSize);

        view_parseDestination(&view, &subctx->stateData.paymentDestination);

        VALIDATE(view_remainingSize(&view) == 0, ERR_INVALID_DATA);
    }

    security_policy_t policy =
        policyForCVoteRegistrationPaymentDestination(&subctx->stateData.paymentDestination,
                                                     commonTxData->networkId);
    TRACE("Policy: %d", (int) policy);
    ENSURE_NOT_DENIED(policy);

    {
        uint8_t addressBuffer[MAX_ADDRESS_SIZE] = {0};
        size_t addressSize = _destinationToAddress(&subctx->stateData.paymentDestination,
                                                   addressBuffer,
                                                   SIZEOF(addressBuffer));

        auxDataHashBuilder_cVoteRegistration_addPaymentAddress(&AUX_DATA_CTX->auxDataHashBuilder,
                                                               addressBuffer,
                                                               addressSize);
    }

    {
        // select UI steps
        switch (policy) {
#define CASE(POLICY, UI_STEP)      \
    case POLICY: {                 \
        subctx->ui_step = UI_STEP; \
        break;                     \
    }
            CASE(POLICY_PROMPT_WARN_UNUSUAL, HANDLE_PAYMENT_ADDRESS_PARAMS_STEP_WARNING);
            CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_PAYMENT_ADDRESS_PARAMS_STEP_DISPLAY_ADDRESS);
            CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_PAYMENT_ADDRESS_PARAMS_STEP_RESPOND);
#undef CASE
            default:
                THROW(ERR_NOT_IMPLEMENTED);
        }

        signTxCVoteRegistration_handlePaymentAddress_ui_runStep();
    }
}

// ============================== NONCE ==============================

__noinline_due_to_stack__ static void signTxCVoteRegistration_handleNonceAPDU(
    const uint8_t* wireDataBuffer,
    size_t wireDataSize) {
    {
        // sanity checks
        CHECK_STATE(STATE_CVOTE_REGISTRATION_NONCE);
    }
    cvote_registration_context_t* subctx = accessSubContext();
    { explicit_bzero(&subctx->stateData, SIZEOF(subctx->stateData)); }
    {
        // parse data
        TRACE_BUFFER(wireDataBuffer, wireDataSize);
        VALIDATE(wireDataSize == 8, ERR_INVALID_DATA);
        subctx->stateData.nonce = u8be_read(wireDataBuffer);
        TRACE("CIP-36 voting registration nonce:");
        TRACE_UINT64(subctx->stateData.nonce);
    }

    security_policy_t policy = policyForCVoteRegistrationNonce();
    TRACE("Policy: %d", (int) policy);
    ENSURE_NOT_DENIED(policy);

    {
        auxDataHashBuilder_cVoteRegistration_addNonce(&AUX_DATA_CTX->auxDataHashBuilder,
                                                      subctx->stateData.nonce);
    }

    {
        // select UI steps
        switch (policy) {
#define CASE(POLICY, UI_STEP)      \
    case POLICY: {                 \
        subctx->ui_step = UI_STEP; \
        break;                     \
    }
            CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_NONCE_STEP_DISPLAY);
            CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_NONCE_STEP_RESPOND);
#undef CASE
            default:
                THROW(ERR_NOT_IMPLEMENTED);
        }
    }

    signTxCVoteRegistration_handleNonce_ui_runStep();
}

// ============================== VOTING PURPOSE ==============================

#define DEFAULT_VOTING_PURPOSE (0)

__noinline_due_to_stack__ static void signTxCVoteRegistration_handleVotingPurposeAPDU(
    const uint8_t* wireDataBuffer,
    size_t wireDataSize) {
    { CHECK_STATE(STATE_CVOTE_REGISTRATION_VOTING_PURPOSE); }
    cvote_registration_context_t* subctx = accessSubContext();
    { explicit_bzero(&subctx->stateData, SIZEOF(subctx->stateData)); }
    {
        TRACE_BUFFER(wireDataBuffer, wireDataSize);

        {
            read_view_t view = make_read_view(wireDataBuffer, wireDataBuffer + wireDataSize);

            const uint8_t isIncluded = parse_u1be(&view);
            bool isVotingPurposeIncluded = signTx_parseIncluded(isIncluded);
            TRACE("isVotingPurposeIncluded = %u", isVotingPurposeIncluded);
            if (isVotingPurposeIncluded) {
                // only allowed in CIP36, not in CIP15
                VALIDATE(subctx->format == CIP36, ERR_INVALID_DATA);
            }

            subctx->stateData.votingPurpose =
                (isVotingPurposeIncluded) ? parse_u8be(&view) : DEFAULT_VOTING_PURPOSE;
            TRACE("votingPurpose = %u", subctx->stateData.votingPurpose);

            VALIDATE(view_remainingSize(&view) == 0, ERR_INVALID_DATA);
        }
    }

    if (subctx->format != CIP36) {
        // nothing to do, the APDU was only received to simplify the state machine
        respondSuccessEmptyMsg();
        voting_registration_advanceState();
        return;
    }

    security_policy_t policy = policyForCVoteRegistrationVotingPurpose();
    TRACE("Policy: %d", (int) policy);
    ENSURE_NOT_DENIED(policy);

    {
        auxDataHashBuilder_cVoteRegistration_addVotingPurpose(&AUX_DATA_CTX->auxDataHashBuilder,
                                                              subctx->stateData.votingPurpose);
    }
    {
        // select UI steps
        switch (policy) {
#define CASE(POLICY, UI_STEP)      \
    case POLICY: {                 \
        subctx->ui_step = UI_STEP; \
        break;                     \
    }
            CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_VOTING_PURPOSE_STEP_DISPLAY);
            CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_VOTING_PURPOSE_STEP_RESPOND);
#undef CASE
            default:
                THROW(ERR_NOT_IMPLEMENTED);
        }
    }

    signTxCVoteRegistration_handleVotingPurpose_ui_runStep();
}

// ============================== CONFIRM ==============================

__noinline_due_to_stack__ static void signTxCVoteRegistration_handleConfirmAPDU(
    const uint8_t* wireDataBuffer MARK_UNUSED,
    size_t wireDataSize) {
    {
        // sanity checks
        CHECK_STATE(STATE_CVOTE_REGISTRATION_CONFIRM);
    }
    cvote_registration_context_t* subctx = accessSubContext();
    { explicit_bzero(&subctx->stateData, SIZEOF(subctx->stateData)); }

    {
        // no data to receive
        VALIDATE(wireDataSize == 0, ERR_INVALID_DATA);
    }

    security_policy_t policy = policyForCVoteRegistrationConfirm();
    TRACE("Policy: %d", (int) policy);
    ENSURE_NOT_DENIED(policy);

    {
        aux_data_hash_builder_t* auxDataHashBuilder = &AUX_DATA_CTX->auxDataHashBuilder;
        {
            uint8_t payloadHashBuffer[CVOTE_REGISTRATION_PAYLOAD_HASH_LENGTH] = {0};
            auxDataHashBuilder_cVoteRegistration_finalizePayload(auxDataHashBuilder,
                                                                 payloadHashBuffer,
                                                                 AUX_DATA_HASH_LENGTH);
            getCVoteRegistrationSignature(&subctx->stakingKeyPath,
                                          payloadHashBuffer,
                                          CVOTE_REGISTRATION_PAYLOAD_HASH_LENGTH,
                                          subctx->stateData.registrationSignature,
                                          ED25519_SIGNATURE_LENGTH);
        }
        auxDataHashBuilder_cVoteRegistration_addSignature(auxDataHashBuilder,
                                                          subctx->stateData.registrationSignature,
                                                          ED25519_SIGNATURE_LENGTH);
        auxDataHashBuilder_cVoteRegistration_addAuxiliaryScripts(auxDataHashBuilder);

        auxDataHashBuilder_finalize(auxDataHashBuilder, subctx->auxDataHash, AUX_DATA_HASH_LENGTH);
    }

    {
        // select UI steps
        switch (policy) {
#define CASE(POLICY, UI_STEP)      \
    case POLICY: {                 \
        subctx->ui_step = UI_STEP; \
        break;                     \
    }
            CASE(POLICY_PROMPT_BEFORE_RESPONSE, HANDLE_CONFIRM_STEP_FINAL_CONFIRM);
            CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_CONFIRM_STEP_RESPOND);
#undef CASE
            default:
                THROW(ERR_NOT_IMPLEMENTED);
        }
    }

    signTxCVoteRegistration_handleConfirm_ui_runStep();
}

// ============================== main APDU handler ==============================

enum {
    APDU_INSTRUCTION_INIT = 0x36,
    APDU_INSTRUCTION_VOTE_KEY = 0x30,
    APDU_INSTRUCTION_DELEGATION = 0x37,
    APDU_INSTRUCTION_STAKING_KEY = 0x31,
    APDU_INSTRUCTION_PAYMENT_ADDRESS = 0x32,
    APDU_INSTRUCTION_NONCE = 0x33,
    APDU_INSTRUCTION_VOTING_PURPOSE = 0x35,
    APDU_INSTRUCTION_CONFIRM = 0x34
};

bool signTxCVoteRegistration_isValidInstruction(uint8_t p2) {
    switch (p2) {
        case APDU_INSTRUCTION_INIT:
        case APDU_INSTRUCTION_VOTE_KEY:
        case APDU_INSTRUCTION_DELEGATION:
        case APDU_INSTRUCTION_STAKING_KEY:
        case APDU_INSTRUCTION_PAYMENT_ADDRESS:
        case APDU_INSTRUCTION_NONCE:
        case APDU_INSTRUCTION_VOTING_PURPOSE:
        case APDU_INSTRUCTION_CONFIRM:
            return true;

        default:
            return false;
    }
}

void signTxCVoteRegistration_handleAPDU(uint8_t p2,
                                        const uint8_t* wireDataBuffer,
                                        size_t wireDataSize) {
    ASSERT(wireDataBuffer != NULL);
    ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);

    switch (p2) {
        case APDU_INSTRUCTION_INIT:
            signTxCVoteRegistration_handleInitAPDU(wireDataBuffer, wireDataSize);
            break;

        case APDU_INSTRUCTION_VOTE_KEY:
            signTxCVoteRegistration_handleVoteKeyAPDU(wireDataBuffer, wireDataSize);
            break;

        case APDU_INSTRUCTION_DELEGATION:
            signTxCVoteRegistration_handleDelegationAPDU(wireDataBuffer, wireDataSize);
            break;

        case APDU_INSTRUCTION_STAKING_KEY:
            signTxCVoteRegistration_handleStakingKeyAPDU(wireDataBuffer, wireDataSize);
            break;

        case APDU_INSTRUCTION_PAYMENT_ADDRESS:
            signTxCVoteRegistration_handlePaymentAddressAPDU(wireDataBuffer, wireDataSize);
            break;

        case APDU_INSTRUCTION_NONCE:
            signTxCVoteRegistration_handleNonceAPDU(wireDataBuffer, wireDataSize);
            break;

        case APDU_INSTRUCTION_VOTING_PURPOSE:
            signTxCVoteRegistration_handleVotingPurposeAPDU(wireDataBuffer, wireDataSize);
            break;

        case APDU_INSTRUCTION_CONFIRM:
            signTxCVoteRegistration_handleConfirmAPDU(wireDataBuffer, wireDataSize);
            break;

        default:
            // this is not supposed to be called with invalid p2
            ASSERT(false);
    }
}
