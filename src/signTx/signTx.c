#include "app_mode.h"
#include "signTx.h"
#include "state.h"
#include "bech32.h"
#include "cardano.h"
#include "addressUtilsByron.h"
#include "addressUtilsShelley.h"
#include "uiHelpers.h"
#include "signTxUtils.h"
#include "txHashBuilder.h"
#include "textUtils.h"
#include "hexUtils.h"
#include "utils.h"
#include "messageSigning.h"
#include "bufView.h"
#include "securityPolicy.h"
#include "signTx_ui.h"
#include "swap.h"
#include "io_swap.h"
#include "handle_sign_transaction.h"

static ins_sign_tx_context_t* ctx = &(instructionState.signTxContext);

static inline void initTxBodyCtx() {
    explicit_bzero(&ctx->txPartCtx, SIZEOF(ctx->txPartCtx));

    {
        // initialization
        BODY_CTX->currentInput = 0;
        BODY_CTX->currentOutput = 0;
        BODY_CTX->currentCertificate = 0;
        BODY_CTX->currentWithdrawal = 0;
        BODY_CTX->currentCollateral = 0;
        BODY_CTX->currentRequiredSigner = 0;
        BODY_CTX->currentReferenceInput = 0;
        BODY_CTX->currentVotingProcedure = 0;
        BODY_CTX->feeReceived = false;
        BODY_CTX->ttlReceived = false;
        BODY_CTX->validityIntervalStartReceived = false;
        BODY_CTX->mintReceived = false;
        BODY_CTX->scriptDataHashReceived = false;
        BODY_CTX->collateralOutputReceived = false;
        BODY_CTX->totalCollateralReceived = false;
        BODY_CTX->treasuryReceived = false;
        BODY_CTX->donationReceived = false;
    }
}

static inline void initTxAuxDataCtx() {
    explicit_bzero(&ctx->txPartCtx, SIZEOF(ctx->txPartCtx));
    {
        AUX_DATA_CTX->auxDataReceived = false;
        AUX_DATA_CTX->auxDataType = false;
    }
}

static inline void initTxWitnessCtx() {
    explicit_bzero(&ctx->txPartCtx, SIZEOF(ctx->txPartCtx));
    { WITNESS_CTX->currentWitness = 0; }
}

// advances the stage of the main state machine
void tx_advanceStage() {
    TRACE("Advancing sign tx stage from: %d", ctx->stage);

    switch (ctx->stage) {
        case SIGN_STAGE_INIT:
            ctx->stage = SIGN_STAGE_AUX_DATA;
            initTxAuxDataCtx();

            if (ctx->includeAuxData) {
                // wait for aux data APDU(s)
                AUX_DATA_CTX->auxDataReceived = false;
                break;
            }

            __attribute__((fallthrough));
        case SIGN_STAGE_AUX_DATA:
            if (ctx->includeAuxData) {
                ASSERT(AUX_DATA_CTX->auxDataReceived);
            }

            ctx->stage = SIGN_STAGE_BODY_INPUTS;
            initTxBodyCtx();

            {
                // Note: make sure that everything in ctx is initialized properly
                txHashBuilder_init(&BODY_CTX->txHashBuilder,
                                   ctx->commonTxData.tagCborSets,
                                   ctx->numInputs,
                                   ctx->numOutputs,
                                   ctx->includeTtl,
                                   ctx->numCertificates,
                                   ctx->numWithdrawals,
                                   ctx->includeAuxData,
                                   ctx->includeValidityIntervalStart,
                                   ctx->includeMint,
                                   ctx->includeScriptDataHash,
                                   ctx->numCollateralInputs,
                                   ctx->numRequiredSigners,
                                   ctx->includeNetworkId,
                                   ctx->includeCollateralOutput,
                                   ctx->includeTotalCollateral,
                                   ctx->numReferenceInputs,
                                   ctx->numVotingProcedures,
                                   ctx->includeTreasury,
                                   ctx->includeDonation);
                txHashBuilder_enterInputs(&BODY_CTX->txHashBuilder);
            }
            break;

        case SIGN_STAGE_BODY_INPUTS:
            // we should have received all inputs
            ASSERT(BODY_CTX->currentInput == ctx->numInputs);
            txHashBuilder_enterOutputs(&BODY_CTX->txHashBuilder);
            initializeOutputSubmachine();

            ctx->stage = SIGN_STAGE_BODY_OUTPUTS;

            if (ctx->numOutputs > 0) {
                // wait for output APDUs
                break;
            }

            __attribute__((fallthrough));
        case SIGN_STAGE_BODY_OUTPUTS:
            // we should have received all outputs
            ASSERT(BODY_CTX->currentOutput == ctx->numOutputs);

            ctx->stage = SIGN_STAGE_BODY_FEE;
            break;

        case SIGN_STAGE_BODY_FEE:
            ASSERT(BODY_CTX->feeReceived);

            ctx->stage = SIGN_STAGE_BODY_TTL;

            if (ctx->includeTtl) {
                // wait for TTL APDU
                break;
            }

            __attribute__((fallthrough));
        case SIGN_STAGE_BODY_TTL:
            if (ctx->includeTtl) {
                ASSERT(BODY_CTX->ttlReceived);
            }

            ctx->stage = SIGN_STAGE_BODY_CERTIFICATES;

            if (ctx->numCertificates > 0) {
                txHashBuilder_enterCertificates(&BODY_CTX->txHashBuilder);
                break;
            }

            __attribute__((fallthrough));
        case SIGN_STAGE_BODY_CERTIFICATES:
            // we should have received all certificates
            ASSERT(BODY_CTX->currentCertificate == ctx->numCertificates);

            ctx->stage = SIGN_STAGE_BODY_WITHDRAWALS;

            if (ctx->numWithdrawals > 0) {
                txHashBuilder_enterWithdrawals(&BODY_CTX->txHashBuilder);
                break;
            }

            __attribute__((fallthrough));
        case SIGN_STAGE_BODY_WITHDRAWALS:
            // we should have received all withdrawals
            ASSERT(BODY_CTX->currentWithdrawal == ctx->numWithdrawals);

            if (ctx->includeAuxData) {
                // add auxiliary data to tx
                TRACE("Adding auxiliary data hash to tx hash");
                txHashBuilder_addAuxData(&BODY_CTX->txHashBuilder,
                                         ctx->auxDataHash,
                                         SIZEOF(ctx->auxDataHash));
            }

            ctx->stage = SIGN_STAGE_BODY_VALIDITY_INTERVAL;

            if (ctx->includeValidityIntervalStart) {
                // wait for Validity interval start APDU
                break;
            }

            __attribute__((fallthrough));
        case SIGN_STAGE_BODY_VALIDITY_INTERVAL:
            if (ctx->includeValidityIntervalStart) {
                ASSERT(BODY_CTX->validityIntervalStartReceived);
            }

            ctx->stage = SIGN_STAGE_BODY_MINT;

            if (ctx->includeMint) {
                txHashBuilder_enterMint(&BODY_CTX->txHashBuilder);
                signTxMint_init();
                // wait for mint APDU
                break;
            }

            __attribute__((fallthrough));
        case SIGN_STAGE_BODY_MINT:
            if (ctx->includeMint) {
                ASSERT(BODY_CTX->mintReceived);
            }

            ctx->stage = SIGN_STAGE_BODY_SCRIPT_DATA_HASH;

            if (ctx->includeScriptDataHash) {
                break;
            }

            __attribute__((fallthrough));
        case SIGN_STAGE_BODY_SCRIPT_DATA_HASH:
            if (ctx->includeScriptDataHash) {
                ASSERT(BODY_CTX->scriptDataHashReceived);
            }

            ctx->stage = SIGN_STAGE_BODY_COLLATERAL_INPUTS;

            if (ctx->numCollateralInputs > 0) {
                txHashBuilder_enterCollateralInputs(&BODY_CTX->txHashBuilder);
                break;
            }

            __attribute__((fallthrough));
        case SIGN_STAGE_BODY_COLLATERAL_INPUTS:
            ASSERT(BODY_CTX->currentCollateral == ctx->numCollateralInputs);

            ctx->stage = SIGN_STAGE_BODY_REQUIRED_SIGNERS;

            if (ctx->numRequiredSigners > 0) {
                txHashBuilder_enterRequiredSigners(&BODY_CTX->txHashBuilder);
                break;
            }

            __attribute__((fallthrough));
        case SIGN_STAGE_BODY_REQUIRED_SIGNERS:
            ASSERT(BODY_CTX->currentRequiredSigner == ctx->numRequiredSigners);
            if (ctx->includeNetworkId) {
                // we are not waiting for any APDU here, network id is already known from the init
                // APDU
                txHashBuilder_addNetworkId(&BODY_CTX->txHashBuilder, ctx->commonTxData.networkId);
            }

            ctx->stage = SIGN_STAGE_BODY_COLLATERAL_OUTPUT;

            if (ctx->includeCollateralOutput) {
                break;
            }

            __attribute__((fallthrough));
        case SIGN_STAGE_BODY_COLLATERAL_OUTPUT:
            if (ctx->includeCollateralOutput) {
                ASSERT(BODY_CTX->collateralOutputReceived);
            }

            ctx->stage = SIGN_STAGE_BODY_TOTAL_COLLATERAL;

            if (ctx->includeTotalCollateral) {
                break;
            }

            __attribute__((fallthrough));
        case SIGN_STAGE_BODY_TOTAL_COLLATERAL:
            if (ctx->includeTotalCollateral) {
                ASSERT(BODY_CTX->totalCollateralReceived);
            }

            ctx->stage = SIGN_STAGE_BODY_REFERENCE_INPUTS;

            if (ctx->numReferenceInputs > 0) {
                txHashBuilder_enterReferenceInputs(&BODY_CTX->txHashBuilder);
                break;
            }

            __attribute__((fallthrough));
        case SIGN_STAGE_BODY_REFERENCE_INPUTS:
            ASSERT(BODY_CTX->currentReferenceInput == ctx->numReferenceInputs);

            ctx->stage = SIGN_STAGE_BODY_VOTING_PROCEDURES;

            if (ctx->numVotingProcedures > 0) {
                txHashBuilder_enterVotingProcedures(&BODY_CTX->txHashBuilder);
                break;
            }

            __attribute__((fallthrough));
        case SIGN_STAGE_BODY_VOTING_PROCEDURES:
            ASSERT(BODY_CTX->currentVotingProcedure == ctx->numVotingProcedures);

            ctx->stage = SIGN_STAGE_BODY_TREASURY;

            if (ctx->includeTreasury) {
                break;
            }

            __attribute__((fallthrough));
        case SIGN_STAGE_BODY_TREASURY:
            if (ctx->includeTreasury) {
                ASSERT(BODY_CTX->treasuryReceived);
            }

            ctx->stage = SIGN_STAGE_BODY_DONATION;

            if (ctx->includeDonation) {
                break;
            }

            __attribute__((fallthrough));
        case SIGN_STAGE_BODY_DONATION:
            if (ctx->includeDonation) {
                ASSERT(BODY_CTX->donationReceived);
            }

            ctx->stage = SIGN_STAGE_CONFIRM;
            break;

        case SIGN_STAGE_CONFIRM:
            ctx->stage = SIGN_STAGE_WITNESSES;
            initTxWitnessCtx();

            if (ctx->numWitnesses > 0) {
                break;
            }

            __attribute__((fallthrough));
        case SIGN_STAGE_WITNESSES:
            ctx->stage = SIGN_STAGE_NONE;
            ui_idle();  // we are done with this tx
            endTxStatus();
            break;

        case SIGN_STAGE_NONE:
            // tx_advanceStage() not supposed to be called after tx processing is finished
            ASSERT(false);
            break;

        default:
            ASSERT(false);
    }

    TRACE("Advancing sign tx stage to: %d", ctx->stage);
}

// called from main state machine when a pool registration certificate
// sub-machine is finished, or when other type of certificate is processed
void tx_advanceCertificatesStateIfAppropriate() {
    TRACE("%u", ctx->stage);

    switch (ctx->stage) {
        case SIGN_STAGE_BODY_CERTIFICATES: {
            ASSERT(BODY_CTX->currentCertificate < ctx->numCertificates);

            // Advance stage to the next certificate
            ASSERT(BODY_CTX->currentCertificate < ctx->numCertificates);
            BODY_CTX->currentCertificate++;

            if (BODY_CTX->currentCertificate == ctx->numCertificates) {
                tx_advanceStage();
            }
        } break;

        default:
#ifdef APP_FEATURE_POOL_REGISTRATION
            ASSERT(ctx->stage == SIGN_STAGE_BODY_CERTIFICATES_POOL_SUBMACHINE);
#else
            ASSERT(false);
#endif  // APP_FEATURE_POOL_REGISTRATION
    }
}

// State sub-machines, e.g. the one in signTxPoolRegistration, might finish
// with a UI handler. The callbacks (resulting from user interaction) are run
// only after all APDU handlers have returned, thus the sub-machine cannot
// notify the main state machine of state changes resulting from user interaction
// (unless it is allowed to directly mess with the state of the main machine).
//
// Consequently, we only find out that a state sub-machine is finished
// when the following APDU of the main state machine arrives, and we need to
// update the state before dealing with the APDU.
static inline void checkForFinishedSubmachines() {
    TRACE("Checking for finished submachines; stage = %d", ctx->stage);

    switch (ctx->stage) {
        case SIGN_STAGE_BODY_OUTPUTS_SUBMACHINE:
            if (isCurrentOutputFinished()) {
                TRACE();
                ASSERT(BODY_CTX->currentOutput < ctx->numOutputs);
                ctx->stage = SIGN_STAGE_BODY_OUTPUTS;

                BODY_CTX->currentOutput++;
                if (BODY_CTX->currentOutput == ctx->numOutputs) {
                    tx_advanceStage();
                }
            }
            break;

#ifdef APP_FEATURE_POOL_REGISTRATION

        case SIGN_STAGE_BODY_CERTIFICATES_POOL_SUBMACHINE:
            if (signTxPoolRegistration_isFinished()) {
                TRACE();
                ASSERT(BODY_CTX->currentCertificate < ctx->numCertificates);
                ctx->stage = SIGN_STAGE_BODY_CERTIFICATES;

                tx_advanceCertificatesStateIfAppropriate();
            }
            break;

#endif  // APP_FEATURE_POOL_REGISTRATION

        case SIGN_STAGE_AUX_DATA_CVOTE_REGISTRATION_SUBMACHINE:
            if (signTxCVoteRegistration_isFinished()) {
                TRACE();
                ctx->stage = SIGN_STAGE_AUX_DATA;
                AUX_DATA_CTX->auxDataReceived = true;

                STATIC_ASSERT(SIZEOF(ctx->auxDataHash) == AUX_DATA_HASH_LENGTH,
                              "Wrong auxiliary data hash length");
                STATIC_ASSERT(
                    SIZEOF(AUX_DATA_CTX->stageContext.cvote_registration_subctx.auxDataHash) ==
                        AUX_DATA_HASH_LENGTH,
                    "Wrong auxiliary data hash length");
                memmove(ctx->auxDataHash,
                        AUX_DATA_CTX->stageContext.cvote_registration_subctx.auxDataHash,
                        AUX_DATA_HASH_LENGTH);

                tx_advanceStage();
            }
            break;

        case SIGN_STAGE_BODY_MINT_SUBMACHINE:
            if (signTxMint_isFinished()) {
                TRACE();
                ctx->stage = SIGN_STAGE_BODY_MINT;
                BODY_CTX->mintReceived = true;
                tx_advanceStage();
            }
            break;

        case SIGN_STAGE_BODY_COLLATERAL_OUTPUT_SUBMACHINE:
            if (isCurrentOutputFinished()) {
                TRACE();
                ctx->stage = SIGN_STAGE_BODY_COLLATERAL_OUTPUT;
                BODY_CTX->collateralOutputReceived = true;
                tx_advanceStage();
            }
            break;

        default:
            break;  // nothing to do otherwise
    }
}

// this is supposed to be called at the beginning of each APDU handler
static inline void CHECK_STAGE(sign_tx_stage_t expected) {
    TRACE("Checking stage... current one is %d, expected %d", ctx->stage, expected);
    VALIDATE(ctx->stage == expected, ERR_INVALID_STATE);
}

// ============================== INIT ==============================

static void _parseTxOptions(uint64_t options) {
    ctx->commonTxData.tagCborSets = options & TX_OPTIONS_TAG_CBOR_SETS;
    options &= ~TX_OPTIONS_TAG_CBOR_SETS;
    TRACE("tagCborSets = %d", ctx->commonTxData.tagCborSets);

    // we only accept known flags
    VALIDATE(options == 0, ERR_INVALID_DATA);
}

__noinline_due_to_stack__ static void signTx_handleInitAPDU(uint8_t p2,
                                                            const uint8_t* wireDataBuffer,
                                                            size_t wireDataSize) {
    TRACE_STACK_USAGE();
    {
        // sanity checks
        CHECK_STAGE(SIGN_STAGE_INIT);

        VALIDATE(p2 == P2_UNUSED, ERR_INVALID_REQUEST_PARAMETERS);
    }

#ifdef HAVE_SWAP
    if (G_called_from_swap) {
        if (G_swap_response_ready) {
            // Safety against trying to make the app sign multiple TX
            // This code should never be triggered as the app is supposed to exit after
            // sending the signed transaction
            PRINTF("Safety against double signing triggered\n");
            swap_finalize_exchange_sign_transaction(false);
            os_sched_exit(-1);
        }
        // We will quit the app after this transaction, whether it succeeds or fails
        PRINTF("Swap response is ready, the app will quit after the next send\n");
        G_swap_response_ready = true;
    }
#endif
    {
        // parse data

        TRACE_BUFFER(wireDataBuffer, wireDataSize);

        struct {
            uint8_t txOptions[8];

            uint8_t networkId;
            uint8_t protocolMagic[4];

            uint8_t includeTtl;
            uint8_t includeAuxData;
            uint8_t includeValidityIntervalStart;
            uint8_t includeMint;
            uint8_t includeScriptDataHash;
            uint8_t includeNetworkId;
            uint8_t includeCollateralOutput;
            uint8_t includeTotalCollateral;
            uint8_t includeTreasury;
            uint8_t includeDonation;
            uint8_t txSigningMode;

            uint8_t numInputs[4];
            uint8_t numOutputs[4];
            uint8_t numCertificates[4];
            uint8_t numWithdrawals[4];
            uint8_t numCollateralInputs[4];
            uint8_t numRequiredSigners[4];
            uint8_t numReferenceInputs[4];
            uint8_t numVotingProcedures[4];

            uint8_t numWitnesses[4];
        }* wireHeader = (void*) wireDataBuffer;

        VALIDATE(SIZEOF(*wireHeader) == wireDataSize, ERR_INVALID_DATA);

        uint64_t txOptions = u8be_read(wireHeader->txOptions);
        _parseTxOptions(txOptions);

        ASSERT_TYPE(ctx->commonTxData.networkId, uint8_t);
        ctx->commonTxData.networkId = wireHeader->networkId;
        TRACE("network id %d", ctx->commonTxData.networkId);
        VALIDATE(isValidNetworkId(ctx->commonTxData.networkId), ERR_INVALID_DATA);

        ASSERT_TYPE(ctx->commonTxData.protocolMagic, uint32_t);
        ctx->commonTxData.protocolMagic = u4be_read(wireHeader->protocolMagic);
        TRACE("protocol magic %d", ctx->commonTxData.protocolMagic);

        ctx->includeTtl = signTx_parseIncluded(wireHeader->includeTtl);
        TRACE("Include ttl %d", ctx->includeTtl);

        ctx->includeAuxData = signTx_parseIncluded(wireHeader->includeAuxData);
        TRACE("Include auxiliary data %d", ctx->includeAuxData);

        ctx->includeValidityIntervalStart =
            signTx_parseIncluded(wireHeader->includeValidityIntervalStart);
        TRACE("Include validity interval start %d", ctx->includeValidityIntervalStart);

        ctx->includeMint = signTx_parseIncluded(wireHeader->includeMint);
        TRACE("Include mint %d", ctx->includeMint);

        ctx->includeScriptDataHash = signTx_parseIncluded(wireHeader->includeScriptDataHash);
        TRACE("Include script data hash %d", ctx->includeScriptDataHash);

        ctx->includeNetworkId = signTx_parseIncluded(wireHeader->includeNetworkId);
        TRACE("Include network id %d", ctx->includeNetworkId);

        ctx->includeCollateralOutput = signTx_parseIncluded(wireHeader->includeCollateralOutput);
        TRACE("Include collateral output %d", ctx->includeCollateralOutput);

        ctx->includeTotalCollateral = signTx_parseIncluded(wireHeader->includeTotalCollateral);
        TRACE("Include total collateral %d", ctx->includeTotalCollateral);

        ctx->includeTreasury = signTx_parseIncluded(wireHeader->includeTreasury);
        TRACE("Include treasury %d", ctx->includeTreasury);

        ctx->includeDonation = signTx_parseIncluded(wireHeader->includeDonation);
        TRACE("Include donation %d", ctx->includeDonation);

        ctx->commonTxData.txSigningMode = wireHeader->txSigningMode;
        TRACE("Signing mode %d", (int) ctx->commonTxData.txSigningMode);
        switch (ctx->commonTxData.txSigningMode) {
            case SIGN_TX_SIGNINGMODE_ORDINARY_TX:
            case SIGN_TX_SIGNINGMODE_MULTISIG_TX:
            case SIGN_TX_SIGNINGMODE_PLUTUS_TX:
                // these signing modes are allowed
                break;

            case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OWNER:
            case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OPERATOR:
// these are allowed unless we have the XS app which does not have code for handling them
#ifndef APP_FEATURE_POOL_REGISTRATION
                THROW(ERR_INVALID_DATA);
#endif  // APP_FEATURE_POOL_REGISTRATION
                break;

            default:
                THROW(ERR_INVALID_DATA);
        }

        ASSERT_TYPE(ctx->numInputs, uint16_t);
        ASSERT_TYPE(ctx->numOutputs, uint16_t);
        ASSERT_TYPE(ctx->numCertificates, uint16_t);
        ASSERT_TYPE(ctx->numWithdrawals, uint16_t);
        ASSERT_TYPE(ctx->numCollateralInputs, uint16_t);
        ASSERT_TYPE(ctx->numRequiredSigners, uint16_t);
        ASSERT_TYPE(ctx->numReferenceInputs, uint16_t);
        ASSERT_TYPE(ctx->numVotingProcedures, uint16_t);
        ASSERT_TYPE(ctx->numWitnesses, uint16_t);

        ctx->numInputs = (uint16_t) u4be_read(wireHeader->numInputs);
        ctx->numOutputs = (uint16_t) u4be_read(wireHeader->numOutputs);
        ctx->numCertificates = (uint16_t) u4be_read(wireHeader->numCertificates);
        ctx->numWithdrawals = (uint16_t) u4be_read(wireHeader->numWithdrawals);
        ctx->numCollateralInputs = (uint16_t) u4be_read(wireHeader->numCollateralInputs);
        ctx->numRequiredSigners = (uint16_t) u4be_read(wireHeader->numRequiredSigners);
        ctx->numReferenceInputs = (uint16_t) u4be_read(wireHeader->numReferenceInputs);
        ctx->numVotingProcedures = (uint16_t) u4be_read(wireHeader->numVotingProcedures);
        ctx->numWitnesses = (uint16_t) u4be_read(wireHeader->numWitnesses);

        TRACE(
            "inputs: %d, outputs: %d, certificates: %d, withdrawals: %d, collateral inputs: %d,"
            " required signers: %d, reference inputs: %d, voting procedures: %d, witnesses: %d",
            ctx->numInputs,
            ctx->numOutputs,
            ctx->numCertificates,
            ctx->numWithdrawals,
            ctx->numCollateralInputs,
            ctx->numRequiredSigners,
            ctx->numReferenceInputs,
            ctx->numVotingProcedures,
            ctx->numWitnesses);
        VALIDATE(ctx->numInputs <= SIGN_MAX_INPUTS, ERR_INVALID_DATA);
        VALIDATE(ctx->numOutputs <= SIGN_MAX_OUTPUTS, ERR_INVALID_DATA);
        VALIDATE(ctx->numCertificates <= SIGN_MAX_CERTIFICATES, ERR_INVALID_DATA);
        VALIDATE(ctx->numWithdrawals <= SIGN_MAX_REWARD_WITHDRAWALS, ERR_INVALID_DATA);
        VALIDATE(ctx->numCollateralInputs <= SIGN_MAX_COLLATERAL_INPUTS, ERR_INVALID_DATA);
        VALIDATE(ctx->numRequiredSigners <= SIGN_MAX_REQUIRED_SIGNERS, ERR_INVALID_DATA);
        VALIDATE(ctx->numReferenceInputs <= SIGN_MAX_REFERENCE_INPUTS, ERR_INVALID_DATA);
        VALIDATE(ctx->numVotingProcedures <= SIGN_MAX_VOTING_PROCEDURES, ERR_INVALID_DATA);

        // Current code design assumes at least one input.
        // If this is to be relaxed, stage switching logic needs to be re-visited.
        // However, an input is needed for certificate replay protection (enforced by node),
        // so double-check this protection is no longer necessary before allowing no inputs.
        VALIDATE(ctx->numInputs > 0, ERR_INVALID_DATA);
    }

    {
        // default values for variables whose value is not given in the APDU
        ctx->poolOwnerByPath = false;
        ctx->shouldDisplayTxid = false;
    }

    security_policy_t policy = POLICY_DENY;
#ifdef HAVE_SWAP
    if (G_called_from_swap) {
        policy = POLICY_ALLOW_WITHOUT_PROMPT;
    } else
#endif
    {
        policy = policyForSignTxInit(ctx->commonTxData.txSigningMode,
                                     ctx->commonTxData.networkId,
                                     ctx->commonTxData.protocolMagic,
                                     ctx->numOutputs,
                                     ctx->numCertificates,
                                     ctx->numWithdrawals,
                                     ctx->includeMint,
                                     ctx->includeScriptDataHash,
                                     ctx->numCollateralInputs,
                                     ctx->numRequiredSigners,
                                     ctx->includeNetworkId,
                                     ctx->includeCollateralOutput,
                                     ctx->includeTotalCollateral,
                                     ctx->numReferenceInputs,
                                     ctx->numVotingProcedures,
                                     ctx->includeTreasury,
                                     ctx->includeDonation);
        TRACE("Policy: %d", (int) policy);
        ENSURE_NOT_DENIED(policy);
    }
    {
        // select UI steps
        switch (policy) {
#define CASE(POLICY, UI_STEP)   \
    case POLICY: {              \
        ctx->ui_step = UI_STEP; \
        break;                  \
    }
            CASE(POLICY_PROMPT_WARN_UNUSUAL, HANDLE_INIT_STEP_PROMPT_SIGNINGMODE);
            CASE(POLICY_PROMPT_BEFORE_RESPONSE, HANDLE_INIT_STEP_PROMPT_SIGNINGMODE);
            CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_INIT_STEP_RESPOND);
#undef CASE
            default:
                THROW(ERR_NOT_IMPLEMENTED);
        }
    }

    signTx_handleInit_ui_runStep();
}

// ============================== AUXILIARY DATA ==============================

__noinline_due_to_stack__ static void signTx_handleAuxDataAPDU(uint8_t p2,
                                                               const uint8_t* wireDataBuffer,
                                                               size_t wireDataSize) {
    {
        TRACE_STACK_USAGE();
        ASSERT(ctx->includeAuxData == true);

        // delegate to state sub-machine for CIP-36 voting registration data
        if (signTxCVoteRegistration_isValidInstruction(p2)) {
            TRACE();
            CHECK_STAGE(SIGN_STAGE_AUX_DATA_CVOTE_REGISTRATION_SUBMACHINE);

            TRACE_STACK_USAGE();

            signTxCVoteRegistration_handleAPDU(p2, wireDataBuffer, wireDataSize);
            return;
        }

        VALIDATE(p2 == P2_UNUSED, ERR_INVALID_REQUEST_PARAMETERS);
        CHECK_STAGE(SIGN_STAGE_AUX_DATA);
    }
    {
        explicit_bzero(ctx->auxDataHash, SIZEOF(ctx->auxDataHash));
        TRACE_BUFFER(wireDataBuffer, wireDataSize);

        read_view_t view = make_read_view(wireDataBuffer, wireDataBuffer + wireDataSize);

        AUX_DATA_CTX->auxDataType = parse_u1be(&view);
        switch (AUX_DATA_CTX->auxDataType) {
            case AUX_DATA_TYPE_ARBITRARY_HASH: {
                // parse data
                STATIC_ASSERT(SIZEOF(ctx->auxDataHash) == AUX_DATA_HASH_LENGTH,
                              "wrong auxiliary data hash length");
                view_parseBuffer(ctx->auxDataHash, &view, AUX_DATA_HASH_LENGTH);
                AUX_DATA_CTX->auxDataReceived = true;
                break;
            }

            case AUX_DATA_TYPE_CVOTE_REGISTRATION:
                break;

            default:
                THROW(ERR_INVALID_DATA);
        }

        VALIDATE(view_remainingSize(&view) == 0, ERR_INVALID_DATA);
    }

    security_policy_t policy = POLICY_DENY;
#ifdef HAVE_SWAP
    if (G_called_from_swap) {
        policy = POLICY_ALLOW_WITHOUT_PROMPT;
    } else
#endif
    {
        policy = policyForSignTxAuxData(AUX_DATA_CTX->auxDataType);
        TRACE("Policy: %d", (int) policy);
        ENSURE_NOT_DENIED(policy);
    }

    switch (AUX_DATA_CTX->auxDataType) {
        case AUX_DATA_TYPE_ARBITRARY_HASH: {
            // select UI step
            switch (policy) {
#define CASE(POLICY, UI_STEP)   \
    case POLICY: {              \
        ctx->ui_step = UI_STEP; \
        break;                  \
    }
                CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_AUX_DATA_ARBITRARY_HASH_STEP_DISPLAY);
                CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_AUX_DATA_ARBITRARY_HASH_STEP_RESPOND);
#undef CASE
                default:
                    THROW(ERR_NOT_IMPLEMENTED);
            }
            signTx_handleAuxDataArbitraryHash_ui_runStep();
            break;
        }
        case AUX_DATA_TYPE_CVOTE_REGISTRATION:
            // select UI step
            switch (policy) {
#define CASE(POLICY, UI_STEP)   \
    case POLICY: {              \
        ctx->ui_step = UI_STEP; \
        break;                  \
    }
                CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_AUX_DATA_CVOTE_REGISTRATION_STEP_DISPLAY);
                CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_AUX_DATA_CVOTE_REGISTRATION_STEP_RESPOND);
#undef CASE
                default:
                    THROW(ERR_NOT_IMPLEMENTED);
            }

            signTx_handleAuxDataCVoteRegistration_ui_runStep();
            break;
        default:
            ASSERT(false);
    }
}

// ============================== INPUTS ==============================

// Advance stage to the next input
static void ui_advanceState_input() {
    ASSERT(BODY_CTX->currentInput < ctx->numInputs);
    BODY_CTX->currentInput++;

    if (BODY_CTX->currentInput == ctx->numInputs) {
        tx_advanceStage();
    }
}

static void parseInput(const uint8_t* wireDataBuffer, size_t wireDataSize) {
    sign_tx_transaction_input_t* input = &BODY_CTX->stageData.input;

    struct {
        uint8_t txHash[TX_HASH_LENGTH];
        uint8_t index[4];
    }* wireUtxo = (void*) wireDataBuffer;

    VALIDATE(wireDataSize == SIZEOF(*wireUtxo), ERR_INVALID_DATA);

    tx_input_t* inputData = &input->input_data;
    memmove(inputData->txHashBuffer, wireUtxo->txHash, SIZEOF(inputData->txHashBuffer));
    inputData->index = u4be_read(wireUtxo->index);
}

static void constructInputLabel(const char* prefix, uint16_t index) {
    char* label = BODY_CTX->stageData.input.label;
    const size_t labelSize = SIZEOF(BODY_CTX->stageData.input.label);
    explicit_bzero(label, labelSize);
    // indexed from 0 as agreed with IOG on Slack
    snprintf(label, labelSize, "%s #%u", prefix, index);
    // make sure all the information is displayed to the user
    ASSERT(strlen(label) + 1 < labelSize);
}

static void ui_selectInputStep(security_policy_t policy) {
    // select UI steps
    switch (policy) {
#define CASE(POLICY, UI_STEP)   \
    case POLICY: {              \
        ctx->ui_step = UI_STEP; \
        break;                  \
    }
        CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_INPUT_STEP_DISPLAY);
        CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_INPUT_STEP_RESPOND);
#undef CASE
        default:
            THROW(ERR_NOT_IMPLEMENTED);
    }
}

__noinline_due_to_stack__ static void signTx_handleInputAPDU(uint8_t p2,
                                                             const uint8_t* wireDataBuffer,
                                                             size_t wireDataSize) {
    TRACE_STACK_USAGE();
    {
        // sanity checks
        CHECK_STAGE(SIGN_STAGE_BODY_INPUTS);
        ASSERT(BODY_CTX->currentInput < ctx->numInputs);

        VALIDATE(p2 == P2_UNUSED, ERR_INVALID_REQUEST_PARAMETERS);
    }

    parseInput(wireDataBuffer, wireDataSize);

    security_policy_t policy = POLICY_DENY;
#ifdef HAVE_SWAP
    if (G_called_from_swap) {
        policy = POLICY_ALLOW_WITHOUT_PROMPT;
    } else
#endif
    {
        policy = policyForSignTxInput(ctx->commonTxData.txSigningMode);
        TRACE("Policy: %d", (int) policy);
        ENSURE_NOT_DENIED(policy);
    }

    {
        // add to tx
        TRACE("Adding input to tx hash");
        txHashBuilder_addInput(&BODY_CTX->txHashBuilder, &BODY_CTX->stageData.input.input_data);
    }
    {
        // not needed if input is not shown, but does not cost much time, so not worth branching
        constructInputLabel("Input", BODY_CTX->currentInput);

        ctx->ui_advanceState = ui_advanceState_input;
        ui_selectInputStep(policy);
        signTx_handleInput_ui_runStep();
    }
}

// ============================== OUTPUTS ==============================

static void signTx_handleOutputAPDU(uint8_t p2,
                                    const uint8_t* wireDataBuffer,
                                    size_t wireDataSize) {
    {
        TRACE("p2 = %d", p2);
        TRACE_BUFFER(wireDataBuffer, wireDataSize);
    }

    if (ctx->stage == SIGN_STAGE_BODY_OUTPUTS) {
        // new output
        VALIDATE(BODY_CTX->currentOutput < ctx->numOutputs, ERR_INVALID_STATE);
        initializeOutputSubmachine();
        ctx->stage = SIGN_STAGE_BODY_OUTPUTS_SUBMACHINE;
    }

    CHECK_STAGE(SIGN_STAGE_BODY_OUTPUTS_SUBMACHINE);
    ASSERT(BODY_CTX->currentOutput < ctx->numOutputs);

    // all output handling is delegated to a state sub-machine
    VALIDATE(signTxOutput_isValidInstruction(p2), ERR_INVALID_REQUEST_PARAMETERS);
    signTxOutput_handleAPDU(p2, wireDataBuffer, wireDataSize);
}

// ============================== FEE ==============================

__noinline_due_to_stack__ static void signTx_handleFeeAPDU(uint8_t p2,
                                                           const uint8_t* wireDataBuffer,
                                                           size_t wireDataSize) {
    {
        // sanity checks
        CHECK_STAGE(SIGN_STAGE_BODY_FEE);

        VALIDATE(p2 == P2_UNUSED, ERR_INVALID_REQUEST_PARAMETERS);
    }
    {
        // parse data
        TRACE_BUFFER(wireDataBuffer, wireDataSize);

        VALIDATE(wireDataSize == 8, ERR_INVALID_DATA);
        BODY_CTX->stageData.fee = u8be_read(wireDataBuffer);
        BODY_CTX->feeReceived = true;
    }

    security_policy_t policy = POLICY_DENY;
#ifdef HAVE_SWAP
    if (G_called_from_swap) {
        if (!swap_check_fee_validity(BODY_CTX->stageData.fee)) {
            send_swap_error(ERROR_WRONG_FEES, APP_CODE_DEFAULT, NULL);
            // unreachable
            os_sched_exit(0);
        }
        policy = POLICY_ALLOW_WITHOUT_PROMPT;
    } else
#endif
    {
        policy = policyForSignTxFee(ctx->commonTxData.txSigningMode, BODY_CTX->stageData.fee);
        TRACE("Policy: %d", (int) policy);
        ENSURE_NOT_DENIED(policy);
    }
    {
        // add to tx
        TRACE("Adding fee to tx hash");
        txHashBuilder_addFee(&BODY_CTX->txHashBuilder, BODY_CTX->stageData.fee);
    }

    {
        // select UI steps
        switch (policy) {
#define CASE(POLICY, UI_STEP)   \
    case POLICY: {              \
        ctx->ui_step = UI_STEP; \
        break;                  \
    }
            CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_FEE_STEP_DISPLAY);
            CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_FEE_STEP_RESPOND);
#undef CASE
            default:
                THROW(ERR_NOT_IMPLEMENTED);
        }
    }

    signTx_handleFee_ui_runStep();
}

// ============================== TTL ==============================

__noinline_due_to_stack__ static void signTx_handleTtlAPDU(uint8_t p2,
                                                           const uint8_t* wireDataBuffer,
                                                           size_t wireDataSize) {
    {
        // sanity checks
        CHECK_STAGE(SIGN_STAGE_BODY_TTL);
        ASSERT(ctx->includeTtl == true);

        VALIDATE(p2 == P2_UNUSED, ERR_INVALID_REQUEST_PARAMETERS);
    }
    {
        // parse data
        TRACE_BUFFER(wireDataBuffer, wireDataSize);

        VALIDATE(wireDataSize == 8, ERR_INVALID_DATA);
        BODY_CTX->stageData.ttl = u8be_read(wireDataBuffer);
        BODY_CTX->ttlReceived = true;
    }

    security_policy_t policy = POLICY_DENY;
#ifdef HAVE_SWAP
    if (G_called_from_swap) {
        policy = POLICY_ALLOW_WITHOUT_PROMPT;
    } else
#endif
    {
        policy = policyForSignTxTtl(BODY_CTX->stageData.ttl);
        TRACE("Policy: %d", (int) policy);
        ENSURE_NOT_DENIED(policy);
    }

    {
        // add to tx
        TRACE("Adding ttl to tx hash");
        txHashBuilder_addTtl(&BODY_CTX->txHashBuilder, BODY_CTX->stageData.ttl);
    }

    {
        // select UI steps
        switch (policy) {
#define CASE(POLICY, UI_STEP)   \
    case POLICY: {              \
        ctx->ui_step = UI_STEP; \
        break;                  \
    }
            CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_TTL_STEP_DISPLAY);
            CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_TTL_STEP_RESPOND);
#undef CASE
            default:
                THROW(ERR_NOT_IMPLEMENTED);
        }
    }

    signTx_handleTtl_ui_runStep();
}

// ============================== CERTIFICATES ==============================

static void _parsePathSpec(read_view_t* view, bip44_path_t* pathSpec) {
    view_skipBytes(view, bip44_parseFromWire(pathSpec, VIEW_REMAINING_TO_TUPLE_BUF_SIZE(view)));
    TRACE();
    BIP44_PRINTF(pathSpec);
    PRINTF("\n");
}

static void _parseCredential(read_view_t* view, ext_credential_t* credential) {
    credential->type = parse_u1be(view);
    switch (credential->type) {
        case EXT_CREDENTIAL_KEY_PATH:
            _parsePathSpec(view, &credential->keyPath);
            break;
        case EXT_CREDENTIAL_KEY_HASH: {
            STATIC_ASSERT(SIZEOF(credential->keyHash) == ADDRESS_KEY_HASH_LENGTH,
                          "bad key hash container size");
            view_parseBuffer(credential->keyHash, view, SIZEOF(credential->keyHash));
            break;
        }
        case EXT_CREDENTIAL_SCRIPT_HASH: {
            STATIC_ASSERT(SIZEOF(credential->scriptHash) == SCRIPT_HASH_LENGTH,
                          "bad script hash container size");
            view_parseBuffer(credential->scriptHash, view, SIZEOF(credential->scriptHash));
            break;
        }
        default:
            THROW(ERR_INVALID_DATA);
    }
}

static void _parseDRep(read_view_t* view, ext_drep_t* drep) {
    drep->type = parse_u1be(view);
    switch (drep->type) {
        case EXT_DREP_KEY_PATH:
            _parsePathSpec(view, &drep->keyPath);
            break;
        case EXT_DREP_KEY_HASH: {
            STATIC_ASSERT(SIZEOF(drep->keyHash) == ADDRESS_KEY_HASH_LENGTH,
                          "bad key hash container size");
            view_parseBuffer(drep->keyHash, view, SIZEOF(drep->keyHash));
            break;
        }
        case EXT_DREP_SCRIPT_HASH: {
            STATIC_ASSERT(SIZEOF(drep->scriptHash) == SCRIPT_HASH_LENGTH,
                          "bad script hash container size");
            view_parseBuffer(drep->scriptHash, view, SIZEOF(drep->scriptHash));
            break;
        }
        case EXT_DREP_ABSTAIN:
        case EXT_DREP_NO_CONFIDENCE: {
            // nothing more to parse
            break;
        }
        default:
            THROW(ERR_INVALID_DATA);
    }
}

static void _parseAnchor(read_view_t* view, anchor_t* anchor) {
    {
        uint8_t includeAnchorByte = parse_u1be(view);
        anchor->isIncluded = signTx_parseIncluded(includeAnchorByte);

        if (!anchor->isIncluded) {
            VALIDATE(view_remainingSize(view) == 0, ERR_INVALID_DATA);
            return;
        }
    }
    {
        STATIC_ASSERT(SIZEOF(anchor->hash) == ANCHOR_HASH_LENGTH, "wrong anchor buffer size");
        view_parseBuffer(anchor->hash, view, ANCHOR_HASH_LENGTH);
    }
    {
        anchor->urlLength = view_remainingSize(view);
        VALIDATE(anchor->urlLength <= ANCHOR_URL_LENGTH_MAX, ERR_INVALID_DATA);
        STATIC_ASSERT(SIZEOF(anchor->url) >= ANCHOR_URL_LENGTH_MAX, "wrong anchor url length");
        view_parseBuffer(anchor->url, view, anchor->urlLength);

        // whitespace not allowed
        VALIDATE(str_isPrintableAsciiWithoutSpaces(anchor->url, anchor->urlLength),
                 ERR_INVALID_DATA);
    }

    VALIDATE(view_remainingSize(view) == 0, ERR_INVALID_DATA);
}

static void _parseCertificateData(const uint8_t* wireDataBuffer,
                                  size_t wireDataSize,
                                  sign_tx_certificate_data_t* certificateData) {
    TRACE_BUFFER(wireDataBuffer, wireDataSize);

    read_view_t view = make_read_view(wireDataBuffer, wireDataBuffer + wireDataSize);

    certificateData->type = parse_u1be(&view);
    TRACE("Certificate type: %d", certificateData->type);

    switch (certificateData->type) {
        case CERTIFICATE_STAKE_REGISTRATION:
        case CERTIFICATE_STAKE_DEREGISTRATION:
            _parseCredential(&view, &certificateData->stakeCredential);
            break;

        case CERTIFICATE_STAKE_REGISTRATION_CONWAY:
        case CERTIFICATE_STAKE_DEREGISTRATION_CONWAY:
            _parseCredential(&view, &certificateData->stakeCredential);
            certificateData->deposit = parse_u8be(&view);
            break;

        case CERTIFICATE_STAKE_DELEGATION:
            _parseCredential(&view, &certificateData->stakeCredential);
            certificateData->poolCredential.type = EXT_CREDENTIAL_KEY_HASH;
            STATIC_ASSERT(SIZEOF(certificateData->poolCredential.keyHash) == POOL_KEY_HASH_LENGTH,
                          "wrong poolKeyHash size");
            view_parseBuffer(certificateData->poolCredential.keyHash, &view, POOL_KEY_HASH_LENGTH);
            break;

        case CERTIFICATE_VOTE_DELEGATION:
            _parseCredential(&view, &certificateData->stakeCredential);
            _parseDRep(&view, &certificateData->drep);
            break;

        case CERTIFICATE_AUTHORIZE_COMMITTEE_HOT:
            _parseCredential(&view, &certificateData->committeeColdCredential);
            _parseCredential(&view, &certificateData->committeeHotCredential);
            break;

        case CERTIFICATE_RESIGN_COMMITTEE_COLD:
            _parseCredential(&view, &certificateData->committeeColdCredential);
            _parseAnchor(&view, &certificateData->anchor);
            break;

        case CERTIFICATE_DREP_REGISTRATION:
            _parseCredential(&view, &certificateData->dRepCredential);
            certificateData->deposit = parse_u8be(&view);
            _parseAnchor(&view, &certificateData->anchor);
            break;

        case CERTIFICATE_DREP_DEREGISTRATION:
            _parseCredential(&view, &certificateData->dRepCredential);
            certificateData->deposit = parse_u8be(&view);
            break;

        case CERTIFICATE_DREP_UPDATE:
            _parseCredential(&view, &certificateData->dRepCredential);
            _parseAnchor(&view, &certificateData->anchor);
            break;

#ifdef APP_FEATURE_POOL_REGISTRATION

        case CERTIFICATE_STAKE_POOL_REGISTRATION:
            // nothing more to parse, certificate data will be provided
            // in additional APDUs processed by a submachine
            return;

#endif  // APP_FEATURE_POOL_REGISTRATION

#ifdef APP_FEATURE_POOL_RETIREMENT

        case CERTIFICATE_STAKE_POOL_RETIREMENT:
            certificateData->poolCredential.type = EXT_CREDENTIAL_KEY_PATH;
            _parsePathSpec(&view, &certificateData->poolCredential.keyPath);
            certificateData->epoch = parse_u8be(&view);
            break;

#endif  // APP_FEATURE_POOL_RETIREMENT

        default:
            THROW(ERR_INVALID_DATA);
    }

    VALIDATE(view_remainingSize(&view) == 0, ERR_INVALID_DATA);
}

static void _setCredential(credential_t* credential, const ext_credential_t* extCredential) {
    switch (extCredential->type) {
        case EXT_CREDENTIAL_KEY_PATH:
            credential->type = CREDENTIAL_KEY_HASH;
            bip44_pathToKeyHash(&extCredential->keyPath,
                                credential->keyHash,
                                SIZEOF(credential->keyHash));
            break;

        case EXT_CREDENTIAL_KEY_HASH:
            credential->type = CREDENTIAL_KEY_HASH;
            STATIC_ASSERT(SIZEOF(credential->keyHash) == SIZEOF(extCredential->keyHash),
                          "bad script hash container size");
            memmove(credential->keyHash, extCredential->keyHash, SIZEOF(extCredential->keyHash));
            break;

        case EXT_CREDENTIAL_SCRIPT_HASH:
            credential->type = CREDENTIAL_SCRIPT_HASH;
            STATIC_ASSERT(SIZEOF(credential->scriptHash) == SIZEOF(extCredential->scriptHash),
                          "bad script hash container size");
            memmove(credential->scriptHash,
                    extCredential->scriptHash,
                    SIZEOF(extCredential->scriptHash));
            break;

        default:
            ASSERT(false);
            break;
    }
}

static void _setDRep(drep_t* drep, const ext_drep_t* extDRep) {
    switch (extDRep->type) {
        case EXT_DREP_KEY_PATH:
            drep->type = DREP_KEY_HASH;
            bip44_pathToKeyHash(&extDRep->keyPath, drep->keyHash, SIZEOF(drep->keyHash));
            break;

        case EXT_DREP_KEY_HASH:
            drep->type = DREP_KEY_HASH;
            STATIC_ASSERT(SIZEOF(drep->keyHash) == SIZEOF(extDRep->keyHash),
                          "bad script hash container size");
            memmove(drep->keyHash, extDRep->keyHash, SIZEOF(extDRep->keyHash));
            break;

        case EXT_DREP_SCRIPT_HASH:
            drep->type = DREP_SCRIPT_HASH;
            STATIC_ASSERT(SIZEOF(drep->scriptHash) == SIZEOF(extDRep->scriptHash),
                          "bad script hash container size");
            memmove(drep->scriptHash, extDRep->scriptHash, SIZEOF(extDRep->scriptHash));
            break;

        case EXT_DREP_ABSTAIN:
            drep->type = DREP_ALWAYS_ABSTAIN;
            break;

        case EXT_DREP_NO_CONFIDENCE:
            drep->type = DREP_ALWAYS_NO_CONFIDENCE;
            break;

        default:
            ASSERT(false);
            break;
    }
}

__noinline_due_to_stack__ static void _addCertificateDataToTx(
    sign_tx_certificate_data_t* certificateData,
    tx_hash_builder_t* txHashBuilder) {
    TRACE("Adding certificate (type %d) to tx hash", certificateData->type);

    // declared here to save the stack space compiler allocates for this function
    credential_t tmpCredential;

    switch (BODY_CTX->stageData.certificate.type) {
        case CERTIFICATE_STAKE_REGISTRATION:
        case CERTIFICATE_STAKE_DEREGISTRATION: {
            _setCredential(&tmpCredential, &certificateData->stakeCredential);
            txHashBuilder_addCertificate_stakingOld(txHashBuilder,
                                                    certificateData->type,
                                                    &tmpCredential);
            break;
        }

        case CERTIFICATE_STAKE_REGISTRATION_CONWAY:
        case CERTIFICATE_STAKE_DEREGISTRATION_CONWAY: {
            _setCredential(&tmpCredential, &certificateData->stakeCredential);
            txHashBuilder_addCertificate_staking(txHashBuilder,
                                                 certificateData->type,
                                                 &tmpCredential,
                                                 certificateData->deposit);
            break;
        }

        case CERTIFICATE_STAKE_DELEGATION: {
            _setCredential(&tmpCredential, &certificateData->stakeCredential);
            ASSERT(certificateData->poolCredential.type == EXT_CREDENTIAL_KEY_HASH);
            txHashBuilder_addCertificate_stakeDelegation(
                txHashBuilder,
                &tmpCredential,
                certificateData->poolCredential.keyHash,
                SIZEOF(certificateData->poolCredential.keyHash));
            break;
        }

        case CERTIFICATE_VOTE_DELEGATION: {
            drep_t drep;
            _setCredential(&tmpCredential, &certificateData->stakeCredential);
            _setDRep(&drep, &certificateData->drep);
            txHashBuilder_addCertificate_voteDelegation(txHashBuilder, &tmpCredential, &drep);
            break;
        }

        case CERTIFICATE_AUTHORIZE_COMMITTEE_HOT: {
            credential_t hotCredential;
            _setCredential(&tmpCredential, &certificateData->committeeColdCredential);
            _setCredential(&hotCredential, &certificateData->committeeHotCredential);
            txHashBuilder_addCertificate_committeeAuthHot(txHashBuilder,
                                                          &tmpCredential,
                                                          &hotCredential);
            break;
        }

        case CERTIFICATE_RESIGN_COMMITTEE_COLD: {
            _setCredential(&tmpCredential, &certificateData->committeeColdCredential);
            txHashBuilder_addCertificate_committeeResign(txHashBuilder,
                                                         &tmpCredential,
                                                         &certificateData->anchor);
            break;
        }

        case CERTIFICATE_DREP_REGISTRATION: {
            _setCredential(&tmpCredential, &certificateData->dRepCredential);
            txHashBuilder_addCertificate_dRepRegistration(txHashBuilder,
                                                          &tmpCredential,
                                                          certificateData->deposit,
                                                          &certificateData->anchor);
            break;
        }

        case CERTIFICATE_DREP_DEREGISTRATION: {
            _setCredential(&tmpCredential, &certificateData->dRepCredential);
            txHashBuilder_addCertificate_dRepDeregistration(txHashBuilder,
                                                            &tmpCredential,
                                                            certificateData->deposit);
            break;
        }

        case CERTIFICATE_DREP_UPDATE: {
            _setCredential(&tmpCredential, &certificateData->dRepCredential);
            txHashBuilder_addCertificate_dRepUpdate(txHashBuilder,
                                                    &tmpCredential,
                                                    &certificateData->anchor);
            break;
        }

#ifdef APP_FEATURE_POOL_RETIREMENT

        case CERTIFICATE_STAKE_POOL_RETIREMENT: {
            uint8_t hash[ADDRESS_KEY_HASH_LENGTH] = {0};
            ext_credential_t* extCredential = &BODY_CTX->stageData.certificate.poolCredential;
            ASSERT(extCredential->type == EXT_CREDENTIAL_KEY_PATH);
            bip44_pathToKeyHash(&extCredential->keyPath, hash, SIZEOF(hash));
            txHashBuilder_addCertificate_poolRetirement(txHashBuilder,
                                                        hash,
                                                        SIZEOF(hash),
                                                        certificateData->epoch);
            break;
        }

#endif  // APP_FEATURE_POOL_RETIREMENT

        default:
            // stake pool registration data only added in the sub-machine, not here
            // see signTxPoolRegistration.c
            ASSERT(false);
    }
}

#ifdef APP_FEATURE_POOL_REGISTRATION

static bool _handlePoolRegistrationIfNeeded(uint8_t p2,
                                            const uint8_t* wireDataBuffer,
                                            size_t wireDataSize) {
    // delegate to state sub-machine for stake pool registration certificate data
    if (signTxPoolRegistration_isValidInstruction(p2)) {
        TRACE();
        VALIDATE(ctx->stage == SIGN_STAGE_BODY_CERTIFICATES_POOL_SUBMACHINE, ERR_INVALID_DATA);

        TRACE_STACK_USAGE();

        signTxPoolRegistration_handleAPDU(p2, wireDataBuffer, wireDataSize);
        return true;
    }

    return false;
}

#endif  // APP_FEATURE_POOL_REGISTRATION

static void _handleCertificateStaking() {
    security_policy_t policy = POLICY_DENY;
#ifdef HAVE_SWAP
    if (G_called_from_swap) {
        policy = POLICY_ALLOW_WITHOUT_PROMPT;
    } else
#endif
    {
        policy =
            policyForSignTxCertificateStaking(ctx->commonTxData.txSigningMode,
                                              BODY_CTX->stageData.certificate.type,
                                              &BODY_CTX->stageData.certificate.stakeCredential);
        TRACE("Policy: %d", (int) policy);
        ENSURE_NOT_DENIED(policy);
    }

    _addCertificateDataToTx(&BODY_CTX->stageData.certificate, &BODY_CTX->txHashBuilder);

    switch (policy) {
#define CASE(POLICY, UI_STEP)   \
    case POLICY: {              \
        ctx->ui_step = UI_STEP; \
        break;                  \
    }
        CASE(POLICY_PROMPT_BEFORE_RESPONSE, HANDLE_CERTIFICATE_STAKING_STEP_DISPLAY_OPERATION);
        CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_CERTIFICATE_STAKING_STEP_RESPOND);
#undef CASE
        default:
            THROW(ERR_NOT_IMPLEMENTED);
    }

    signTx_handleCertificateStaking_ui_runStep();
}

static void _handleCertificateVoteDeleg() {
    security_policy_t policy = POLICY_DENY;
#ifdef HAVE_SWAP
    if (G_called_from_swap) {
        policy = POLICY_ALLOW_WITHOUT_PROMPT;
    } else
#endif
    {
        policy = policyForSignTxCertificateVoteDelegation(
            ctx->commonTxData.txSigningMode,
            &BODY_CTX->stageData.certificate.stakeCredential,
            &BODY_CTX->stageData.certificate.drep);
        TRACE("Policy: %d", (int) policy);
        ENSURE_NOT_DENIED(policy);
    }

    _addCertificateDataToTx(&BODY_CTX->stageData.certificate, &BODY_CTX->txHashBuilder);

    switch (policy) {
#define CASE(POLICY, UI_STEP)   \
    case POLICY: {              \
        ctx->ui_step = UI_STEP; \
        break;                  \
    }
        CASE(POLICY_PROMPT_BEFORE_RESPONSE,
             HANDLE_CERTIFICATE_VOTE_DELEGATION_STEP_DISPLAY_OPERATION);
        CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_CERTIFICATE_VOTE_DELEGATION_STEP_RESPOND);
#undef CASE
        default:
            THROW(ERR_NOT_IMPLEMENTED);
    }

    signTx_handleCertificateVoteDeleg_ui_runStep();
}

static void _handleCertificateCommitteeAuth() {
    security_policy_t policy = POLICY_DENY;
#ifdef HAVE_SWAP
    if (G_called_from_swap) {
        policy = POLICY_ALLOW_WITHOUT_PROMPT;
    } else
#endif
    {
        policy = policyForSignTxCertificateCommitteeAuth(
            ctx->commonTxData.txSigningMode,
            &BODY_CTX->stageData.certificate.committeeColdCredential,
            &BODY_CTX->stageData.certificate.committeeHotCredential);
        TRACE("Policy: %d", (int) policy);
        ENSURE_NOT_DENIED(policy);
    }

    _addCertificateDataToTx(&BODY_CTX->stageData.certificate, &BODY_CTX->txHashBuilder);

    switch (policy) {
#define CASE(POLICY, UI_STEP)   \
    case POLICY: {              \
        ctx->ui_step = UI_STEP; \
        break;                  \
    }
        CASE(POLICY_PROMPT_BEFORE_RESPONSE, HANDLE_CERTIFICATE_COMM_AUTH_STEP_DISPLAY_OPERATION);
        CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_CERTIFICATE_COMM_AUTH_STEP_RESPOND);
#undef CASE
        default:
            THROW(ERR_NOT_IMPLEMENTED);
    }

    signTx_handleCertificateCommitteeAuth_ui_runStep();
}

static void _handleCertificateCommitteeResign() {
    security_policy_t policy = POLICY_DENY;
#ifdef HAVE_SWAP
    if (G_called_from_swap) {
        policy = POLICY_ALLOW_WITHOUT_PROMPT;
    } else
#endif
    {
        policy = policyForSignTxCertificateCommitteeResign(
            ctx->commonTxData.txSigningMode,
            &BODY_CTX->stageData.certificate.committeeColdCredential);
        TRACE("Policy: %d", (int) policy);
        ENSURE_NOT_DENIED(policy);
    }

    _addCertificateDataToTx(&BODY_CTX->stageData.certificate, &BODY_CTX->txHashBuilder);

    switch (policy) {
#define CASE(POLICY, UI_STEP)   \
    case POLICY: {              \
        ctx->ui_step = UI_STEP; \
        break;                  \
    }
        CASE(POLICY_PROMPT_BEFORE_RESPONSE, HANDLE_CERTIFICATE_COMM_RESIGN_STEP_DISPLAY_OPERATION);
        CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_CERTIFICATE_COMM_RESIGN_STEP_RESPOND);
#undef CASE
        default:
            THROW(ERR_NOT_IMPLEMENTED);
    }

    signTx_handleCertificateCommitteeResign_ui_runStep();
}

static void _handleCertificateDRep() {
    security_policy_t policy = POLICY_DENY;
#ifdef HAVE_SWAP
    if (G_called_from_swap) {
        policy = POLICY_ALLOW_WITHOUT_PROMPT;
    } else
#endif
    {
        policy = policyForSignTxCertificateDRep(ctx->commonTxData.txSigningMode,
                                                &BODY_CTX->stageData.certificate.dRepCredential);
        TRACE("Policy: %d", (int) policy);
        ENSURE_NOT_DENIED(policy);
    }

    _addCertificateDataToTx(&BODY_CTX->stageData.certificate, &BODY_CTX->txHashBuilder);

    switch (policy) {
#define CASE(POLICY, UI_STEP)   \
    case POLICY: {              \
        ctx->ui_step = UI_STEP; \
        break;                  \
    }
        CASE(POLICY_PROMPT_BEFORE_RESPONSE, HANDLE_CERTIFICATE_DREP_STEP_DISPLAY_OPERATION);
        CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_CERTIFICATE_DREP_STEP_RESPOND);
#undef CASE
        default:
            THROW(ERR_NOT_IMPLEMENTED);
    }

    signTx_handleCertificateDRep_ui_runStep();
}

#ifdef APP_FEATURE_POOL_REGISTRATION

static void _handleCertificatePoolRegistration() {
    // pool registration certificates have a separate sub-machine for handling APDU and UI
    // nothing more to be done with them here, we just init the sub-machine
    ctx->stage = SIGN_STAGE_BODY_CERTIFICATES_POOL_SUBMACHINE;
    signTxPoolRegistration_init();

    respondSuccessEmptyMsg();
}

#endif  // APP_FEATURE_POOL_REGISTRATION

#ifdef APP_FEATURE_POOL_RETIREMENT

static void _handleCertificatePoolRetirement() {
    security_policy_t policy = POLICY_DENY;
#ifdef HAVE_SWAP
    if (G_called_from_swap) {
        policy = POLICY_ALLOW_WITHOUT_PROMPT;
    } else
#endif
    {
        policy = policyForSignTxCertificateStakePoolRetirement(
            ctx->commonTxData.txSigningMode,
            &BODY_CTX->stageData.certificate.poolCredential,
            BODY_CTX->stageData.certificate.epoch);
        TRACE("Policy: %d", (int) policy);
        ENSURE_NOT_DENIED(policy);
    }

    _addCertificateDataToTx(&BODY_CTX->stageData.certificate, &BODY_CTX->txHashBuilder);

    switch (policy) {
#define CASE(POLICY, UI_STEP)   \
    case POLICY: {              \
        ctx->ui_step = UI_STEP; \
        break;                  \
    }
        CASE(POLICY_PROMPT_BEFORE_RESPONSE,
             HANDLE_CERTIFICATE_POOL_RETIREMENT_STEP_DISPLAY_OPERATION);
        CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_CERTIFICATE_POOL_RETIREMENT_STEP_RESPOND);
#undef CASE
        default:
            THROW(ERR_NOT_IMPLEMENTED);
    }
    signTx_handleCertificatePoolRetirement_ui_runStep();
}

#endif  // APP_FEATURE_POOL_RETIREMENT

// Note(JM): it is possible to treat every certificate separately,
// which makes the code somewhat more readable if read per certificate,
// but it increases code size and that creates problems for Nano S
__noinline_due_to_stack__ static void signTx_handleCertificateAPDU(uint8_t p2,
                                                                   const uint8_t* wireDataBuffer,
                                                                   size_t wireDataSize) {
    TRACE_STACK_USAGE();
    ASSERT(BODY_CTX->currentCertificate < ctx->numCertificates);

#ifdef APP_FEATURE_POOL_REGISTRATION
    // usage of P2 determines if we are in the pool registration submachine
    if (_handlePoolRegistrationIfNeeded(p2, wireDataBuffer, wireDataSize)) {
        return;
    }
#endif  // APP_FEATURE_POOL_REGISTRATION
    VALIDATE(p2 == P2_UNUSED, ERR_INVALID_REQUEST_PARAMETERS);
    CHECK_STAGE(SIGN_STAGE_BODY_CERTIFICATES);

    // a new certificate arrived
    explicit_bzero(&BODY_CTX->stageData.certificate, SIZEOF(BODY_CTX->stageData.certificate));
    _parseCertificateData(wireDataBuffer, wireDataSize, &BODY_CTX->stageData.certificate);
#ifdef HAVE_SWAP
    if (!G_called_from_swap)
#endif
    {
        // basic policy that just decides if the certificate type is allowed
        security_policy_t policy = policyForSignTxCertificate(ctx->commonTxData.txSigningMode,
                                                              BODY_CTX->stageData.certificate.type);
        TRACE("Policy: %d", (int) policy);
        ENSURE_NOT_DENIED(policy);
    }

    switch (BODY_CTX->stageData.certificate.type) {
        case CERTIFICATE_STAKE_REGISTRATION:
        case CERTIFICATE_STAKE_DEREGISTRATION:
        case CERTIFICATE_STAKE_REGISTRATION_CONWAY:
        case CERTIFICATE_STAKE_DEREGISTRATION_CONWAY:
        case CERTIFICATE_STAKE_DELEGATION: {
            _handleCertificateStaking();
            return;
        }

        case CERTIFICATE_VOTE_DELEGATION: {
            _handleCertificateVoteDeleg();
            return;
        }

        case CERTIFICATE_AUTHORIZE_COMMITTEE_HOT: {
            _handleCertificateCommitteeAuth();
            return;
        }

        case CERTIFICATE_RESIGN_COMMITTEE_COLD: {
            _handleCertificateCommitteeResign();
            return;
        }

        case CERTIFICATE_DREP_REGISTRATION:
        case CERTIFICATE_DREP_DEREGISTRATION:
        case CERTIFICATE_DREP_UPDATE: {
            _handleCertificateDRep();
            return;
        }

#ifdef APP_FEATURE_POOL_REGISTRATION
        case CERTIFICATE_STAKE_POOL_REGISTRATION: {
            _handleCertificatePoolRegistration();
            return;
        }
#endif  // APP_FEATURE_POOL_REGISTRATION

#ifdef APP_FEATURE_POOL_RETIREMENT
        case CERTIFICATE_STAKE_POOL_RETIREMENT: {
            _handleCertificatePoolRetirement();
            return;
        }
#endif  // APP_FEATURE_POOL_RETIREMENT

        default:
            ASSERT(false);
    }
}

// ============================== WITHDRAWALS ==============================

__noinline_due_to_stack__ static void _addWithdrawalToTxHash(bool validateCanonicalOrdering) {
    uint8_t rewardAddress[REWARD_ACCOUNT_SIZE] = {0};

    switch (BODY_CTX->stageData.withdrawal.stakeCredential.type) {
        case EXT_CREDENTIAL_KEY_PATH:
            constructRewardAddressFromKeyPath(
                &BODY_CTX->stageData.withdrawal.stakeCredential.keyPath,
                ctx->commonTxData.networkId,
                rewardAddress,
                SIZEOF(rewardAddress));
            break;
        case EXT_CREDENTIAL_KEY_HASH:
            constructRewardAddressFromHash(
                ctx->commonTxData.networkId,
                REWARD_HASH_SOURCE_KEY,
                BODY_CTX->stageData.withdrawal.stakeCredential.keyHash,
                SIZEOF(BODY_CTX->stageData.withdrawal.stakeCredential.keyHash),
                rewardAddress,
                SIZEOF(rewardAddress));
            break;
        case EXT_CREDENTIAL_SCRIPT_HASH:
            constructRewardAddressFromHash(
                ctx->commonTxData.networkId,
                REWARD_HASH_SOURCE_SCRIPT,
                BODY_CTX->stageData.withdrawal.stakeCredential.scriptHash,
                SIZEOF(BODY_CTX->stageData.withdrawal.stakeCredential.scriptHash),
                rewardAddress,
                SIZEOF(rewardAddress));
            break;
        default:
            ASSERT(false);
            return;
    }

    {
        STATIC_ASSERT(
            SIZEOF(BODY_CTX->stageData.withdrawal.previousRewardAccount) == REWARD_ACCOUNT_SIZE,
            "wrong reward account buffer size");
        STATIC_ASSERT(SIZEOF(rewardAddress) == REWARD_ACCOUNT_SIZE,
                      "wrong reward account buffer size");

        if (validateCanonicalOrdering) {
            // compare with previous map entry
            VALIDATE(cbor_mapKeyFulfillsCanonicalOrdering(
                         BODY_CTX->stageData.withdrawal.previousRewardAccount,
                         REWARD_ACCOUNT_SIZE,
                         rewardAddress,
                         REWARD_ACCOUNT_SIZE),
                     ERR_INVALID_DATA);
        }

        // update the value for potential future comparison
        memmove(BODY_CTX->stageData.withdrawal.previousRewardAccount,
                rewardAddress,
                REWARD_ACCOUNT_SIZE);
    }

    TRACE("Adding withdrawal to tx hash");
    txHashBuilder_addWithdrawal(&BODY_CTX->txHashBuilder,
                                rewardAddress,
                                SIZEOF(rewardAddress),
                                BODY_CTX->stageData.withdrawal.amount);
}

__noinline_due_to_stack__ static void signTx_handleWithdrawalAPDU(uint8_t p2,
                                                                  const uint8_t* wireDataBuffer,
                                                                  size_t wireDataSize) {
    TRACE_STACK_USAGE();
    {
        // sanity checks
        CHECK_STAGE(SIGN_STAGE_BODY_WITHDRAWALS);
        ASSERT(BODY_CTX->currentWithdrawal < ctx->numWithdrawals);

        VALIDATE(p2 == P2_UNUSED, ERR_INVALID_REQUEST_PARAMETERS);
    }

    // we can't bzero the whole stageData.withdrawal since
    // we need to compare it with the previous one (canonical ordering check)
    BODY_CTX->stageData.withdrawal.amount = 0;
    explicit_bzero(&BODY_CTX->stageData.withdrawal.stakeCredential,
                   SIZEOF(BODY_CTX->stageData.withdrawal.stakeCredential));

    {
        // parse input
        TRACE_BUFFER(wireDataBuffer, wireDataSize);

        read_view_t view = make_read_view(wireDataBuffer, wireDataBuffer + wireDataSize);
        BODY_CTX->stageData.withdrawal.amount = parse_u8be(&view);

        _parseCredential(&view, &BODY_CTX->stageData.withdrawal.stakeCredential);

        VALIDATE(view_remainingSize(&view) == 0, ERR_INVALID_DATA);
    }

    security_policy_t policy = POLICY_DENY;
#ifdef HAVE_SWAP
    if (G_called_from_swap) {
        policy = POLICY_ALLOW_WITHOUT_PROMPT;
    } else
#endif
    {
        policy = policyForSignTxWithdrawal(ctx->commonTxData.txSigningMode,
                                           &BODY_CTX->stageData.withdrawal.stakeCredential);
        TRACE("Policy: %d", (int) policy);
        ENSURE_NOT_DENIED(policy);
    }

    const bool validateCanonicalOrdering = BODY_CTX->currentWithdrawal > 0;
    _addWithdrawalToTxHash(validateCanonicalOrdering);

    {
        // select UI steps
        switch (policy) {
#define CASE(POLICY, UI_STEP)   \
    case POLICY: {              \
        ctx->ui_step = UI_STEP; \
        break;                  \
    }
            CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_WITHDRAWAL_STEP_DISPLAY_AMOUNT);
            CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_WITHDRAWAL_STEP_RESPOND);
#undef CASE
            default:
                THROW(ERR_NOT_IMPLEMENTED);
        }
    }

    signTx_handleWithdrawal_ui_runStep();
}

// ============================== VALIDITY INTERVAL START ==============================

static void signTx_handleValidityIntervalStartAPDU(uint8_t p2,
                                                   const uint8_t* wireDataBuffer,
                                                   size_t wireDataSize) {
    {
        // sanity checks
        CHECK_STAGE(SIGN_STAGE_BODY_VALIDITY_INTERVAL);
        ASSERT(ctx->includeValidityIntervalStart == true);

        VALIDATE(p2 == P2_UNUSED, ERR_INVALID_REQUEST_PARAMETERS);
    }

    {
        // parse data
        TRACE_BUFFER(wireDataBuffer, wireDataSize);

        VALIDATE(wireDataSize == 8, ERR_INVALID_DATA);
        BODY_CTX->stageData.validityIntervalStart = u8be_read(wireDataBuffer);
        BODY_CTX->validityIntervalStartReceived = true;
    }

    security_policy_t policy = POLICY_DENY;
#ifdef HAVE_SWAP
    if (G_called_from_swap) {
        policy = POLICY_ALLOW_WITHOUT_PROMPT;
    } else
#endif
    {
        policy = policyForSignTxValidityIntervalStart();
        TRACE("Policy: %d", (int) policy);
        ENSURE_NOT_DENIED(policy);
    }

    {
        TRACE("Adding validity interval start to tx hash");
        txHashBuilder_addValidityIntervalStart(&BODY_CTX->txHashBuilder,
                                               BODY_CTX->stageData.validityIntervalStart);
        TRACE();
    }

    {
        // select UI step
        switch (policy) {
#define CASE(POLICY, UI_STEP)   \
    case POLICY: {              \
        ctx->ui_step = UI_STEP; \
        break;                  \
    }
            CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_VALIDITY_INTERVAL_START_STEP_DISPLAY);
            CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_VALIDITY_INTERVAL_START_STEP_RESPOND);
#undef CASE
            default:
                THROW(ERR_NOT_IMPLEMENTED);
        }
    }

    signTx_handleValidityInterval_ui_runStep();
}

// ============================== MINT ==============================

static void signTx_handleMintAPDU(uint8_t p2, const uint8_t* wireDataBuffer, size_t wireDataSize) {
    {
        TRACE("p2 = %d", p2);
        TRACE_BUFFER(wireDataBuffer, wireDataSize);
    }

    if (ctx->stage == SIGN_STAGE_BODY_MINT) {
        ctx->stage = SIGN_STAGE_BODY_MINT_SUBMACHINE;
    }

    CHECK_STAGE(SIGN_STAGE_BODY_MINT_SUBMACHINE);

    // all mint handling is delegated to a state sub-machine
    VALIDATE(signTxMint_isValidInstruction(p2), ERR_INVALID_REQUEST_PARAMETERS);
    signTxMint_handleAPDU(p2, wireDataBuffer, wireDataSize);
}

// ========================= SCRIPT DATA HASH ==========================

static void signTx_handleScriptDataHashAPDU(uint8_t p2,
                                            const uint8_t* wireDataBuffer,
                                            size_t wireDataSize) {
    {
        // sanity checks
        CHECK_STAGE(SIGN_STAGE_BODY_SCRIPT_DATA_HASH);
        ASSERT(ctx->includeScriptDataHash == true);

        VALIDATE(p2 == P2_UNUSED, ERR_INVALID_REQUEST_PARAMETERS);
    }
    {
        // parse data
        TRACE_BUFFER(wireDataBuffer, wireDataSize);

        read_view_t view = make_read_view(wireDataBuffer, wireDataBuffer + wireDataSize);
        STATIC_ASSERT(SIZEOF(BODY_CTX->stageData.scriptDataHash) == SCRIPT_DATA_HASH_LENGTH,
                      "wrong script data hash length");
        view_parseBuffer(BODY_CTX->stageData.scriptDataHash, &view, SCRIPT_DATA_HASH_LENGTH);
        VALIDATE(view_remainingSize(&view) == 0, ERR_INVALID_DATA);

        BODY_CTX->scriptDataHashReceived = true;
    }

    security_policy_t policy = POLICY_DENY;
#ifdef HAVE_SWAP
    if (G_called_from_swap) {
        policy = POLICY_ALLOW_WITHOUT_PROMPT;
    } else
#endif
    {
        policy = policyForSignTxScriptDataHash(ctx->commonTxData.txSigningMode);
        TRACE("Policy: %d", (int) policy);
        ENSURE_NOT_DENIED(policy);
    }

    {
        // add to tx
        TRACE("Adding script data hash to tx hash");
        txHashBuilder_addScriptDataHash(&BODY_CTX->txHashBuilder,
                                        BODY_CTX->stageData.scriptDataHash,
                                        SIZEOF(BODY_CTX->stageData.scriptDataHash));
    }

    {
        // select UI steps
        switch (policy) {
#define CASE(POLICY, UI_STEP)   \
    case POLICY: {              \
        ctx->ui_step = UI_STEP; \
        break;                  \
    }
            CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_SCRIPT_DATA_HASH_STEP_DISPLAY);
            CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_SCRIPT_DATA_HASH_STEP_RESPOND);
#undef CASE
            default:
                THROW(ERR_NOT_IMPLEMENTED);
        }
    }

    signTx_handleScriptDataHash_ui_runStep();
}

// ============================== COLLATERAL INPUTS ==============================

// Advance stage to the next collateral input
static void ui_advanceState_collateralInput() {
    ASSERT(BODY_CTX->currentCollateral < ctx->numCollateralInputs);
    BODY_CTX->currentCollateral++;

    if (BODY_CTX->currentCollateral == ctx->numCollateralInputs) {
        tx_advanceStage();
    }
}

__noinline_due_to_stack__ static void
signTx_handleCollateralInputAPDU(uint8_t p2, const uint8_t* wireDataBuffer, size_t wireDataSize) {
    TRACE_STACK_USAGE();
    {
        // sanity checks
        CHECK_STAGE(SIGN_STAGE_BODY_COLLATERAL_INPUTS);
        ASSERT(BODY_CTX->currentCollateral < ctx->numCollateralInputs);

        VALIDATE(p2 == P2_UNUSED, ERR_INVALID_REQUEST_PARAMETERS);
    }

    parseInput(wireDataBuffer, wireDataSize);

    security_policy_t policy = POLICY_DENY;
#ifdef HAVE_SWAP
    if (G_called_from_swap) {
        policy = POLICY_ALLOW_WITHOUT_PROMPT;
    } else
#endif
    {
        policy = policyForSignTxCollateralInput(ctx->commonTxData.txSigningMode,
                                                ctx->includeTotalCollateral);
        TRACE("Policy: %d", (int) policy);
        ENSURE_NOT_DENIED(policy);
    }

    {
        // add to tx
        TRACE("Adding collateral input to tx hash");
        txHashBuilder_addCollateralInput(&BODY_CTX->txHashBuilder,
                                         &BODY_CTX->stageData.input.input_data);
    }
    {
        // not needed if input is not shown, but does not cost much time, so not worth branching
        constructInputLabel("Collat. input", BODY_CTX->currentCollateral);

        ctx->ui_advanceState = ui_advanceState_collateralInput;
        ui_selectInputStep(policy);
        signTx_handleInput_ui_runStep();
    }
}

// ========================= REQUIRED SIGNERS ===========================

__noinline_due_to_stack__ static void signTx_handleRequiredSignerAPDU(uint8_t p2,
                                                                      const uint8_t* wireDataBuffer,
                                                                      size_t wireDataSize) {
    TRACE_STACK_USAGE();
    {
        // sanity checks
        CHECK_STAGE(SIGN_STAGE_BODY_REQUIRED_SIGNERS);
        ASSERT(BODY_CTX->currentRequiredSigner < ctx->numRequiredSigners);

        VALIDATE(p2 == P2_UNUSED, ERR_INVALID_REQUEST_PARAMETERS);
    }

    {
        TRACE_BUFFER(wireDataBuffer, wireDataSize);

        read_view_t view = make_read_view(wireDataBuffer, wireDataBuffer + wireDataSize);
        BODY_CTX->stageData.requiredSigner.type = parse_u1be(&view);
        STATIC_ASSERT(SIZEOF(BODY_CTX->stageData.requiredSigner.keyHash) == ADDRESS_KEY_HASH_LENGTH,
                      "wrong key hash length");
        switch (BODY_CTX->stageData.requiredSigner.type) {
            case REQUIRED_SIGNER_WITH_PATH:
                _parsePathSpec(&view, &BODY_CTX->stageData.requiredSigner.keyPath);
                break;
            case REQUIRED_SIGNER_WITH_HASH:
                view_parseBuffer(BODY_CTX->stageData.requiredSigner.keyHash,
                                 &view,
                                 ADDRESS_KEY_HASH_LENGTH);
                break;
        }
        VALIDATE(view_remainingSize(&view) == 0, ERR_INVALID_DATA);
    }

    security_policy_t policy = POLICY_DENY;
#ifdef HAVE_SWAP
    if (G_called_from_swap) {
        policy = POLICY_ALLOW_WITHOUT_PROMPT;
    } else
#endif
    {
        policy = policyForSignTxRequiredSigner(ctx->commonTxData.txSigningMode,
                                               &BODY_CTX->stageData.requiredSigner);
        TRACE("Policy: %d", (int) policy);
        ENSURE_NOT_DENIED(policy);
    }

    {
        // add to tx
        TRACE("Adding required signer to tx hash");
        if (BODY_CTX->stageData.requiredSigner.type == REQUIRED_SIGNER_WITH_PATH) {
            uint8_t keyHash[ADDRESS_KEY_HASH_LENGTH] = {0};
            bip44_pathToKeyHash(&BODY_CTX->stageData.requiredSigner.keyPath,
                                keyHash,
                                SIZEOF(keyHash));
            txHashBuilder_addRequiredSigner(&BODY_CTX->txHashBuilder, keyHash, SIZEOF(keyHash));
        } else {
            txHashBuilder_addRequiredSigner(&BODY_CTX->txHashBuilder,
                                            BODY_CTX->stageData.requiredSigner.keyHash,
                                            SIZEOF(BODY_CTX->stageData.requiredSigner.keyHash));
        }
    }

    {
        // select UI steps
        switch (policy) {
#define CASE(POLICY, UI_STEP)   \
    case POLICY: {              \
        ctx->ui_step = UI_STEP; \
        break;                  \
    }
            CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_REQUIRED_SIGNERS_STEP_DISPLAY);
            CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_REQUIRED_SIGNERS_STEP_RESPOND);
#undef CASE
            default:
                THROW(ERR_NOT_IMPLEMENTED);
        }
    }
    signTx_handleRequiredSigner_ui_runStep();
}

// ========================= COLLATERAL RETURN OUTPUT ===========================

static void signTx_handleCollateralOutputAPDU(uint8_t p2,
                                              const uint8_t* wireDataBuffer,
                                              size_t wireDataSize) {
    {
        TRACE("p2 = %d", p2);
        TRACE_BUFFER(wireDataBuffer, wireDataSize);
    }

    if (ctx->stage == SIGN_STAGE_BODY_COLLATERAL_OUTPUT) {
        // first APDU for collateral return output
        initializeOutputSubmachine();
        ctx->stage = SIGN_STAGE_BODY_COLLATERAL_OUTPUT_SUBMACHINE;
    }

    CHECK_STAGE(SIGN_STAGE_BODY_COLLATERAL_OUTPUT_SUBMACHINE);

    // all output handling is delegated to a state sub-machine
    VALIDATE(signTxCollateralOutput_isValidInstruction(p2), ERR_INVALID_REQUEST_PARAMETERS);
    signTxCollateralOutput_handleAPDU(p2, wireDataBuffer, wireDataSize);
}

// ========================= TOTAL COLLATERAL ===========================

__noinline_due_to_stack__ static void
signTx_handleTotalCollateralAPDU(uint8_t p2, const uint8_t* wireDataBuffer, size_t wireDataSize) {
    {
        // sanity checks
        CHECK_STAGE(SIGN_STAGE_BODY_TOTAL_COLLATERAL);
        ASSERT(ctx->includeTotalCollateral == true);

        VALIDATE(p2 == P2_UNUSED, ERR_INVALID_REQUEST_PARAMETERS);
    }
    {
        // parse data
        TRACE_BUFFER(wireDataBuffer, wireDataSize);

        VALIDATE(wireDataSize == 8, ERR_INVALID_DATA);

        BODY_CTX->stageData.totalCollateral = u8be_read(wireDataBuffer);
        BODY_CTX->totalCollateralReceived = true;
        TRACE("totalCollateral:");
        TRACE_UINT64(BODY_CTX->stageData.totalCollateral);
    }

    security_policy_t policy = POLICY_DENY;
#ifdef HAVE_SWAP
    if (G_called_from_swap) {
        policy = POLICY_ALLOW_WITHOUT_PROMPT;
    } else
#endif
    {
        policy = policyForSignTxTotalCollateral();
        TRACE("Policy: %d", (int) policy);
        ENSURE_NOT_DENIED(policy);
    }

    {
        // add to tx
        TRACE("Adding total collateral to tx hash");
        txHashBuilder_addTotalCollateral(&BODY_CTX->txHashBuilder,
                                         BODY_CTX->stageData.totalCollateral);
    }

    {
        // select UI steps
        switch (policy) {
#define CASE(POLICY, UI_STEP)   \
    case POLICY: {              \
        ctx->ui_step = UI_STEP; \
        break;                  \
    }
            CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_TOTAL_COLLATERAL_STEP_DISPLAY);
            CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_TOTAL_COLLATERAL_STEP_RESPOND);
#undef CASE
            default:
                THROW(ERR_NOT_IMPLEMENTED);
        }
    }

    signTx_handleTotalCollateral_ui_runStep();
}

// ============================== REFERENCE INPUTS ==============================

// Advance stage to the next input
static void ui_advanceState_ReferenceInput() {
    ASSERT(BODY_CTX->currentReferenceInput < ctx->numReferenceInputs);
    BODY_CTX->currentReferenceInput++;

    if (BODY_CTX->currentReferenceInput == ctx->numReferenceInputs) {
        tx_advanceStage();
    }
}

__noinline_due_to_stack__ static void signTx_handleReferenceInputAPDU(uint8_t p2,
                                                                      const uint8_t* wireDataBuffer,
                                                                      size_t wireDataSize) {
    TRACE_STACK_USAGE();
    {
        // sanity checks
        CHECK_STAGE(SIGN_STAGE_BODY_REFERENCE_INPUTS);
        ASSERT(BODY_CTX->currentReferenceInput < ctx->numReferenceInputs);

        VALIDATE(p2 == P2_UNUSED, ERR_INVALID_REQUEST_PARAMETERS);
    }
    // Parsed in same way as the inputs
    parseInput(wireDataBuffer, wireDataSize);

    security_policy_t policy = POLICY_DENY;
#ifdef HAVE_SWAP
    if (G_called_from_swap) {
        policy = POLICY_ALLOW_WITHOUT_PROMPT;
    } else
#endif
    {
        policy = policyForSignTxReferenceInput(ctx->commonTxData.txSigningMode);
        TRACE("Policy: %d", (int) policy);
        ENSURE_NOT_DENIED(policy);
    }

    {
        // add to tx
        TRACE("Adding reference input to tx hash");
        txHashBuilder_addReferenceInput(&BODY_CTX->txHashBuilder,
                                        &BODY_CTX->stageData.input.input_data);
    }
    {
        // not needed if input is not shown, but does not cost much time, so not worth branching
        constructInputLabel("Refer. input", BODY_CTX->currentReferenceInput);

        ctx->ui_advanceState = ui_advanceState_ReferenceInput;
        ui_selectInputStep(policy);
        signTx_handleInput_ui_runStep();
    }
}

// ========================= VOTING PROCEDURES ===========================

static void _setVoter(voter_t* voter, const ext_voter_t* extVoter) {
    switch (extVoter->type) {
        case EXT_VOTER_COMMITTEE_HOT_KEY_PATH:
            voter->type = VOTER_COMMITTEE_HOT_KEY_HASH;
            bip44_pathToKeyHash(&extVoter->keyPath, voter->keyHash, SIZEOF(voter->keyHash));
            break;

        case EXT_VOTER_DREP_KEY_PATH:
            voter->type = VOTER_DREP_KEY_HASH;
            bip44_pathToKeyHash(&extVoter->keyPath, voter->keyHash, SIZEOF(voter->keyHash));
            break;

        case EXT_VOTER_STAKE_POOL_KEY_PATH:
            voter->type = VOTER_STAKE_POOL_KEY_HASH;
            bip44_pathToKeyHash(&extVoter->keyPath, voter->keyHash, SIZEOF(voter->keyHash));
            break;

        case EXT_VOTER_COMMITTEE_HOT_KEY_HASH:
            voter->type = VOTER_COMMITTEE_HOT_KEY_HASH;
            STATIC_ASSERT(SIZEOF(voter->keyHash) == SIZEOF(extVoter->keyHash),
                          "bad script hash container size");
            memmove(voter->keyHash, extVoter->keyHash, SIZEOF(extVoter->keyHash));
            break;

        case EXT_VOTER_DREP_KEY_HASH:
            voter->type = VOTER_DREP_KEY_HASH;
            STATIC_ASSERT(SIZEOF(voter->keyHash) == SIZEOF(extVoter->keyHash),
                          "bad script hash container size");
            memmove(voter->keyHash, extVoter->keyHash, SIZEOF(extVoter->keyHash));
            break;

        case EXT_VOTER_STAKE_POOL_KEY_HASH:
            voter->type = VOTER_STAKE_POOL_KEY_HASH;
            STATIC_ASSERT(SIZEOF(voter->keyHash) == SIZEOF(extVoter->keyHash),
                          "bad script hash container size");
            memmove(voter->keyHash, extVoter->keyHash, SIZEOF(extVoter->keyHash));
            break;

        case EXT_VOTER_COMMITTEE_HOT_SCRIPT_HASH:
            voter->type = VOTER_COMMITTEE_HOT_SCRIPT_HASH;
            STATIC_ASSERT(SIZEOF(voter->scriptHash) == SIZEOF(extVoter->scriptHash),
                          "bad script hash container size");
            memmove(voter->scriptHash, extVoter->scriptHash, SIZEOF(extVoter->scriptHash));
            break;

        case EXT_VOTER_DREP_SCRIPT_HASH:
            voter->type = VOTER_DREP_SCRIPT_HASH;
            STATIC_ASSERT(SIZEOF(voter->scriptHash) == SIZEOF(extVoter->scriptHash),
                          "bad script hash container size");
            memmove(voter->scriptHash, extVoter->scriptHash, SIZEOF(extVoter->scriptHash));
            break;

        default:
            ASSERT(false);
            break;
    }
}

__noinline_due_to_stack__ static void
signTx_handleVotingProcedureAPDU(uint8_t p2, const uint8_t* wireDataBuffer, size_t wireDataSize) {
    TRACE_STACK_USAGE();
    {
        // sanity checks
        CHECK_STAGE(SIGN_STAGE_BODY_VOTING_PROCEDURES);
        ASSERT(BODY_CTX->currentVotingProcedure < ctx->numVotingProcedures);

        VALIDATE(p2 == P2_UNUSED, ERR_INVALID_REQUEST_PARAMETERS);
    }

    {
        TRACE_BUFFER(wireDataBuffer, wireDataSize);

        read_view_t view = make_read_view(wireDataBuffer, wireDataBuffer + wireDataSize);
        {
            // voter
            ext_voter_t* voter = &BODY_CTX->stageData.votingProcedure.voter;
            voter->type = parse_u1be(&view);
            switch (voter->type) {
                case EXT_VOTER_COMMITTEE_HOT_KEY_PATH:
                case EXT_VOTER_DREP_KEY_PATH:
                case EXT_VOTER_STAKE_POOL_KEY_PATH: {
                    _parsePathSpec(&view, &voter->keyPath);
                    break;
                }
                case EXT_VOTER_COMMITTEE_HOT_KEY_HASH:
                case EXT_VOTER_DREP_KEY_HASH:
                case EXT_VOTER_STAKE_POOL_KEY_HASH: {
                    STATIC_ASSERT(SIZEOF(voter->keyHash) == ADDRESS_KEY_HASH_LENGTH,
                                  "bad key hash container size");
                    view_parseBuffer(voter->keyHash, &view, SIZEOF(voter->keyHash));
                    break;
                }
                case EXT_VOTER_COMMITTEE_HOT_SCRIPT_HASH:
                case EXT_VOTER_DREP_SCRIPT_HASH: {
                    STATIC_ASSERT(SIZEOF(voter->scriptHash) == SCRIPT_HASH_LENGTH,
                                  "bad script hash container size");
                    view_parseBuffer(voter->scriptHash, &view, SIZEOF(voter->scriptHash));
                    break;
                }
                default:
                    THROW(ERR_INVALID_DATA);
            }
        }
        {
            // gov action id
            gov_action_id_t* actionId = &BODY_CTX->stageData.votingProcedure.govActionId;
            view_parseBuffer(actionId->txHashBuffer, &view, TX_HASH_LENGTH);
            actionId->govActionIndex = parse_u4be(&view);
        }
        {
            // voting procedure
            voting_procedure_t* procedure = &BODY_CTX->stageData.votingProcedure.votingProcedure;
            procedure->vote = parse_u1be(&view);
            switch (procedure->vote) {
                case VOTE_NO:
                case VOTE_YES:
                case VOTE_ABSTAIN:
                    // OK
                    break;
                default:
                    THROW(ERR_INVALID_DATA);
            }
            _parseAnchor(&view, &procedure->anchor);
        }
        VALIDATE(view_remainingSize(&view) == 0, ERR_INVALID_DATA);
    }

    security_policy_t policy = POLICY_DENY;
#ifdef HAVE_SWAP
    if (G_called_from_swap) {
        policy = POLICY_ALLOW_WITHOUT_PROMPT;
    } else
#endif
    {
        policy = policyForSignTxVotingProcedure(ctx->commonTxData.txSigningMode,
                                                &BODY_CTX->stageData.votingProcedure.voter);
        TRACE("Policy: %d", (int) policy);
        ENSURE_NOT_DENIED(policy);
    }

    // Note: if more than one voter is ever allowed, we need to check canonical ordering
    // of voters and possibly canonical ordering of governance actions in the subordinated map
    {
        // add to tx
        TRACE("Adding voting procedure to tx hash");
        voter_t voter;
        _setVoter(&voter, &BODY_CTX->stageData.votingProcedure.voter);
        txHashBuilder_addVotingProcedure(&BODY_CTX->txHashBuilder,
                                         &voter,
                                         &BODY_CTX->stageData.votingProcedure.govActionId,
                                         &BODY_CTX->stageData.votingProcedure.votingProcedure);
    }

    {
        // select UI steps
        switch (policy) {
#define CASE(POLICY, UI_STEP)   \
    case POLICY: {              \
        ctx->ui_step = UI_STEP; \
        break;                  \
    }
            CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_VOTING_PROCEDURE_STEP_INTRO);
            CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_VOTING_PROCEDURE_STEP_RESPOND);
#undef CASE
            default:
                THROW(ERR_NOT_IMPLEMENTED);
        }
    }
    signTx_handleVotingProcedure_ui_runStep();
}

// ============================== TREASURY ==============================

__noinline_due_to_stack__ static void signTx_handleTreasuryAPDU(uint8_t p2,
                                                                const uint8_t* wireDataBuffer,
                                                                size_t wireDataSize) {
    {
        // sanity checks
        CHECK_STAGE(SIGN_STAGE_BODY_TREASURY);
        ASSERT(ctx->includeTreasury == true);

        VALIDATE(p2 == P2_UNUSED, ERR_INVALID_REQUEST_PARAMETERS);
    }
    {
        // parse data
        TRACE_BUFFER(wireDataBuffer, wireDataSize);

        VALIDATE(wireDataSize == 8, ERR_INVALID_DATA);
        BODY_CTX->stageData.treasury = u8be_read(wireDataBuffer);
        BODY_CTX->treasuryReceived = true;
    }

    security_policy_t policy = POLICY_DENY;
#ifdef HAVE_SWAP
    if (G_called_from_swap) {
        policy = POLICY_ALLOW_WITHOUT_PROMPT;
    } else
#endif
    {
        policy =
            policyForSignTxTreasury(ctx->commonTxData.txSigningMode, BODY_CTX->stageData.treasury);
        TRACE("Policy: %d", (int) policy);
        ENSURE_NOT_DENIED(policy);
    }

    {
        // add to tx
        TRACE("Adding treasury to tx hash");
        txHashBuilder_addTreasury(&BODY_CTX->txHashBuilder, BODY_CTX->stageData.treasury);
    }

    {
        // select UI steps
        switch (policy) {
#define CASE(POLICY, UI_STEP)   \
    case POLICY: {              \
        ctx->ui_step = UI_STEP; \
        break;                  \
    }
            CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_TREASURY_STEP_DISPLAY);
            CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_TREASURY_STEP_RESPOND);
#undef CASE
            default:
                THROW(ERR_NOT_IMPLEMENTED);
        }
    }

    signTx_handleTreasury_ui_runStep();
}

// ============================== DONATION ==============================

__noinline_due_to_stack__ static void signTx_handleDonationAPDU(uint8_t p2,
                                                                const uint8_t* wireDataBuffer,
                                                                size_t wireDataSize) {
    {
        // sanity checks
        CHECK_STAGE(SIGN_STAGE_BODY_DONATION);
        ASSERT(ctx->includeDonation == true);

        VALIDATE(p2 == P2_UNUSED, ERR_INVALID_REQUEST_PARAMETERS);
    }
    {
        // parse data
        TRACE_BUFFER(wireDataBuffer, wireDataSize);

        VALIDATE(wireDataSize == 8, ERR_INVALID_DATA);
        BODY_CTX->stageData.donation = u8be_read(wireDataBuffer);
        VALIDATE(BODY_CTX->stageData.donation > 0, ERR_INVALID_DATA);
        BODY_CTX->donationReceived = true;
    }

    security_policy_t policy = POLICY_DENY;
#ifdef HAVE_SWAP
    if (G_called_from_swap) {
        policy = POLICY_ALLOW_WITHOUT_PROMPT;
    } else
#endif
    {
        policy =
            policyForSignTxDonation(ctx->commonTxData.txSigningMode, BODY_CTX->stageData.donation);
        TRACE("Policy: %d", (int) policy);
        ENSURE_NOT_DENIED(policy);
    }

    {
        // add to tx
        TRACE("Adding donation to tx hash");
        txHashBuilder_addDonation(&BODY_CTX->txHashBuilder, BODY_CTX->stageData.donation);
    }

    {
        // select UI steps
        switch (policy) {
#define CASE(POLICY, UI_STEP)   \
    case POLICY: {              \
        ctx->ui_step = UI_STEP; \
        break;                  \
    }
            CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_DONATION_STEP_DISPLAY);
            CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_DONATION_STEP_RESPOND);
#undef CASE
            default:
                THROW(ERR_NOT_IMPLEMENTED);
        }
    }

    signTx_handleDonation_ui_runStep();
}

// ============================== CONFIRM ==============================

static bool _shouldDisplayTxId(sign_tx_signingmode_t signingMode) {
    switch (signingMode) {
        case SIGN_TX_SIGNINGMODE_ORDINARY_TX:
        case SIGN_TX_SIGNINGMODE_MULTISIG_TX:
            if (ctx->shouldDisplayTxid && app_mode_expert()) return true;
            return false;

        case SIGN_TX_SIGNINGMODE_PLUTUS_TX:
            return true;

        default:
            return false;
    }
}

__noinline_due_to_stack__ static void signTx_handleConfirmAPDU(uint8_t p2,
                                                               const uint8_t* wireDataBuffer
                                                                   MARK_UNUSED,
                                                               size_t wireDataSize) {
    TRACE_STACK_USAGE();
    {
        // sanity checks
        CHECK_STAGE(SIGN_STAGE_CONFIRM);

        VALIDATE(p2 == P2_UNUSED, ERR_INVALID_REQUEST_PARAMETERS);
    }

    {
        // no data to receive
        VALIDATE(wireDataSize == 0, ERR_INVALID_DATA);
    }

    security_policy_t policy = POLICY_DENY;
#ifdef HAVE_SWAP
    if (G_called_from_swap) {
        policy = POLICY_ALLOW_WITHOUT_PROMPT;
    } else
#endif
    {
        policy = policyForSignTxConfirm();
        TRACE("Policy: %d", (int) policy);
        ENSURE_NOT_DENIED(policy);
    }
    {
        // compute txHash
        TRACE("Finalizing tx hash");
        txHashBuilder_finalize(&BODY_CTX->txHashBuilder, ctx->txHash, SIZEOF(ctx->txHash));
    }

    {
        // select UI step
        const int firstStep = (_shouldDisplayTxId(ctx->commonTxData.txSigningMode))
                                  ? HANDLE_CONFIRM_STEP_TXID
                                  : HANDLE_CONFIRM_STEP_FINAL_CONFIRM;
        switch (policy) {
#define CASE(POLICY, UI_STEP)   \
    case POLICY: {              \
        ctx->ui_step = UI_STEP; \
        break;                  \
    }
            CASE(POLICY_PROMPT_BEFORE_RESPONSE, firstStep);
            CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_CONFIRM_STEP_RESPOND);
#undef CASE
            default:
                THROW(ERR_NOT_IMPLEMENTED);
        }
    }

    signTx_handleConfirm_ui_runStep();
}

// ============================== WITNESS ==============================

__noinline_due_to_stack__ static void signTx_handleWitnessAPDU(uint8_t p2,
                                                               const uint8_t* wireDataBuffer,
                                                               size_t wireDataSize) {
    TRACE_STACK_USAGE();
    {
        // sanity checks
        CHECK_STAGE(SIGN_STAGE_WITNESSES);
        TRACE("Witness no. %d out of %d", WITNESS_CTX->currentWitness + 1, ctx->numWitnesses);
        ASSERT(WITNESS_CTX->currentWitness < ctx->numWitnesses);

        VALIDATE(p2 == P2_UNUSED, ERR_INVALID_REQUEST_PARAMETERS);
    }

    explicit_bzero(&WITNESS_CTX->stageData.witness, SIZEOF(WITNESS_CTX->stageData.witness));

    {
        // parse
        TRACE_BUFFER(wireDataBuffer, wireDataSize);

        size_t parsedSize =
            bip44_parseFromWire(&WITNESS_CTX->stageData.witness.path, wireDataBuffer, wireDataSize);
        VALIDATE(parsedSize == wireDataSize, ERR_INVALID_DATA);

        TRACE();
        BIP44_PRINTF(&WITNESS_CTX->stageData.witness.path);
        PRINTF("\n");
    }

    security_policy_t policy = POLICY_DENY;
#ifdef HAVE_SWAP
    if (G_called_from_swap) {
        policy = POLICY_ALLOW_WITHOUT_PROMPT;
    } else
#endif
    {
        policy = policyForSignTxWitness(ctx->commonTxData.txSigningMode,
                                        &WITNESS_CTX->stageData.witness.path,
                                        ctx->includeMint,
                                        ctx->poolOwnerByPath ? &ctx->poolOwnerPath : NULL);
        TRACE("Policy: %d", (int) policy);
        ENSURE_NOT_DENIED(policy);
    }
    {
        // compute witness
        TRACE("getWitness");
        TRACE("TX HASH");
        TRACE_BUFFER(ctx->txHash, SIZEOF(ctx->txHash));
        TRACE("END TX HASH");

        getWitness(&WITNESS_CTX->stageData.witness.path,
                   ctx->txHash,
                   SIZEOF(ctx->txHash),
                   WITNESS_CTX->stageData.witness.signature,
                   SIZEOF(WITNESS_CTX->stageData.witness.signature));
    }

    {
        // choose UI steps
        switch (policy) {
#define CASE(POLICY, UI_STEP)   \
    case POLICY: {              \
        ctx->ui_step = UI_STEP; \
        break;                  \
    }
            CASE(POLICY_PROMPT_WARN_UNUSUAL, HANDLE_WITNESS_STEP_WARNING);
            CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_WITNESS_STEP_DISPLAY);
            CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_WITNESS_STEP_RESPOND);
#undef CASE
            default:
                THROW(ERR_NOT_IMPLEMENTED);
        }
    }
    signTx_handleWitness_ui_runStep();
#ifdef HAVE_SWAP
    if (G_called_from_swap) {
        if (ctx->stage == SIGN_STAGE_NONE) {
            // Consider step is completed
            swap_finalize_exchange_sign_transaction(true);
        }
    }
#endif
}

// ============================== MAIN HANDLER ==============================

typedef void subhandler_fn_t(uint8_t p2, const uint8_t* dataBuffer, size_t dataSize);

static subhandler_fn_t* lookup_subhandler(uint8_t p1) {
    switch (p1) {
#define CASE(P1, HANDLER) \
    case P1:              \
        return HANDLER;
#define DEFAULT(HANDLER) \
    default:             \
        return HANDLER;
        CASE(0x01, signTx_handleInitAPDU);
        /*
         * Auxiliary data have to be handled before tx body because of memory consumption:
         * in certain cases we need compute a rolling hash,
         * and that cannot be done while the computation of tx body hash is in progress
         * without prohibitively bloating the instruction state.
         */
        CASE(0x08, signTx_handleAuxDataAPDU);
        CASE(0x02, signTx_handleInputAPDU);
        CASE(0x03, signTx_handleOutputAPDU);
        CASE(0x04, signTx_handleFeeAPDU);
        CASE(0x05, signTx_handleTtlAPDU);
        CASE(0x06, signTx_handleCertificateAPDU);
        CASE(0x07, signTx_handleWithdrawalAPDU);
        CASE(0x09, signTx_handleValidityIntervalStartAPDU);
        CASE(0x0b, signTx_handleMintAPDU);
        CASE(0x0c, signTx_handleScriptDataHashAPDU);
        CASE(0x0d, signTx_handleCollateralInputAPDU);
        CASE(0x0e, signTx_handleRequiredSignerAPDU);
        CASE(0x12, signTx_handleCollateralOutputAPDU);
        CASE(0x10, signTx_handleTotalCollateralAPDU);
        CASE(0x11, signTx_handleReferenceInputAPDU);
        CASE(0x13, signTx_handleVotingProcedureAPDU);
        CASE(0x15, signTx_handleTreasuryAPDU);
        CASE(0x16, signTx_handleDonationAPDU);
        CASE(0x0a, signTx_handleConfirmAPDU);
        CASE(0x0f, signTx_handleWitnessAPDU);
        DEFAULT(NULL)
#undef CASE
#undef DEFAULT
    }
}

uint16_t signTx_handleAPDU(uint8_t p1,
                           uint8_t p2,
                           const uint8_t* wireDataBuffer,
                           size_t wireDataSize,
                           bool isNewCall) {
    TRACE("P1 = 0x%x, P2 = 0x%x, isNewCall = %d", p1, p2, isNewCall);
    ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);

    if (isNewCall) {
        explicit_bzero(ctx, SIZEOF(*ctx));
        ctx->stage = SIGN_STAGE_INIT;
    }

    // advance stage if a state sub-machine has finished
    checkForFinishedSubmachines();

    switch (ctx->stage) {
        case SIGN_STAGE_BODY_INPUTS:
        case SIGN_STAGE_BODY_OUTPUTS:
        case SIGN_STAGE_BODY_OUTPUTS_SUBMACHINE:
        case SIGN_STAGE_BODY_FEE:
        case SIGN_STAGE_BODY_TTL:
        case SIGN_STAGE_BODY_CERTIFICATES:
#ifdef APP_FEATURE_POOL_REGISTRATION
        case SIGN_STAGE_BODY_CERTIFICATES_POOL_SUBMACHINE:
#endif  // APP_FEATURE_POOL_REGISTRATION
        case SIGN_STAGE_BODY_VALIDITY_INTERVAL:
        case SIGN_STAGE_BODY_MINT:
        case SIGN_STAGE_BODY_MINT_SUBMACHINE:
        case SIGN_STAGE_BODY_SCRIPT_DATA_HASH:
        case SIGN_STAGE_BODY_COLLATERAL_INPUTS:
        case SIGN_STAGE_BODY_REQUIRED_SIGNERS:
        case SIGN_STAGE_BODY_COLLATERAL_OUTPUT:
        case SIGN_STAGE_BODY_COLLATERAL_OUTPUT_SUBMACHINE:
        case SIGN_STAGE_BODY_TOTAL_COLLATERAL:
        case SIGN_STAGE_BODY_REFERENCE_INPUTS: {
            explicit_bzero(&BODY_CTX->stageData, SIZEOF(BODY_CTX->stageData));
            break;
        }

        case SIGN_STAGE_BODY_WITHDRAWALS:
            // we need to keep previous data for checking canonical ordering
            break;

        default:
            break;
    }

    subhandler_fn_t* subhandler = lookup_subhandler(p1);
    VALIDATE(subhandler != NULL, ERR_INVALID_REQUEST_PARAMETERS);
    subhandler(p2, wireDataBuffer, wireDataSize);
    return ERR_NO_RESPONSE;
}

ins_sign_tx_aux_data_context_t* accessAuxDataContext() {
    switch (ctx->stage) {
        case SIGN_STAGE_AUX_DATA:
        case SIGN_STAGE_AUX_DATA_CVOTE_REGISTRATION_SUBMACHINE:
            return &(ctx->txPartCtx.aux_data_ctx);

        default:
            PRINTF("accessAuxDataContext() bug\n");
            ASSERT(false);
            THROW(ERR_ASSERT);
    }
}

ins_sign_tx_body_context_t* accessBodyContext() {
    switch (ctx->stage) {
        case SIGN_STAGE_BODY_INPUTS:
        case SIGN_STAGE_BODY_OUTPUTS:
        case SIGN_STAGE_BODY_OUTPUTS_SUBMACHINE:
        case SIGN_STAGE_BODY_FEE:
        case SIGN_STAGE_BODY_TTL:
        case SIGN_STAGE_BODY_CERTIFICATES:
#ifdef APP_FEATURE_POOL_REGISTRATION
        case SIGN_STAGE_BODY_CERTIFICATES_POOL_SUBMACHINE:
#endif  // APP_FEATURE_POOL_REGISTRATION
        case SIGN_STAGE_BODY_WITHDRAWALS:
        case SIGN_STAGE_BODY_VALIDITY_INTERVAL:
        case SIGN_STAGE_BODY_MINT:
        case SIGN_STAGE_BODY_MINT_SUBMACHINE:
        case SIGN_STAGE_BODY_SCRIPT_DATA_HASH:
        case SIGN_STAGE_BODY_COLLATERAL_INPUTS:
        case SIGN_STAGE_BODY_REQUIRED_SIGNERS:
        case SIGN_STAGE_BODY_COLLATERAL_OUTPUT:
        case SIGN_STAGE_BODY_COLLATERAL_OUTPUT_SUBMACHINE:
        case SIGN_STAGE_BODY_TOTAL_COLLATERAL:
        case SIGN_STAGE_BODY_REFERENCE_INPUTS:
        case SIGN_STAGE_BODY_VOTING_PROCEDURES:
        case SIGN_STAGE_BODY_TREASURY:
        case SIGN_STAGE_BODY_DONATION:
        case SIGN_STAGE_CONFIRM:
            return &(ctx->txPartCtx.body_ctx);

        default:
            PRINTF("accessBodyContext() bug\n");
            ASSERT(false);
            THROW(ERR_ASSERT);
    }
}

ins_sign_tx_witness_context_t* accessWitnessContext() {
    switch (ctx->stage) {
        case SIGN_STAGE_WITNESSES:
            return &(ctx->txPartCtx.witnesses_ctx);

        default:
            PRINTF("accessWitnessContext() bug\n");
            ASSERT(false);
            THROW(ERR_ASSERT);
    }
}
