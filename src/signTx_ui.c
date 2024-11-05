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

#ifdef HAVE_BAGL
#include "uiScreens_bagl.h"
#elif defined(HAVE_NBGL)
#include "uiScreens_nbgl.h"
#include "nbgl_use_case.h"
#endif

static ins_sign_tx_context_t* ctx = &(instructionState.signTxContext);

// ============================== INIT ==============================

static const char* _newTxLine1(sign_tx_signingmode_t txSigningMode) {
    switch (txSigningMode) {
        case SIGN_TX_SIGNINGMODE_ORDINARY_TX:
#ifdef HAVE_BAGL
            return "New ordinary";
#elif defined(HAVE_NBGL)
            return "Review transaction";
#endif  // HAVE_BAGL

        case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OWNER:
#ifdef HAVE_BAGL
            return "New pool owner";
#elif defined(HAVE_NBGL)
            return "Review pool owner\ntransaction";
#endif  // HAVE_BAGL

        case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OPERATOR:
#ifdef HAVE_BAGL
            return "New pool operator";
#elif defined(HAVE_NBGL)
            return "Review pool operator\ntransaction";
#endif  // HAVE_BAGL

        case SIGN_TX_SIGNINGMODE_MULTISIG_TX:
#ifdef HAVE_BAGL
            return "New multisig";
#elif defined(HAVE_NBGL)
            return "Review multisig\ntransaction";
#endif  // HAVE_BAGL

        case SIGN_TX_SIGNINGMODE_PLUTUS_TX:
#ifdef HAVE_BAGL
            return "New Plutus";
#elif defined(HAVE_NBGL)
            return "Review Plutus\ntransaction";
#endif  // HAVE_BAGL

        default:
            ASSERT(false);
    }
}

#ifdef HAVE_NBGL
static void signTx_handleInit_ui_runStep_cb(void) {
// if the protocol magic check is not enabled,
// displaying the protocol magic might be misleading,
// so we must not show it
#ifdef APP_FEATURE_BYRON_PROTOCOL_MAGIC_CHECK
    char networkParams[100] = {0};
    ui_getNetworkParamsScreen_2(networkParams,
                                SIZEOF(networkParams),
                                ctx->commonTxData.protocolMagic);
    fill_and_display_if_required("Protocol magic",
                                 networkParams,
                                 signTx_handleInit_ui_runStep,
                                 respond_with_user_reject);
#endif
}
#endif  // HAVE_NBGL

void signTx_handleInit_ui_runStep() {
    TRACE("UI step %d", ctx->ui_step);
    TRACE_STACK_USAGE();
    ui_callback_fn_t* this_fn = signTx_handleInit_ui_runStep;

    UI_STEP_BEGIN(ctx->ui_step, this_fn);

    UI_STEP(HANDLE_INIT_STEP_PROMPT_SIGNINGMODE) {
#ifdef HAVE_BAGL
        ui_displayPrompt(_newTxLine1(ctx->commonTxData.txSigningMode),
                         "transaction?",
                         this_fn,
                         respond_with_user_reject);
#elif defined(HAVE_NBGL)
        display_prompt(_newTxLine1(ctx->commonTxData.txSigningMode),
                       "",
                       this_fn,
                       respond_with_user_reject);
#endif  // HAVE_BAGL
    }

    UI_STEP(HANDLE_INIT_STEP_DISPLAY_NETWORK_DETAILS) {
        const bool isNetworkIdVerifiable = isTxNetworkIdVerifiable(ctx->includeNetworkId,
                                                                   ctx->numOutputs,
                                                                   ctx->numWithdrawals,
                                                                   ctx->commonTxData.txSigningMode);
        if (isNetworkIdVerifiable) {
            if (isNetworkUsual(ctx->commonTxData.networkId, ctx->commonTxData.protocolMagic)) {
                // no need to display the network details
                UI_STEP_JUMP(HANDLE_INIT_STEP_SCRIPT_RUNNING_WARNING);
            }
#ifdef HAVE_BAGL
            ui_displayNetworkParamsScreen("Network details",
                                          ctx->commonTxData.networkId,
                                          ctx->commonTxData.protocolMagic,
                                          this_fn);
#elif defined(HAVE_NBGL)
            char networkParams[100] = {0};
            ui_getNetworkParamsScreen_1(networkParams,
                                        SIZEOF(networkParams),
                                        ctx->commonTxData.networkId);
            fill_and_display_if_required("Network ID",
                                         networkParams,
                                         signTx_handleInit_ui_runStep_cb,
                                         respond_with_user_reject);
#endif  // HAVE_BAGL
        } else {
// technically, no pool reg. certificate as well, but the UI message would be too long
#ifdef HAVE_BAGL
            ui_displayPaginatedText("Warning:",
                                    "cannot verify network id: no outputs or withdrawals",
                                    this_fn);
#elif defined(HAVE_NBGL)
            display_warning("Cannot verify network id:\nno outputs, or withdrawals",
                            this_fn,
                            respond_with_user_reject);
#endif  // HAVE_BAGL
        }
    }

    UI_STEP(HANDLE_INIT_STEP_SCRIPT_RUNNING_WARNING) {
        if (!needsRunningScriptWarning(ctx->numCollateralInputs)) {
            UI_STEP_JUMP(HANDLE_INIT_STEP_NO_COLLATERAL_WARNING);
        }
#ifdef HAVE_BAGL
        ui_displayPaginatedText("WARNING:", "Plutus script will be evaluated", this_fn);
#elif defined(HAVE_NBGL)
        display_warning("Plutus script will be evaluated", this_fn, respond_with_user_reject);
#endif  // HAVE_BAGL
    }

    UI_STEP(HANDLE_INIT_STEP_NO_COLLATERAL_WARNING) {
        if (!needsMissingCollateralWarning(ctx->commonTxData.txSigningMode,
                                           ctx->numCollateralInputs)) {
            UI_STEP_JUMP(HANDLE_INIT_STEP_NO_SCRIPT_DATA_HASH_WARNING);
        }
#ifdef HAVE_BAGL
        ui_displayPaginatedText("WARNING:", "No collateral given for Plutus transaction", this_fn);
#elif defined(HAVE_NBGL)
        display_warning("No collateral given for\nPlutus transaction",
                        this_fn,
                        respond_with_user_reject);
#endif  // HAVE_BAGL
    }

    UI_STEP(HANDLE_INIT_STEP_UNKNOWN_COLLATERAL_WARNING) {
        if (!needsUnknownCollateralWarning(ctx->commonTxData.txSigningMode,
                                           ctx->includeTotalCollateral)) {
            UI_STEP_JUMP(HANDLE_INIT_STEP_NO_SCRIPT_DATA_HASH_WARNING);
        }
#ifdef HAVE_BAGL
        ui_displayPaginatedText("WARNING:", "Unknown collateral amount", this_fn);
#elif defined(HAVE_NBGL)
        display_warning("Unknown collateral amount", this_fn, respond_with_user_reject);
#endif  // HAVE_BAGL
    }

    UI_STEP(HANDLE_INIT_STEP_NO_SCRIPT_DATA_HASH_WARNING) {
        if (!needsMissingScriptDataHashWarning(ctx->commonTxData.txSigningMode,
                                               ctx->includeScriptDataHash)) {
            UI_STEP_JUMP(HANDLE_INIT_STEP_RESPOND);
        }
#ifdef HAVE_BAGL
        ui_displayPaginatedText("WARNING:", "No script data given for Plutus transaction", this_fn);
#elif defined(HAVE_NBGL)
        display_warning("No script data given for\nPlutus transaction",
                        this_fn,
                        respond_with_user_reject);
#endif  // HAVE_BAGL
    }

    UI_STEP(HANDLE_INIT_STEP_RESPOND) {
        respondSuccessEmptyMsg();
        tx_advanceStage();
    }
    UI_STEP_END(HANDLE_INIT_STEP_INVALID);
}

// ============================== AUXILIARY DATA ==============================

void signTx_handleAuxDataArbitraryHash_ui_runStep() {
    TRACE("UI step %d", ctx->ui_step);
    TRACE_STACK_USAGE();
    ui_callback_fn_t* this_fn = signTx_handleAuxDataArbitraryHash_ui_runStep;

    UI_STEP_BEGIN(ctx->ui_step, this_fn);

    UI_STEP(HANDLE_AUX_DATA_ARBITRARY_HASH_STEP_DISPLAY) {
#ifdef HAVE_BAGL
        ui_displayHexBufferScreen("Auxiliary data hash",
                                  ctx->auxDataHash,
                                  SIZEOF(ctx->auxDataHash),
                                  this_fn);
#elif defined(HAVE_NBGL)
        char bufferHex[2 * AUX_DATA_HASH_LENGTH + 1] = {0};
        ui_getHexBufferScreen(bufferHex,
                              SIZEOF(bufferHex),
                              ctx->auxDataHash,
                              SIZEOF(ctx->auxDataHash));
        fill_and_display_if_required("Auxiliary data hash",
                                     bufferHex,
                                     this_fn,
                                     respond_with_user_reject);
#endif  // HAVE_BAGL
    }
    UI_STEP(HANDLE_AUX_DATA_ARBITRARY_HASH_STEP_RESPOND) {
        respondSuccessEmptyMsg();
        tx_advanceStage();
    }
    UI_STEP_END(HANDLE_AUX_DATA_ARBITRARY_HASH_STEP_INVALID);
}

void signTx_handleAuxDataCVoteRegistration_ui_runStep() {
    TRACE("UI step %d", ctx->ui_step);
    TRACE_STACK_USAGE();
    ui_callback_fn_t* this_fn = signTx_handleAuxDataCVoteRegistration_ui_runStep;

    UI_STEP_BEGIN(ctx->ui_step, this_fn);

    UI_STEP(HANDLE_AUX_DATA_CVOTE_REGISTRATION_STEP_DISPLAY) {
#ifdef HAVE_BAGL
        ui_displayPrompt("Register vote", "key (CIP-36)?", this_fn, respond_with_user_reject);
#elif defined(HAVE_NBGL)
        set_light_confirmation(true);
        display_prompt("Register vote\nkey (CIP-36)?", "", this_fn, respond_with_user_reject);
#endif  // HAVE_BAGL
    }
    UI_STEP(HANDLE_AUX_DATA_CVOTE_REGISTRATION_STEP_RESPOND) {
        respondSuccessEmptyMsg();
        signTxCVoteRegistration_init();
        ctx->stage = SIGN_STAGE_AUX_DATA_CVOTE_REGISTRATION_SUBMACHINE;
    }
    UI_STEP_END(HANDLE_AUX_DATA_CVOTE_REGISTRATION_STEP_INVALID);
}

// ============================== INPUTS ==============================

void signTx_handleInput_ui_runStep() {
    TRACE("UI step %d", ctx->ui_step);
    ui_callback_fn_t* this_fn = signTx_handleInput_ui_runStep;

    UI_STEP_BEGIN(ctx->ui_step, this_fn);

    UI_STEP(HANDLE_INPUT_STEP_DISPLAY) {
#ifdef HAVE_BAGL
        ui_displayInputScreen(&BODY_CTX->stageData.input, this_fn);
#elif defined(HAVE_NBGL)
        // index 32 bit (10) + separator (" / ") + utxo hash hex format + \0
        // + 1 byte to detect if everything has been written
        char inputStr[10 + 3 + TX_HASH_LENGTH * 2 + 1 + 1] = {0};

        ui_getInputScreen(inputStr, SIZEOF(inputStr), &BODY_CTX->stageData.input);
        fill_and_display_if_required(BODY_CTX->stageData.input.label,
                                     inputStr,
                                     this_fn,
                                     respond_with_user_reject);
#endif  // HAVE_BAGL
    }

    UI_STEP(HANDLE_INPUT_STEP_RESPOND) {
        respondSuccessEmptyMsg();

        ASSERT(ctx->ui_advanceState != NULL);
        ctx->ui_advanceState();
    }
    UI_STEP_END(HANDLE_INPUT_STEP_INVALID);
}

// ============================== FEE ==============================

#define MAX_FEES 5000000  // 5 ADA threshold

void signTx_handleFee_ui_runStep() {
    TRACE("UI step %d", ctx->ui_step);
    ui_callback_fn_t* this_fn = signTx_handleFee_ui_runStep;

    TRACE_ADA_AMOUNT("fee ", BODY_CTX->stageData.fee);

    UI_STEP_BEGIN(ctx->ui_step, this_fn);

    UI_STEP(HANDLE_FEE_STEP_DISPLAY) {
#ifdef HAVE_BAGL
        if (BODY_CTX->stageData.fee > (uint64_t) MAX_FEES) {
            ui_displayPaginatedText("Warning: Fees are", "above 5 ADA", fee_high_cb);
        } else {
            fee_high_cb();
        }
#elif defined(HAVE_NBGL)
        if (BODY_CTX->stageData.fee > (uint64_t) MAX_FEES) {
            display_warning_fee();
        } else {
            fee_high_cb(TOKEN_HIGH_FEES_NEXT, 0);
        }
#endif  // HAVE_BAGL
    }
    UI_STEP(HANDLE_FEE_STEP_RESPOND) {
        respondSuccessEmptyMsg();
        tx_advanceStage();
    }
    UI_STEP_END(HANDLE_FEE_STEP_INVALID);
}

// ============================== TTL ==============================

void signTx_handleTtl_ui_runStep() {
    TRACE("UI step %d", ctx->ui_step);
    ui_callback_fn_t* this_fn = signTx_handleTtl_ui_runStep;

    UI_STEP_BEGIN(ctx->ui_step, this_fn);

    UI_STEP(HANDLE_TTL_STEP_DISPLAY) {
#ifdef HAVE_BAGL
        ui_displayValidityBoundaryScreen("Transaction TTL",
                                         BODY_CTX->stageData.ttl,
                                         ctx->commonTxData.networkId,
                                         ctx->commonTxData.protocolMagic,
                                         this_fn);
#elif defined(HAVE_NBGL)
        char boundaryStr[30] = {0};
        ui_getValidityBoundaryScreen(boundaryStr,
                                     SIZEOF(boundaryStr),
                                     BODY_CTX->stageData.ttl,
                                     ctx->commonTxData.networkId,
                                     ctx->commonTxData.protocolMagic);
        fill_and_display_if_required("Transaction TTL",
                                     boundaryStr,
                                     this_fn,
                                     respond_with_user_reject);
#endif  // HAVE_BAGL
    }
    UI_STEP(HANDLE_TTL_STEP_RESPOND) {
        respondSuccessEmptyMsg();
        tx_advanceStage();
    }
    UI_STEP_END(HANDLE_TTL_STEP_INVALID);
}

// ============================== CERTIFICATES ==============================

#ifdef HAVE_NBGL
static void signTx_handleCertificate_ui_delegation_cb(void) {
    sign_tx_certificate_data_t* cert = &BODY_CTX->stageData.certificate;

    char encodedStr[BECH32_STRING_SIZE_MAX] = {0};
    ASSERT(cert->poolCredential.type == EXT_CREDENTIAL_KEY_HASH);
    ui_getBech32Screen(encodedStr,
                       SIZEOF(encodedStr),
                       "pool",
                       cert->poolCredential.keyHash,
                       SIZEOF(cert->poolCredential.keyHash));
    fill_and_display_if_required("Pool",
                                 encodedStr,
                                 signTx_handleCertificateStaking_ui_runStep,
                                 respond_with_user_reject);
}
#endif

static void _displayKeyPath(ui_callback_fn_t* callback, bip44_path_t* path, const char* label) {
#ifdef HAVE_BAGL
    ui_displayPathScreen(label, path, callback);
#elif defined(HAVE_NBGL)
    {
        char pathStr[BIP44_PATH_STRING_SIZE_MAX + 1] = {0};
        ui_getPathScreen(pathStr, SIZEOF(pathStr), path);
        fill_and_display_if_required(label, pathStr, callback, respond_with_user_reject);
    }
#endif  // HAVE_BAGL
}

static void _displayKeyHash(ui_callback_fn_t* callback,
                            uint8_t keyHash[static ADDRESS_KEY_HASH_LENGTH],
                            const char* label,
                            const char* bech32Prefix) {
#ifdef HAVE_BAGL
    ui_displayBech32Screen(label, bech32Prefix, keyHash, ADDRESS_KEY_HASH_LENGTH, callback);
#elif defined(HAVE_NBGL)
    {
        char encodedStr[BECH32_STRING_SIZE_MAX] = {0};
        ui_getBech32Screen(encodedStr,
                           SIZEOF(encodedStr),
                           bech32Prefix,
                           keyHash,
                           ADDRESS_KEY_HASH_LENGTH);
        fill_and_display_if_required(label, encodedStr, callback, respond_with_user_reject);
    }
#endif  // HAVE_BAGL
}

static void _displayScriptHash(ui_callback_fn_t* callback,
                               uint8_t scriptHash[static SCRIPT_HASH_LENGTH],
                               const char* label,
                               const char* bech32Prefix) {
#ifdef HAVE_BAGL
    ui_displayBech32Screen(label, bech32Prefix, scriptHash, SCRIPT_HASH_LENGTH, callback);
#elif defined(HAVE_NBGL)
    {
        char encodedStr[BECH32_STRING_SIZE_MAX] = {0};
        ui_getBech32Screen(encodedStr,
                           SIZEOF(encodedStr),
                           bech32Prefix,
                           scriptHash,
                           SCRIPT_HASH_LENGTH);
        fill_and_display_if_required(label, encodedStr, callback, respond_with_user_reject);
    }
#endif  // HAVE_BAGL
}

static void _displayCredential(ui_callback_fn_t* callback,
                               ext_credential_t* credential,
                               const char* keyPathLabel,
                               const char* keyHashLabel,
                               const char* keyHashPrefix,
                               const char* scriptHashLabel,
                               const char* scriptHashPrefix) {
    switch (credential->type) {
        case EXT_CREDENTIAL_KEY_PATH:
            _displayKeyPath(callback, &credential->keyPath, keyPathLabel);
            break;
        case EXT_CREDENTIAL_KEY_HASH:
            _displayKeyHash(callback, credential->keyHash, keyHashLabel, keyHashPrefix);
            break;
        case EXT_CREDENTIAL_SCRIPT_HASH:
            _displayScriptHash(callback, credential->scriptHash, scriptHashLabel, scriptHashPrefix);
            break;
        default:
            ASSERT(false);
            break;
    }
}

static void _displayDeposit(ui_callback_fn_t* callback, uint64_t deposit) {
#ifdef HAVE_BAGL
    ui_displayAdaAmountScreen("Deposit", deposit, callback);
#elif defined(HAVE_NBGL)
    char adaAmountStr[50] = {0};
    ui_getAdaAmountScreen(adaAmountStr, SIZEOF(adaAmountStr), deposit);
    fill_and_display_if_required("Deposit", adaAmountStr, callback, respond_with_user_reject);
#endif  // HAVE_BAGL
}

static void _displayAnchorNull(ui_callback_fn_t* callback) {
#ifdef HAVE_BAGL
    ui_displayPaginatedText("Anchor", "null", callback);
#elif defined(HAVE_NBGL)
    fill_and_display_if_required("Anchor", "null", callback, respond_with_user_reject);
#endif  // HAVE_BAGL
}

static void _displayAnchorUrl(ui_callback_fn_t* callback, anchor_t* anchor) {
    char urlStr[1 + ANCHOR_URL_LENGTH_MAX] = {0};
    explicit_bzero(urlStr, SIZEOF(urlStr));
    ASSERT(anchor->urlLength <= ANCHOR_URL_LENGTH_MAX);
    memmove(urlStr, anchor->url, anchor->urlLength);
    urlStr[anchor->urlLength] = '\0';
    ASSERT(strlen(urlStr) == anchor->urlLength);

#ifdef HAVE_BAGL
    ui_displayPaginatedText("Anchor url", urlStr, callback);
#elif defined(HAVE_NBGL)
    fill_and_display_if_required("Anchor url", urlStr, callback, respond_with_user_reject);
#endif  // HAVE_BAGL
}

static void _displayAnchorHash(ui_callback_fn_t* callback, anchor_t* anchor) {
    char hex[1 + 2 * ANCHOR_HASH_LENGTH] = {0};
    explicit_bzero(hex, SIZEOF(hex));
    size_t len = encode_hex(anchor->hash, SIZEOF(anchor->hash), hex, SIZEOF(hex));
    ASSERT(len + 1 == SIZEOF(hex));

#ifdef HAVE_BAGL
    ui_displayPaginatedText("Anchor data hash", hex, callback);
#elif defined(HAVE_NBGL)
    fill_and_display_if_required("Anchor data hash", hex, callback, respond_with_user_reject);
#endif  // HAVE_BAGL
}

void signTx_handleCertificateStaking_ui_runStep() {
    TRACE("UI step %d", ctx->ui_step);
    ui_callback_fn_t* this_fn = signTx_handleCertificateStaking_ui_runStep;
    sign_tx_certificate_data_t* cert = &BODY_CTX->stageData.certificate;

    UI_STEP_BEGIN(ctx->ui_step, this_fn);

    UI_STEP(HANDLE_CERTIFICATE_STAKING_STEP_DISPLAY_OPERATION) {
        switch (cert->type) {
            case CERTIFICATE_STAKE_REGISTRATION:
            case CERTIFICATE_STAKE_REGISTRATION_CONWAY:
#ifdef HAVE_BAGL
                ui_displayPaginatedText("Register", "stake key", this_fn);
#elif defined(HAVE_NBGL)
                set_light_confirmation(true);
                display_prompt("Register\nstake key", "", this_fn, respond_with_user_reject);
#endif  // HAVE_BAGL
                break;

            case CERTIFICATE_STAKE_DEREGISTRATION:
            case CERTIFICATE_STAKE_DEREGISTRATION_CONWAY:
#ifdef HAVE_BAGL
                ui_displayPaginatedText("Deregister", "stake key", this_fn);
#elif defined(HAVE_NBGL)
                set_light_confirmation(true);
                display_prompt("Deregister\nstake key", "", this_fn, respond_with_user_reject);
#endif  // HAVE_BAGL
                break;

            case CERTIFICATE_STAKE_DELEGATION:
#ifdef HAVE_BAGL
                ASSERT(cert->poolCredential.type == EXT_CREDENTIAL_KEY_HASH);
                ui_displayBech32Screen("Delegate stake",
                                       "pool",
                                       cert->poolCredential.keyHash,
                                       SIZEOF(cert->poolCredential.keyHash),
                                       this_fn);
#elif defined(HAVE_NBGL)
                set_light_confirmation(true);
                display_prompt("Delegate stake",
                               "",
                               signTx_handleCertificate_ui_delegation_cb,
                               respond_with_user_reject);
#endif  // HAVE_BAGL
                break;

            default:
                // includes CERTIFICATE_STAKE_POOL_REGISTRATION
                // and CERTIFICATE_STAKE_POOL_RETIREMENT
                // which have separate UI; this handler must not be used
                ASSERT(false);
        }
    }
    UI_STEP(HANDLE_CERTIFICATE_STAKING_STEP_DISPLAY_STAKE_CRED) {
        _displayCredential(this_fn,
                           &cert->stakeCredential,
                           "Stake key",
                           "Stake key hash",
                           "stake_vkh",
                           "Stake script hash",
                           "script");
    }
    UI_STEP(HANDLE_CERTIFICATE_STAKING_STEP_DISPLAY_DEPOSIT) {
        switch (cert->type) {
            case CERTIFICATE_STAKE_REGISTRATION:
            case CERTIFICATE_STAKE_DEREGISTRATION:
            case CERTIFICATE_STAKE_DELEGATION:
                // no deposit in these
                UI_STEP_JUMP(HANDLE_CERTIFICATE_STAKING_STEP_CONFIRM);
                break;

            case CERTIFICATE_STAKE_REGISTRATION_CONWAY:
            case CERTIFICATE_STAKE_DEREGISTRATION_CONWAY:
                _displayDeposit(this_fn, cert->deposit);
                break;

            default:
                ASSERT(false);
        }
    }
    UI_STEP(HANDLE_CERTIFICATE_STAKING_STEP_CONFIRM) {
        char description[50] = {0};
        explicit_bzero(description, SIZEOF(description));

        switch (cert->type) {
            case CERTIFICATE_STAKE_REGISTRATION:
            case CERTIFICATE_STAKE_REGISTRATION_CONWAY:
#ifdef HAVE_BAGL
                snprintf(description, SIZEOF(description), "registration?");
#elif defined(HAVE_NBGL)
                display_confirmation("Confirm\nregistration",
                                     "",
                                     "REGISTRATION\nACCEPTED",
                                     "Registration\nrejected",
                                     this_fn,
                                     respond_with_user_reject);
#endif  // HAVE_BAGL
                break;

            case CERTIFICATE_STAKE_DEREGISTRATION:
            case CERTIFICATE_STAKE_DEREGISTRATION_CONWAY:
#ifdef HAVE_BAGL
                snprintf(description, SIZEOF(description), "deregistration?");
#elif defined(HAVE_NBGL)
                display_confirmation("Confirm\nderegistration",
                                     "",
                                     "DEREGISTRATION\nACCEPTED",
                                     "Deregistration\nrejected",
                                     this_fn,
                                     respond_with_user_reject);
#endif  // HAVE_BAGL
                break;

            case CERTIFICATE_STAKE_DELEGATION:
#ifdef HAVE_BAGL
                snprintf(description, SIZEOF(description), "delegation?");
#elif defined(HAVE_NBGL)
                display_confirmation("Confirm\ndelegation",
                                     "",
                                     "DELEGATION\nACCEPTED",
                                     "Delegation\nrejected",
                                     this_fn,
                                     respond_with_user_reject);
#endif  // HAVE_BAGL
                break;

            default:
                ASSERT(false);
        }
        // make sure all the information is displayed to the user
        ASSERT(strlen(description) + 1 < SIZEOF(description));

#ifdef HAVE_BAGL
        ui_displayPrompt("Confirm", description, this_fn, respond_with_user_reject);
#elif defined(HAVE_NBGL)
#endif  // HAVE_BAGL
    }
    UI_STEP(HANDLE_CERTIFICATE_STAKING_STEP_RESPOND) {
        respondSuccessEmptyMsg();

        tx_advanceCertificatesStateIfAppropriate();
    }
    UI_STEP_END(HANDLE_CERTIFICATE_STAKING_STEP_INVALID);
}

void signTx_handleCertificateVoteDeleg_ui_runStep() {
    TRACE("UI step %d", ctx->ui_step);
    ui_callback_fn_t* this_fn = signTx_handleCertificateVoteDeleg_ui_runStep;
    sign_tx_certificate_data_t* cert = &BODY_CTX->stageData.certificate;

    UI_STEP_BEGIN(ctx->ui_step, this_fn);

    UI_STEP(HANDLE_CERTIFICATE_VOTE_DELEGATION_STEP_DISPLAY_OPERATION) {
#ifdef HAVE_BAGL
        ui_displayPaginatedText("Delegate", "vote", this_fn);
#elif defined(HAVE_NBGL)
        set_light_confirmation(true);
        display_prompt("Delegate\nvote", "", this_fn, respond_with_user_reject);
#endif  // HAVE_BAGL
    }
    UI_STEP(HANDLE_CERTIFICATE_VOTE_DELEGATION_STEP_DISPLAY_STAKE_CRED) {
        _displayCredential(this_fn,
                           &cert->stakeCredential,
                           "Stake key",
                           "Stake key hash",
                           "stake_vkh",
                           "Stake script hash",
                           "script");
    }
    UI_STEP(HANDLE_CERTIFICATE_VOTE_DELEGATION_STEP_DISPLAY_DREP) {
        switch (cert->drep.type) {
            case EXT_DREP_KEY_PATH:
                _displayKeyPath(this_fn, &cert->drep.keyPath, "DRep key");
                break;
            case EXT_DREP_KEY_HASH:
                _displayKeyHash(this_fn, cert->drep.keyHash, "DRep key hash", "drep");
                break;
            case EXT_DREP_SCRIPT_HASH:
                _displayScriptHash(this_fn,
                                   cert->drep.scriptHash,
                                   "DRep script hash",
                                   "drep_script");
                break;
            case DREP_ALWAYS_ABSTAIN:
#ifdef HAVE_BAGL
                ui_displayPaginatedText("Always", "abstain", this_fn);
#elif defined(HAVE_NBGL)
                set_light_confirmation(true);
                display_prompt("Always\nabstain", "", this_fn, respond_with_user_reject);
#endif  // HAVE_BAGL
                break;
            case DREP_ALWAYS_NO_CONFIDENCE:
#ifdef HAVE_BAGL
                ui_displayPaginatedText("Always", "no confidence", this_fn);
#elif defined(HAVE_NBGL)
                set_light_confirmation(true);
                display_prompt("Always\nno confidence", "", this_fn, respond_with_user_reject);
#endif  // HAVE_BAGL
                break;
            default:
                ASSERT(false);
                break;
        }
    }
    UI_STEP(HANDLE_CERTIFICATE_VOTE_DELEGATION_STEP_CONFIRM) {
#ifdef HAVE_BAGL
        ui_displayPrompt("Confirm vote", "delegation", this_fn, respond_with_user_reject);
#elif defined(HAVE_NBGL)
        display_confirmation("Confirm vote\ndelegation",
                             "",
                             "DELEGATION\nACCEPTED",
                             "Delegation\nrejected",
                             this_fn,
                             respond_with_user_reject);
#endif  // HAVE_BAGL
    }
    UI_STEP(HANDLE_CERTIFICATE_VOTE_DELEGATION_STEP_RESPOND) {
        respondSuccessEmptyMsg();

        tx_advanceCertificatesStateIfAppropriate();
    }
    UI_STEP_END(HANDLE_CERTIFICATE_VOTE_DELEGATION_STEP_INVALID);
}

void signTx_handleCertificateCommitteeAuth_ui_runStep() {
    TRACE("UI step %d", ctx->ui_step);
    ui_callback_fn_t* this_fn = signTx_handleCertificateCommitteeAuth_ui_runStep;
    sign_tx_certificate_data_t* cert = &BODY_CTX->stageData.certificate;

    UI_STEP_BEGIN(ctx->ui_step, this_fn);

    UI_STEP(HANDLE_CERTIFICATE_COMM_AUTH_STEP_DISPLAY_OPERATION) {
#ifdef HAVE_BAGL
        ui_displayPaginatedText("Authorize", "committee", this_fn);
#elif defined(HAVE_NBGL)
        set_light_confirmation(true);
        display_prompt("Authorize committee", "", this_fn, respond_with_user_reject);
#endif  // HAVE_BAGL
    }
    UI_STEP(HANDLE_CERTIFICATE_COMM_AUTH_STEP_DISPLAY_COLD_CRED) {
        _displayCredential(this_fn,
                           &cert->committeeColdCredential,
                           "Cmte. cold key",
                           "Cmte. cold key hash",
                           "cc_cold",
                           "Cmte. cold script",
                           "cc_cold_script");
    }
    UI_STEP(HANDLE_CERTIFICATE_COMM_AUTH_STEP_DISPLAY_HOT_CRED) {
        _displayCredential(this_fn,
                           &cert->committeeHotCredential,
                           "Cmte. hot key",
                           "Cmte. hot key hash",
                           "cc_hot",
                           "Cmte. hot script",
                           "cc_hot_script");
    }
    UI_STEP(HANDLE_CERTIFICATE_COMM_AUTH_STEP_CONFIRM) {
#ifdef HAVE_BAGL
        ui_displayPrompt("Confirm", "authorization?", this_fn, respond_with_user_reject);
#elif defined(HAVE_NBGL)
        display_confirmation("Confirm\nauthorization",
                             "",
                             "AUTHORIZATION\nACCEPTED",
                             "Authorization\nrejected",
                             this_fn,
                             respond_with_user_reject);
#endif  // HAVE_BAGL
    }
    UI_STEP(HANDLE_CERTIFICATE_COMM_AUTH_STEP_RESPOND) {
        respondSuccessEmptyMsg();

        tx_advanceCertificatesStateIfAppropriate();
    }
    UI_STEP_END(HANDLE_CERTIFICATE_COMM_AUTH_STEP_INVALID);
}

void signTx_handleCertificateCommitteeResign_ui_runStep() {
    TRACE("UI step %d", ctx->ui_step);
    ui_callback_fn_t* this_fn = signTx_handleCertificateCommitteeResign_ui_runStep;
    sign_tx_certificate_data_t* cert = &BODY_CTX->stageData.certificate;

    UI_STEP_BEGIN(ctx->ui_step, this_fn);

    UI_STEP(HANDLE_CERTIFICATE_COMM_RESIGN_STEP_DISPLAY_OPERATION) {
#ifdef HAVE_BAGL
        ui_displayPaginatedText("Resign from", "committee", this_fn);
#elif defined(HAVE_NBGL)
        set_light_confirmation(true);
        display_prompt("Resign from\ncommittee", "", this_fn, respond_with_user_reject);
#endif  // HAVE_BAGL
    }
    UI_STEP(HANDLE_CERTIFICATE_COMM_RESIGN_STEP_DISPLAY_COLD_CRED) {
        _displayCredential(this_fn,
                           &cert->committeeColdCredential,
                           "Cmte. cold key",
                           "Cmte. cold key hash",
                           "cc_cold",
                           "Cmte. cold script",
                           "cc_cold");
    }
    UI_STEP(HANDLE_CERTIFICATE_COMM_RESIGN_STEP_DISPLAY_ANCHOR_NULL) {
        if (cert->anchor.isIncluded) {
            UI_STEP_JUMP(HANDLE_CERTIFICATE_COMM_RESIGN_STEP_DISPLAY_ANCHOR_URL);
        }
        _displayAnchorNull(this_fn);
    }
    UI_STEP(HANDLE_CERTIFICATE_COMM_RESIGN_STEP_DISPLAY_ANCHOR_URL) {
        if (!cert->anchor.isIncluded) {
            UI_STEP_JUMP(HANDLE_CERTIFICATE_COMM_RESIGN_STEP_CONFIRM);
        }
        _displayAnchorUrl(this_fn, &cert->anchor);
    }
    UI_STEP(HANDLE_CERTIFICATE_COMM_RESIGN_STEP_DISPLAY_ANCHOR_HASH) {
        _displayAnchorHash(this_fn, &cert->anchor);
    }
    UI_STEP(HANDLE_CERTIFICATE_COMM_RESIGN_STEP_CONFIRM) {
#ifdef HAVE_BAGL
        ui_displayPrompt("Confirm", "resignation", this_fn, respond_with_user_reject);
#elif defined(HAVE_NBGL)
        display_confirmation("Confirm\nresignation",
                             "",
                             "RESIGNATION\nACCEPTED",
                             "Resignation\nrejected",
                             this_fn,
                             respond_with_user_reject);
#endif  // HAVE_BAGL
    }
    UI_STEP(HANDLE_CERTIFICATE_COMM_RESIGN_STEP_RESPOND) {
        respondSuccessEmptyMsg();

        tx_advanceCertificatesStateIfAppropriate();
    }
    UI_STEP_END(HANDLE_CERTIFICATE_COMM_RESIGN_STEP_INVALID);
}

void signTx_handleCertificateDRep_ui_runStep() {
    TRACE("UI step %d", ctx->ui_step);
    ui_callback_fn_t* this_fn = signTx_handleCertificateDRep_ui_runStep;
    sign_tx_certificate_data_t* cert = &BODY_CTX->stageData.certificate;

    UI_STEP_BEGIN(ctx->ui_step, this_fn);

    UI_STEP(HANDLE_CERTIFICATE_DREP_STEP_DISPLAY_OPERATION) {
        switch (cert->type) {
            case CERTIFICATE_DREP_REGISTRATION:
#ifdef HAVE_BAGL
                ui_displayPaginatedText("Register", "DRep", this_fn);
#elif defined(HAVE_NBGL)
                set_light_confirmation(true);
                display_prompt("Register\nDRep", "", this_fn, respond_with_user_reject);
#endif  // HAVE_BAGL
                break;

            case CERTIFICATE_DREP_DEREGISTRATION:
            case CERTIFICATE_STAKE_DEREGISTRATION_CONWAY:
#ifdef HAVE_BAGL
                ui_displayPaginatedText("Deregister", "DRep", this_fn);
#elif defined(HAVE_NBGL)
                set_light_confirmation(true);
                display_prompt("Deregister\nDRep", "", this_fn, respond_with_user_reject);
#endif  // HAVE_BAGL
                break;

            case CERTIFICATE_DREP_UPDATE:
#ifdef HAVE_BAGL
                ui_displayPaginatedText("Update", "DRep", this_fn);
#elif defined(HAVE_NBGL)
                set_light_confirmation(true);
                display_prompt("Update\nDRep", "", this_fn, respond_with_user_reject);
#endif  // HAVE_BAGL
                break;

            default:
                ASSERT(false);
        }
    }
    UI_STEP(HANDLE_CERTIFICATE_DREP_STEP_DISPLAY_CREDENTIAL) {
        _displayCredential(this_fn,
                           &cert->dRepCredential,
                           "DRep key",
                           "DRep key hash",
                           "drep",
                           "DRep script hash",
                           "drep");
    }
    UI_STEP(HANDLE_CERTIFICATE_DREP_STEP_DISPLAY_DEPOSIT) {
        switch (cert->type) {
            case CERTIFICATE_DREP_UPDATE:
                // no deposit in these
                UI_STEP_JUMP(HANDLE_CERTIFICATE_DREP_STEP_DISPLAY_ANCHOR_NULL);
                break;

            case CERTIFICATE_DREP_REGISTRATION:
            case CERTIFICATE_DREP_DEREGISTRATION:
                _displayDeposit(this_fn, cert->deposit);
                break;

            default:
                ASSERT(false);
        }
    }
    UI_STEP(HANDLE_CERTIFICATE_DREP_STEP_DISPLAY_ANCHOR_NULL) {
        if (cert->type == CERTIFICATE_DREP_DEREGISTRATION) {
            // no anchor for this type
            UI_STEP_JUMP(HANDLE_CERTIFICATE_DREP_STEP_CONFIRM);
        }
        if (cert->anchor.isIncluded) {
            UI_STEP_JUMP(HANDLE_CERTIFICATE_DREP_STEP_DISPLAY_ANCHOR_URL);
        }
        _displayAnchorNull(this_fn);
    }
    UI_STEP(HANDLE_CERTIFICATE_DREP_STEP_DISPLAY_ANCHOR_URL) {
        if (!cert->anchor.isIncluded) {
            UI_STEP_JUMP(HANDLE_CERTIFICATE_DREP_STEP_CONFIRM);
        }
        _displayAnchorUrl(this_fn, &cert->anchor);
    }
    UI_STEP(HANDLE_CERTIFICATE_DREP_STEP_DISPLAY_ANCHOR_HASH) {
        _displayAnchorHash(this_fn, &cert->anchor);
    }
    UI_STEP(HANDLE_CERTIFICATE_DREP_STEP_CONFIRM) {
        char description[50] = {0};
        explicit_bzero(description, SIZEOF(description));

        switch (cert->type) {
            case CERTIFICATE_DREP_REGISTRATION:
#ifdef HAVE_BAGL
                snprintf(description, SIZEOF(description), "registration?");
#elif defined(HAVE_NBGL)
                display_confirmation("Confirm\nregistration",
                                     "",
                                     "REGISTRATION\nACCEPTED",
                                     "Registration\nrejected",
                                     this_fn,
                                     respond_with_user_reject);
#endif  // HAVE_BAGL
                break;

            case CERTIFICATE_DREP_DEREGISTRATION:
#ifdef HAVE_BAGL
                snprintf(description, SIZEOF(description), "deregistration?");
#elif defined(HAVE_NBGL)
                display_confirmation("Confirm\nderegistration",
                                     "",
                                     "DEREGISTRATION\nACCEPTED",
                                     "Deregistration\nrejected",
                                     this_fn,
                                     respond_with_user_reject);
#endif  // HAVE_BAGL
                break;

            case CERTIFICATE_DREP_UPDATE:
#ifdef HAVE_BAGL
                snprintf(description, SIZEOF(description), "update?");
#elif defined(HAVE_NBGL)
                display_confirmation("Confirm\nupdate",
                                     "",
                                     "UPDATE\nACCEPTED",
                                     "Update\nrejected",
                                     this_fn,
                                     respond_with_user_reject);
#endif  // HAVE_BAGL
                break;

            default:
                ASSERT(false);
        }
        // make sure all the information is displayed to the user
        ASSERT(strlen(description) + 1 < SIZEOF(description));

#ifdef HAVE_BAGL
        ui_displayPrompt("Confirm", description, this_fn, respond_with_user_reject);
#elif defined(HAVE_NBGL)
#endif  // HAVE_BAGL
    }
    UI_STEP(HANDLE_CERTIFICATE_DREP_STEP_RESPOND) {
        respondSuccessEmptyMsg();

        tx_advanceCertificatesStateIfAppropriate();
    }
    UI_STEP_END(HANDLE_CERTIFICATE_DREP_STEP_INVALID);
}

#ifdef APP_FEATURE_POOL_RETIREMENT

void signTx_handleCertificatePoolRetirement_ui_runStep() {
    TRACE("UI step %d", ctx->ui_step);

    ui_callback_fn_t* this_fn = signTx_handleCertificatePoolRetirement_ui_runStep;
    sign_tx_certificate_data_t* cert = &BODY_CTX->stageData.certificate;
    ASSERT(cert->type == CERTIFICATE_STAKE_POOL_RETIREMENT);

    UI_STEP_BEGIN(ctx->ui_step, this_fn);

    UI_STEP(HANDLE_CERTIFICATE_POOL_RETIREMENT_STEP_DISPLAY_OPERATION) {
#ifdef HAVE_BAGL
        ui_displayBech32Screen("Retire stake pool",
                               "pool",
                               cert->poolCredential.keyHash,
                               SIZEOF(cert->poolCredential.keyHash),
                               this_fn);
#elif defined(HAVE_NBGL)
        set_light_confirmation(true);
        char encodedStr[BECH32_STRING_SIZE_MAX] = {0};
        ui_getBech32Screen(encodedStr,
                           SIZEOF(encodedStr),
                           "pool",
                           cert->poolCredential.keyHash,
                           SIZEOF(cert->poolCredential.keyHash));
        fill_and_display_if_required("Retire stake pool",
                                     encodedStr,
                                     this_fn,
                                     respond_with_user_reject);
#endif  // HAVE_BAGL
    }
    UI_STEP(HANDLE_CERTIFICATE_POOL_RETIREMENT_STEP_DISPLAY_EPOCH) {
#ifdef HAVE_BAGL
        ui_displayUint64Screen("at the start of epoch", cert->epoch, this_fn);
#elif defined(HAVE_NBGL)
        char line[30];
        ui_getUint64Screen(line, SIZEOF(line), cert->epoch);
        fill_and_display_if_required("Start of epoch", line, this_fn, respond_with_user_reject);
#endif  // HAVE_BAGL
    }
    UI_STEP(HANDLE_CERTIFICATE_POOL_RETIREMENT_STEP_CONFIRM) {
#ifdef HAVE_BAGL
        ui_displayPrompt("Confirm", "pool retirement", this_fn, respond_with_user_reject);
#elif defined(HAVE_NBGL)
        display_confirmation("Confirm\npool retirement",
                             "",
                             "POOL RETIREMENT\nCONFIRMED",
                             "Pool retirement\nrejected",
                             this_fn,
                             respond_with_user_reject);
#endif  // HAVE_BAGL
    }
    UI_STEP(HANDLE_CERTIFICATE_POOL_RETIREMENT_STEP_RESPOND) {
        respondSuccessEmptyMsg();

        tx_advanceCertificatesStateIfAppropriate();
    }
    UI_STEP_END(HANDLE_CERTIFICATE_POOL_RETIREMENT_STEP_INVALID);
}

#endif  // APP_FEATURE_POOL_RETIREMENT

// ============================== WITHDRAWALS ==============================

void signTx_handleWithdrawal_ui_runStep() {
    TRACE("UI step %d", ctx->ui_step);
    TRACE_STACK_USAGE();
    ui_callback_fn_t* this_fn = signTx_handleWithdrawal_ui_runStep;

    UI_STEP_BEGIN(ctx->ui_step, this_fn);

    UI_STEP(HANDLE_WITHDRAWAL_STEP_DISPLAY_AMOUNT) {
#ifdef HAVE_BAGL
        ui_displayAdaAmountScreen("Withdrawing rewards",
                                  BODY_CTX->stageData.withdrawal.amount,
                                  this_fn);
#elif defined(HAVE_NBGL)
        char adaAmountStr[50] = {0};
        ui_getAdaAmountScreen(adaAmountStr,
                              SIZEOF(adaAmountStr),
                              BODY_CTX->stageData.withdrawal.amount);
        fill_and_display_if_required("Withdrawing rewards",
                                     adaAmountStr,
                                     this_fn,
                                     respond_with_user_reject);
#endif  // HAVE_BAGL
    }
    UI_STEP(HANDLE_WITHDRAWAL_STEP_DISPLAY_PATH) {
        reward_account_t rewardAccount;
        switch (BODY_CTX->stageData.withdrawal.stakeCredential.type) {
            case EXT_CREDENTIAL_KEY_PATH: {
                rewardAccount.keyReferenceType = KEY_REFERENCE_PATH;
                rewardAccount.path = BODY_CTX->stageData.withdrawal.stakeCredential.keyPath;
                break;
            }
            case EXT_CREDENTIAL_KEY_HASH: {
                rewardAccount.keyReferenceType = KEY_REFERENCE_HASH;
                constructRewardAddressFromHash(
                    ctx->commonTxData.networkId,
                    REWARD_HASH_SOURCE_KEY,
                    BODY_CTX->stageData.withdrawal.stakeCredential.keyHash,
                    SIZEOF(BODY_CTX->stageData.withdrawal.stakeCredential.keyHash),
                    rewardAccount.hashBuffer,
                    SIZEOF(rewardAccount.hashBuffer));
                break;
            }
            case EXT_CREDENTIAL_SCRIPT_HASH: {
                rewardAccount.keyReferenceType = KEY_REFERENCE_HASH;
                constructRewardAddressFromHash(
                    ctx->commonTxData.networkId,
                    REWARD_HASH_SOURCE_SCRIPT,
                    BODY_CTX->stageData.withdrawal.stakeCredential.scriptHash,
                    SIZEOF(BODY_CTX->stageData.withdrawal.stakeCredential.scriptHash),
                    rewardAccount.hashBuffer,
                    SIZEOF(rewardAccount.hashBuffer));
                break;
            }
            default:
                ASSERT(false);
                break;
        }
#ifdef HAVE_BAGL
        ui_displayRewardAccountScreen(&rewardAccount, ctx->commonTxData.networkId, this_fn);
#elif defined(HAVE_NBGL)
        char firstLine[32] = {0};
        char secondLine[BIP44_PATH_STRING_SIZE_MAX + MAX_HUMAN_REWARD_ACCOUNT_SIZE + 2] = {0};
        ui_getRewardAccountScreen(firstLine,
                                  SIZEOF(firstLine),
                                  secondLine,
                                  SIZEOF(secondLine),
                                  &rewardAccount,
                                  ctx->commonTxData.networkId);
        fill_and_display_if_required(firstLine, secondLine, this_fn, respond_with_user_reject);
#endif  // HAVE_BAGL
    }
    UI_STEP(HANDLE_WITHDRAWAL_STEP_RESPOND) {
        respondSuccessEmptyMsg();

        // Advance stage to the next withdrawal
        ASSERT(BODY_CTX->currentWithdrawal < ctx->numWithdrawals);
        BODY_CTX->currentWithdrawal++;

        if (BODY_CTX->currentWithdrawal == ctx->numWithdrawals) {
            tx_advanceStage();
        }
    }
    UI_STEP_END(HANDLE_WITHDRAWAL_STEP_INVALID);
}

// ============================== VALIDITY INTERVAL START ==============================

void signTx_handleValidityInterval_ui_runStep() {
    TRACE("UI step %d", ctx->ui_step);
    ui_callback_fn_t* this_fn = signTx_handleValidityInterval_ui_runStep;

    UI_STEP_BEGIN(ctx->ui_step, this_fn);

    UI_STEP(HANDLE_VALIDITY_INTERVAL_START_STEP_DISPLAY) {
#ifdef HAVE_BAGL
        ui_displayValidityBoundaryScreen("Validity interval start",
                                         BODY_CTX->stageData.validityIntervalStart,
                                         ctx->commonTxData.networkId,
                                         ctx->commonTxData.protocolMagic,
                                         this_fn);
#elif defined(HAVE_NBGL)
        char boundaryStr[30] = {0};
        ui_getValidityBoundaryScreen(boundaryStr,
                                     SIZEOF(boundaryStr),
                                     BODY_CTX->stageData.validityIntervalStart,
                                     ctx->commonTxData.networkId,
                                     ctx->commonTxData.protocolMagic);
        fill_and_display_if_required("Validity interval start",
                                     boundaryStr,
                                     this_fn,
                                     respond_with_user_reject);
#endif  // HAVE_BAGL
    }
    UI_STEP(HANDLE_VALIDITY_INTERVAL_START_STEP_RESPOND) {
        respondSuccessEmptyMsg();
        tx_advanceStage();
    }
    UI_STEP_END(HANDLE_VALIDITY_INTERVAL_START_STEP_INVALID);
}

// ========================= SCRIPT DATA HASH ==========================

void signTx_handleScriptDataHash_ui_runStep() {
    TRACE("UI step %d", ctx->ui_step);
    ui_callback_fn_t* this_fn = signTx_handleScriptDataHash_ui_runStep;

    UI_STEP_BEGIN(ctx->ui_step, this_fn);

    UI_STEP(HANDLE_SCRIPT_DATA_HASH_STEP_DISPLAY) {
#ifdef HAVE_BAGL
        ui_displayBech32Screen("Script data hash",
                               "script_data",
                               BODY_CTX->stageData.scriptDataHash,
                               SCRIPT_DATA_HASH_LENGTH,
                               this_fn);
#elif defined(HAVE_NBGL)
        char encodedStr[BECH32_STRING_SIZE_MAX] = {0};
        ui_getBech32Screen(encodedStr,
                           SIZEOF(encodedStr),
                           "script_data",
                           BODY_CTX->stageData.scriptDataHash,
                           SIZEOF(BODY_CTX->stageData.scriptDataHash));
        fill_and_display_if_required("Script data hash",
                                     encodedStr,
                                     this_fn,
                                     respond_with_user_reject);
#endif  // HAVE_BAGL
    }
    UI_STEP(HANDLE_SCRIPT_DATA_HASH_STEP_RESPOND) {
        respondSuccessEmptyMsg();
        tx_advanceStage();
    }
    UI_STEP_END(HANDLE_FEE_STEP_INVALID);
}

// ========================= REQUIRED SIGNERS ===========================

void signTx_handleRequiredSigner_ui_runStep() {
    TRACE("UI step %d", ctx->ui_step);
    ui_callback_fn_t* this_fn = signTx_handleRequiredSigner_ui_runStep;

    UI_STEP_BEGIN(ctx->ui_step, this_fn);

    UI_STEP(HANDLE_REQUIRED_SIGNERS_STEP_DISPLAY) {
        switch (BODY_CTX->stageData.requiredSigner.type) {
            case REQUIRED_SIGNER_WITH_PATH: {
#ifdef HAVE_BAGL
                ui_displayPathScreen("Required signer",
                                     &BODY_CTX->stageData.requiredSigner.keyPath,
                                     this_fn);
#elif defined(HAVE_NBGL)
                char pathStr[BIP44_PATH_STRING_SIZE_MAX + 1] = {0};
                ui_getPathScreen(pathStr,
                                 SIZEOF(pathStr),
                                 &BODY_CTX->stageData.requiredSigner.keyPath);
                fill_and_display_if_required("Required signer",
                                             pathStr,
                                             this_fn,
                                             respond_with_user_reject);
#endif  // HAVE_BAGL
                break;
            }
            case REQUIRED_SIGNER_WITH_HASH: {
#ifdef HAVE_BAGL
                ui_displayBech32Screen("Required signer",
                                       "req_signer_vkh",
                                       BODY_CTX->stageData.requiredSigner.keyHash,
                                       SIZEOF(BODY_CTX->stageData.requiredSigner.keyHash),
                                       this_fn);
#elif defined(HAVE_NBGL)
                char encodedStr[BECH32_STRING_SIZE_MAX] = {0};
                ui_getBech32Screen(encodedStr,
                                   SIZEOF(encodedStr),
                                   "req_signer_vkh",
                                   BODY_CTX->stageData.requiredSigner.keyHash,
                                   SIZEOF(BODY_CTX->stageData.requiredSigner.keyHash));
                fill_and_display_if_required("Required signer",
                                             encodedStr,
                                             this_fn,
                                             respond_with_user_reject);
#endif  // HAVE_BAGL
                break;
            }

            default:
                ASSERT(false);
                break;
        }
    }

    UI_STEP(HANDLE_REQUIRED_SIGNERS_STEP_RESPOND) {
        respondSuccessEmptyMsg();

        // Advance stage to the next required signer
        ASSERT(BODY_CTX->currentRequiredSigner < ctx->numRequiredSigners);
        BODY_CTX->currentRequiredSigner++;

        if (BODY_CTX->currentRequiredSigner == ctx->numRequiredSigners) {
            tx_advanceStage();
        }
    }
    UI_STEP_END(HANDLE_REQUIRED_SIGNERS_STEP_INVALID);
}

// ========================= TOTAL COLLATERAL ===========================

void signTx_handleTotalCollateral_ui_runStep() {
    TRACE("UI step %d", ctx->ui_step);
    ui_callback_fn_t* this_fn = signTx_handleTotalCollateral_ui_runStep;

    TRACE_ADA_AMOUNT("total collateral ", BODY_CTX->stageData.totalCollateral);

    UI_STEP_BEGIN(ctx->ui_step, this_fn);

    UI_STEP(HANDLE_TOTAL_COLLATERAL_STEP_DISPLAY) {
#ifdef HAVE_BAGL
        ui_displayAdaAmountScreen("Total collateral", BODY_CTX->stageData.totalCollateral, this_fn);
#elif defined(HAVE_NBGL)
        char adaAmountStr[50] = {0};
        ui_getAdaAmountScreen(adaAmountStr,
                              SIZEOF(adaAmountStr),
                              BODY_CTX->stageData.totalCollateral);
        fill_and_display_if_required("Total collateral",
                                     adaAmountStr,
                                     this_fn,
                                     respond_with_user_reject);
#endif  // HAVE_BAGL
    }
    UI_STEP(HANDLE_TOTAL_COLLATERAL_STEP_RESPOND) {
        respondSuccessEmptyMsg();
        tx_advanceStage();
    }
    UI_STEP_END(HANDLE_TOTAL_COLLATERAL_STEP_INVALID);
}

// ========================= VOTING PROCEDURES ===========================

void signTx_handleVotingProcedure_ui_runStep() {
    TRACE("UI step %d", ctx->ui_step);
    ui_callback_fn_t* this_fn = signTx_handleVotingProcedure_ui_runStep;
    sign_tx_voting_procedure_t* vp = &BODY_CTX->stageData.votingProcedure;

    UI_STEP_BEGIN(ctx->ui_step, this_fn);

    UI_STEP(HANDLE_VOTING_PROCEDURE_STEP_INTRO) {
#ifdef HAVE_BAGL
        ui_displayPaginatedText("Vote for", "governance action", this_fn);
#elif defined(HAVE_NBGL)
        set_light_confirmation(true);
        display_prompt("Vote for\ngovernance action", "", this_fn, respond_with_user_reject);
#endif  // HAVE_BAGL
    }
    UI_STEP(HANDLE_VOTING_PROCEDURE_STEP_VOTER) {
        switch (vp->voter.type) {
            case EXT_VOTER_DREP_KEY_PATH:
            case EXT_VOTER_COMMITTEE_HOT_KEY_PATH:
            case EXT_VOTER_STAKE_POOL_KEY_PATH:
                _displayKeyPath(this_fn, &vp->voter.keyPath, "Voter key");
                break;
            case EXT_VOTER_DREP_KEY_HASH:
                _displayKeyHash(this_fn, vp->voter.keyHash, "Voter key hash", "drep");
                break;
            case EXT_VOTER_COMMITTEE_HOT_KEY_HASH:
                _displayKeyHash(this_fn, vp->voter.keyHash, "Voter key hash", "cc_hot");
                break;
            case EXT_VOTER_STAKE_POOL_KEY_HASH:
                _displayKeyHash(this_fn, vp->voter.keyHash, "Voter key hash", "pool");
                break;
            case EXT_VOTER_COMMITTEE_HOT_SCRIPT_HASH:
                _displayScriptHash(this_fn, vp->voter.scriptHash, "Voter script hash", "cc_hot");
                break;
            case EXT_VOTER_DREP_SCRIPT_HASH:
                _displayScriptHash(this_fn, vp->voter.scriptHash, "Voter script hash", "drep");
                break;
            default:
                ASSERT(false);
                break;
        }
    }
    UI_STEP(HANDLE_VOTING_PROCEDURE_STEP_GOV_ACTION_ID_TXHASH) {
        char txHashHex[1 + 2 * TX_HASH_LENGTH] = {0};
        explicit_bzero(txHashHex, SIZEOF(txHashHex));
        size_t len = encode_hex(vp->govActionId.txHashBuffer,
                                SIZEOF(vp->govActionId.txHashBuffer),
                                txHashHex,
                                SIZEOF(txHashHex));
        ASSERT(len + 1 == SIZEOF(txHashHex));

#ifdef HAVE_BAGL
        ui_displayPaginatedText("Action tx hash", txHashHex, this_fn);
#elif defined(HAVE_NBGL)
        fill_and_display_if_required("Action tx hash",
                                     txHashHex,
                                     this_fn,
                                     respond_with_user_reject);
#endif  // HAVE_BAGL
    }
    UI_STEP(HANDLE_VOTING_PROCEDURE_STEP_GOV_ACTION_ID_INDEX) {
        char indexStr[30] = {0};
        explicit_bzero(indexStr, SIZEOF(indexStr));
        snprintf(indexStr, SIZEOF(indexStr), "%d", vp->govActionId.govActionIndex);
        ASSERT(indexStr[SIZEOF(indexStr) - 1] == '\0');

#ifdef HAVE_BAGL
        ui_displayPaginatedText("Action tx index", indexStr, this_fn);
#elif defined(HAVE_NBGL)
        fill_and_display_if_required("Action tx index",
                                     indexStr,
                                     this_fn,
                                     respond_with_user_reject);
#endif  // HAVE_BAGL
    }
    UI_STEP(HANDLE_VOTING_PROCEDURE_STEP_VOTE) {
        char voteStr[30] = {0};
        explicit_bzero(voteStr, SIZEOF(voteStr));
        switch (vp->votingProcedure.vote) {
            case VOTE_NO:
                snprintf(voteStr, SIZEOF(voteStr), "NO");
                break;
            case VOTE_YES:
                snprintf(voteStr, SIZEOF(voteStr), "YES");
                break;
            case VOTE_ABSTAIN:
                snprintf(voteStr, SIZEOF(voteStr), "ABSTAIN");
                break;
            default:
                ASSERT(false);
        }
        ASSERT(voteStr[SIZEOF(voteStr) - 1] == '\0');

#ifdef HAVE_BAGL
        ui_displayPaginatedText("Vote", voteStr, this_fn);
#elif defined(HAVE_NBGL)
        fill_and_display_if_required("Vote", voteStr, this_fn, respond_with_user_reject);
#endif  // HAVE_BAGL
    }
    UI_STEP(HANDLE_VOTING_PROCEDURE_STEP_ANCHOR_NULL) {
        if (vp->votingProcedure.anchor.isIncluded) {
            UI_STEP_JUMP(HANDLE_VOTING_PROCEDURE_STEP_ANCHOR_URL);
        }
        _displayAnchorNull(this_fn);
    }
    UI_STEP(HANDLE_VOTING_PROCEDURE_STEP_ANCHOR_URL) {
        if (!vp->votingProcedure.anchor.isIncluded) {
            UI_STEP_JUMP(HANDLE_VOTING_PROCEDURE_STEP_CONFIRM);
        }
        _displayAnchorUrl(this_fn, &vp->votingProcedure.anchor);
    }
    UI_STEP(HANDLE_VOTING_PROCEDURE_STEP_ANCHOR_HASH) {
        _displayAnchorHash(this_fn, &vp->votingProcedure.anchor);
    }
    UI_STEP(HANDLE_VOTING_PROCEDURE_STEP_CONFIRM) {
#ifdef HAVE_BAGL
        ui_displayPrompt("Confirm", "vote?", this_fn, respond_with_user_reject);
#elif defined(HAVE_NBGL)
        display_confirmation("Confirm\nvote?",
                             "",
                             "VOTE\nACCEPTED",
                             "Vote\nrejected",
                             this_fn,
                             respond_with_user_reject);
#endif  // HAVE_BAGL
    }
    UI_STEP(HANDLE_VOTING_PROCEDURE_STEP_RESPOND) {
        respondSuccessEmptyMsg();

        // Advance stage to the next vote
        ASSERT(BODY_CTX->currentVotingProcedure < ctx->numVotingProcedures);
        BODY_CTX->currentVotingProcedure++;

        if (BODY_CTX->currentVotingProcedure == ctx->numVotingProcedures) {
            tx_advanceStage();
        }
    }
    UI_STEP_END(HANDLE_VOTING_PROCEDURE_STEP_INVALID);
}

// ============================== TREASURY ==============================

void signTx_handleTreasury_ui_runStep() {
    TRACE("UI step %d", ctx->ui_step);
    ui_callback_fn_t* this_fn = signTx_handleTreasury_ui_runStep;

    TRACE_ADA_AMOUNT("treasury ", BODY_CTX->stageData.treasury);

    UI_STEP_BEGIN(ctx->ui_step, this_fn);

    UI_STEP(HANDLE_TREASURY_STEP_DISPLAY) {
#ifdef HAVE_BAGL
        ui_displayAdaAmountScreen("Treasury amount", BODY_CTX->stageData.treasury, this_fn);
#elif defined(HAVE_NBGL)
        char adaAmountStr[50] = {0};
        ui_getAdaAmountScreen(adaAmountStr, SIZEOF(adaAmountStr), BODY_CTX->stageData.treasury);
        fill_and_display_if_required("Treasury amount",
                                     adaAmountStr,
                                     this_fn,
                                     respond_with_user_reject);
#endif  // HAVE_BAGL
    }
    UI_STEP(HANDLE_TREASURY_STEP_RESPOND) {
        respondSuccessEmptyMsg();
        tx_advanceStage();
    }
    UI_STEP_END(HANDLE_TREASURY_STEP_INVALID);
}

// ============================== DONATION ==============================

void signTx_handleDonation_ui_runStep() {
    TRACE("UI step %d", ctx->ui_step);
    ui_callback_fn_t* this_fn = signTx_handleDonation_ui_runStep;

    TRACE_ADA_AMOUNT("donation ", BODY_CTX->stageData.donation);

    UI_STEP_BEGIN(ctx->ui_step, this_fn);

    UI_STEP(HANDLE_DONATION_STEP_DISPLAY) {
#ifdef HAVE_BAGL
        ui_displayAdaAmountScreen("Donation", BODY_CTX->stageData.donation, this_fn);
#elif defined(HAVE_NBGL)
        char adaAmountStr[50] = {0};
        ui_getAdaAmountScreen(adaAmountStr, SIZEOF(adaAmountStr), BODY_CTX->stageData.donation);
        fill_and_display_if_required("Donation", adaAmountStr, this_fn, respond_with_user_reject);
#endif  // HAVE_BAGL
    }
    UI_STEP(HANDLE_DONATION_STEP_RESPOND) {
        respondSuccessEmptyMsg();
        tx_advanceStage();
    }
    UI_STEP_END(HANDLE_DONATION_STEP_INVALID);
}

// ============================== CONFIRM ==============================

void signTx_handleConfirm_ui_runStep() {
    TRACE("UI step %d", ctx->ui_step);
    TRACE_STACK_USAGE();
    ui_callback_fn_t* this_fn = signTx_handleConfirm_ui_runStep;

    UI_STEP_BEGIN(ctx->ui_step, this_fn);

    UI_STEP(HANDLE_CONFIRM_STEP_TXID) {
#ifdef HAVE_BAGL
        ui_displayHexBufferScreen("Transaction id", ctx->txHash, SIZEOF(ctx->txHash), this_fn);
#elif defined(HAVE_NBGL)
        char bufferHex[2 * TX_HASH_LENGTH + 1] = {0};
        ui_getHexBufferScreen(bufferHex, SIZEOF(bufferHex), ctx->txHash, SIZEOF(ctx->txHash));
        fill_and_display_if_required("Transaction id",
                                     bufferHex,
                                     this_fn,
                                     respond_with_user_reject);
#endif  // HAVE_BAGL
    }
    UI_STEP(HANDLE_CONFIRM_STEP_FINAL_CONFIRM) {
#ifdef HAVE_BAGL
        ui_displayPrompt("Confirm", "transaction?", this_fn, respond_with_user_reject);
#elif defined(HAVE_NBGL)
        set_light_confirmation(false);
        display_confirmation_no_approved_status("Sign\ntransaction?",
                                                "",
                                                "Transaction\nrejected",
                                                this_fn,
                                                respond_with_user_reject);
#endif  // HAVE_BAGL
    }
    UI_STEP(HANDLE_CONFIRM_STEP_RESPOND) {
        io_send_buf(SUCCESS, ctx->txHash, SIZEOF(ctx->txHash));
#ifdef HAVE_BAGL
        ui_displayBusy();  // displays dots, called only after I/O to avoid freezing
#endif                     // HAVE_BAGL

        tx_advanceStage();
    }
    UI_STEP_END(HANDLE_CONFIRM_STEP_INVALID);
}

// ============================== WITNESS ==============================

static void _wipeWitnessSignature() {
    // safer not to keep the signature in memory
    explicit_bzero(WITNESS_CTX->stageData.witness.signature,
                   SIZEOF(WITNESS_CTX->stageData.witness.signature));
    respond_with_user_reject();
}

void signTx_handleWitness_ui_runStep() {
    TRACE("UI step %d", ctx->ui_step);
    TRACE_STACK_USAGE();
    ui_callback_fn_t* this_fn = signTx_handleWitness_ui_runStep;

    UI_STEP_BEGIN(ctx->ui_step, this_fn);

    UI_STEP(HANDLE_WITNESS_STEP_WARNING) {
#ifdef HAVE_BAGL
        ui_displayPaginatedText("WARNING:", "unusual witness requested", this_fn);
#elif defined(HAVE_NBGL)
        set_light_confirmation(true);
        display_warning("Unusual\nwitness requested", this_fn, respond_with_user_reject);
#endif  // HAVE_BAGL
    }
    UI_STEP(HANDLE_WITNESS_STEP_DISPLAY) {
#ifdef HAVE_BAGL
        ui_displayPathScreen("Witness path", &WITNESS_CTX->stageData.witness.path, this_fn);
#elif defined(HAVE_NBGL)
        set_light_confirmation(true);
        char pathStr[BIP44_PATH_STRING_SIZE_MAX + 1] = {0};
        ui_getPathScreen(pathStr, SIZEOF(pathStr), &WITNESS_CTX->stageData.witness.path);
        fill_and_display_if_required("Witness path", pathStr, this_fn, respond_with_user_reject);
#endif  // HAVE_BAGL
    }
    UI_STEP(HANDLE_WITNESS_STEP_CONFIRM) {
#ifdef HAVE_BAGL
        ui_displayPrompt("Sign using", "this witness?", this_fn, _wipeWitnessSignature);
#elif defined(HAVE_NBGL)
        display_confirmation_no_approved_status("Sign using witness",
                                                "",
                                                "Signature\nrejected",
                                                this_fn,
                                                _wipeWitnessSignature);
#endif  // HAVE_BAGL
    }
    UI_STEP(HANDLE_WITNESS_STEP_RESPOND) {
        TRACE("Sending witness data");
        TRACE_BUFFER(WITNESS_CTX->stageData.witness.signature,
                     SIZEOF(WITNESS_CTX->stageData.witness.signature));
        io_send_buf(SUCCESS,
                    WITNESS_CTX->stageData.witness.signature,
                    SIZEOF(WITNESS_CTX->stageData.witness.signature));
#ifdef HAVE_BAGL
        ui_displayBusy();  // displays dots, called only after I/O to avoid freezing
#endif                     // HAVE_BAGL

        WITNESS_CTX->currentWitness++;
        if (WITNESS_CTX->currentWitness == ctx->numWitnesses) {
            tx_advanceStage();
        }
    }
    UI_STEP_END(HANDLE_WITNESS_STEP_INVALID);
}

void endTxStatus(void) {
#ifdef HAVE_NBGL
    display_status("Transaction\nsigned");
#endif  // HAVE_NBGL
}
