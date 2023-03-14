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

static const char* _newTxLine1(sign_tx_signingmode_t txSigningMode)
{
	switch (txSigningMode) {

	case SIGN_TX_SIGNINGMODE_ORDINARY_TX:
#ifdef HAVE_BAGL
		return "New ordinary";
#elif defined(HAVE_NBGL)
		return "New ordinary\ntransaction";
#endif // HAVE_BAGL

	case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OWNER:
#ifdef HAVE_BAGL
		return "New pool owner";
#elif defined(HAVE_NBGL)
		return "New pool owner\ntransaction";
#endif // HAVE_BAGL

	case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OPERATOR:
#ifdef HAVE_BAGL
		return "New pool operator";
#elif defined(HAVE_NBGL)
		return "New pool operator\ntransaction";
#endif // HAVE_BAGL

	case SIGN_TX_SIGNINGMODE_MULTISIG_TX:
#ifdef HAVE_BAGL
		return "New multisig";
#elif defined(HAVE_NBGL)
		return "New multisig\ntransaction";
#endif // HAVE_BAGL

	case SIGN_TX_SIGNINGMODE_PLUTUS_TX:
#ifdef HAVE_BAGL
		return "New Plutus";
#elif defined(HAVE_NBGL)
		return "New Plutus\ntransaction";
#endif // HAVE_BAGL

	default:
		ASSERT(false);
	}
}

#ifdef HAVE_NBGL
static void signTx_handleInit_ui_runStep_cb(void) {
    char networkParams[100] = {0};
    ui_getNetworkParamsScreen_2(
            networkParams,
            SIZEOF(networkParams),
            ctx->commonTxData.protocolMagic);
    fill_and_display_if_required("Protocol magic", networkParams, signTx_handleInit_ui_runStep, respond_with_user_reject);
}
#endif // HAVE_NBGL

void signTx_handleInit_ui_runStep()
{
	TRACE("UI step %d", ctx->ui_step);
	TRACE_STACK_USAGE();
	ui_callback_fn_t* this_fn = signTx_handleInit_ui_runStep;

	UI_STEP_BEGIN(ctx->ui_step, this_fn);

	UI_STEP(HANDLE_INIT_STEP_PROMPT_SIGNINGMODE) {
#ifdef HAVE_BAGL
		ui_displayPrompt(
		        _newTxLine1(ctx->commonTxData.txSigningMode),
		        "transaction?",
		        this_fn,
		        respond_with_user_reject
		);
#elif defined(HAVE_NBGL)
        display_prompt(_newTxLine1(ctx->commonTxData.txSigningMode), "", this_fn, respond_with_user_reject); 
#endif // HAVE_BAGL
	}

	UI_STEP(HANDLE_INIT_STEP_DISPLAY_NETWORK_DETAILS) {
		const bool isNetworkIdVerifiable = isTxNetworkIdVerifiable(
		        ctx->includeNetworkId,
		        ctx->numOutputs, ctx->numWithdrawals,
		        ctx->commonTxData.txSigningMode
		                                   );
		if (isNetworkIdVerifiable) {
			if (isNetworkUsual(ctx->commonTxData.networkId, ctx->commonTxData.protocolMagic)) {
				// no need to display the network details
				UI_STEP_JUMP(HANDLE_INIT_STEP_SCRIPT_RUNNING_WARNING);
			}
#ifdef HAVE_BAGL
			ui_displayNetworkParamsScreen(
			        "Network details",
			        ctx->commonTxData.networkId, ctx->commonTxData.protocolMagic,
			        this_fn
			);
#elif defined(HAVE_NBGL)
            char networkParams[100] = {0};
			ui_getNetworkParamsScreen_1(
                      networkParams,
                      SIZEOF(networkParams),
			          ctx->commonTxData.networkId);
            fill_and_display_if_required("Network ID", networkParams, signTx_handleInit_ui_runStep_cb, respond_with_user_reject);
#endif // HAVE_BAGL
		} else {
			// technically, no pool reg. certificate as well, but the UI message would be too long
#ifdef HAVE_BAGL
			ui_displayPaginatedText(
			        "Warning:",
			        "cannot verify network id: no outputs or withdrawals",
			        this_fn
			);
#elif defined(HAVE_NBGL)
            display_warning("Cannot verify network id:\nno outputs, or withdrawals", this_fn, respond_with_user_reject);
#endif // HAVE_BAGL
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
#endif // HAVE_BAGL
	}

	UI_STEP(HANDLE_INIT_STEP_NO_COLLATERAL_WARNING) {
		if (!needsMissingCollateralWarning(ctx->commonTxData.txSigningMode, ctx->numCollateralInputs)) {
			UI_STEP_JUMP(HANDLE_INIT_STEP_NO_SCRIPT_DATA_HASH_WARNING);
		}
#ifdef HAVE_BAGL
		ui_displayPaginatedText("WARNING:", "No collateral given for Plutus transaction", this_fn);
#elif defined(HAVE_NBGL)
        display_warning("No collateral given for\nPlutus transaction", this_fn, respond_with_user_reject);
#endif // HAVE_BAGL
	}

	UI_STEP(HANDLE_INIT_STEP_UNKNOWN_COLLATERAL_WARNING) {
		if (!needsUnknownCollateralWarning(ctx->commonTxData.txSigningMode, ctx->includeTotalCollateral)) {
			UI_STEP_JUMP(HANDLE_INIT_STEP_NO_SCRIPT_DATA_HASH_WARNING);
		}
#ifdef HAVE_BAGL
		ui_displayPaginatedText("WARNING:", "Unknown collateral amount", this_fn);
#elif defined(HAVE_NBGL)
        display_warning("Unknown collateral amount", this_fn, respond_with_user_reject);
#endif // HAVE_BAGL
	}

	UI_STEP(HANDLE_INIT_STEP_NO_SCRIPT_DATA_HASH_WARNING) {
		if (!needsMissingScriptDataHashWarning(ctx->commonTxData.txSigningMode, ctx->includeScriptDataHash)) {
			UI_STEP_JUMP(HANDLE_INIT_STEP_RESPOND);
		}
#ifdef HAVE_BAGL
		ui_displayPaginatedText("WARNING:", "No script data given for Plutus transaction", this_fn);
#elif defined(HAVE_NBGL)
        display_warning("No script data given for\nPlutus transaction", this_fn, respond_with_user_reject);
#endif // HAVE_BAGL
	}

	UI_STEP(HANDLE_INIT_STEP_RESPOND) {
		respondSuccessEmptyMsg();
		tx_advanceStage();
	}
	UI_STEP_END(HANDLE_INIT_STEP_INVALID);
}

// ============================== AUXILIARY DATA ==============================

void signTx_handleAuxDataArbitraryHash_ui_runStep()
{
	TRACE("UI step %d", ctx->ui_step);
	TRACE_STACK_USAGE();
	ui_callback_fn_t* this_fn = signTx_handleAuxDataArbitraryHash_ui_runStep;

	UI_STEP_BEGIN(ctx->ui_step, this_fn);

	UI_STEP(HANDLE_AUX_DATA_ARBITRARY_HASH_STEP_DISPLAY) {
#ifdef HAVE_BAGL
		ui_displayHexBufferScreen(
		        "Auxiliary data hash",
		        ctx->auxDataHash,
		        SIZEOF(ctx->auxDataHash),
		        this_fn
		);
#elif defined(HAVE_NBGL)
        char bufferHex[2 * 32 + 1] = {0};
        ui_getHexBufferScreen(bufferHex, SIZEOF(bufferHex), ctx->auxDataHash, SIZEOF(ctx->auxDataHash));
        fill_and_display_if_required("Auxiliary data hash", bufferHex, this_fn, respond_with_user_reject);
#endif // HAVE_BAGL
	}
	UI_STEP(HANDLE_AUX_DATA_ARBITRARY_HASH_STEP_RESPOND) {
		respondSuccessEmptyMsg();
		tx_advanceStage();
	}
	UI_STEP_END(HANDLE_AUX_DATA_ARBITRARY_HASH_STEP_INVALID);
}

void signTx_handleAuxDataCVoteRegistration_ui_runStep()
{
	TRACE("UI step %d", ctx->ui_step);
	TRACE_STACK_USAGE();
	ui_callback_fn_t* this_fn = signTx_handleAuxDataCVoteRegistration_ui_runStep;

	UI_STEP_BEGIN(ctx->ui_step, this_fn);

	UI_STEP(HANDLE_AUX_DATA_CVOTE_REGISTRATION_STEP_DISPLAY) {
#ifdef HAVE_BAGL
		ui_displayPrompt(
		        "Register vote",
		        "key (CIP-36)?",
		        this_fn,
		        respond_with_user_reject
		);
#elif defined(HAVE_NBGL)
        set_light_confirmation(true);
        display_prompt("Register vote\nkey (CIP-36)?", "", this_fn, respond_with_user_reject); 
#endif // HAVE_BAGL
	}
	UI_STEP(HANDLE_AUX_DATA_CVOTE_REGISTRATION_STEP_RESPOND) {
		respondSuccessEmptyMsg();
		signTxCVoteRegistration_init();
		ctx->stage = SIGN_STAGE_AUX_DATA_CVOTE_REGISTRATION_SUBMACHINE;
	}
	UI_STEP_END(HANDLE_AUX_DATA_CVOTE_REGISTRATION_STEP_INVALID);
}

// ============================== INPUTS ==============================

void signTx_handleInput_ui_runStep()
{
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
        fill_and_display_if_required(BODY_CTX->stageData.input.label, inputStr, this_fn, respond_with_user_reject);
#endif // HAVE_BAGL
	}

	UI_STEP(HANDLE_INPUT_STEP_RESPOND) {
		respondSuccessEmptyMsg();

		ASSERT(ctx->ui_advanceState != NULL);
		ctx->ui_advanceState();
	}
	UI_STEP_END(HANDLE_INPUT_STEP_INVALID);
}

// ============================== FEE ==============================

void signTx_handleFee_ui_runStep()
{
	TRACE("UI step %d", ctx->ui_step);
	ui_callback_fn_t* this_fn = signTx_handleFee_ui_runStep;

	TRACE_ADA_AMOUNT("fee ", BODY_CTX->stageData.fee);

	UI_STEP_BEGIN(ctx->ui_step, this_fn);

	UI_STEP(HANDLE_FEE_STEP_DISPLAY) {
#ifdef HAVE_BAGL
		ui_displayAdaAmountScreen("Transaction fee", BODY_CTX->stageData.fee, this_fn);
#elif defined(HAVE_NBGL)
        char adaAmountStr[50] = {0};
        ui_getAdaAmountScreen(adaAmountStr, SIZEOF(adaAmountStr), BODY_CTX->stageData.fee);
        fill_and_display_if_required("Transaction fee", adaAmountStr, this_fn, respond_with_user_reject);
#endif // HAVE_BAGL
	}
	UI_STEP(HANDLE_FEE_STEP_RESPOND) {
		respondSuccessEmptyMsg();
		tx_advanceStage();
	}
	UI_STEP_END(HANDLE_FEE_STEP_INVALID);
}

// ============================== TTL ==============================

void signTx_handleTtl_ui_runStep()
{
	TRACE("UI step %d", ctx->ui_step);
	ui_callback_fn_t* this_fn = signTx_handleTtl_ui_runStep;

	UI_STEP_BEGIN(ctx->ui_step, this_fn);

	UI_STEP(HANDLE_TTL_STEP_DISPLAY) {
#ifdef HAVE_BAGL
		ui_displayValidityBoundaryScreen(
		        "Transaction TTL",
		        BODY_CTX->stageData.ttl,
		        ctx->commonTxData.networkId, ctx->commonTxData.protocolMagic,
		        this_fn
		);
#elif defined(HAVE_NBGL)
        char boundaryStr[30] = {0};
        ui_getValidityBoundaryScreen(boundaryStr, SIZEOF(boundaryStr), BODY_CTX->stageData.ttl, ctx->commonTxData.networkId, ctx->commonTxData.protocolMagic);
        fill_and_display_if_required("Transaction TTL", boundaryStr, this_fn, respond_with_user_reject);
#endif // HAVE_BAGL
	}
	UI_STEP(HANDLE_TTL_STEP_RESPOND) {
		respondSuccessEmptyMsg();
		tx_advanceStage();
	}
	UI_STEP_END(HANDLE_TTL_STEP_INVALID);
}

// ============================== CERTIFICATES ==============================

// called from main state machine when a pool registration certificate
// sub-machine is finished, or when other type of certificate is processed
static inline void advanceCertificatesStateIfAppropriate()
{
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
	}
	break;

	default:
		ASSERT(ctx->stage == SIGN_STAGE_BODY_CERTIFICATES_POOL_SUBMACHINE);
	}
}

#ifdef HAVE_NBGL
static void signTx_handleCertificate_ui_delegation_cb(void) {
    char encodedStr[11 + BECH32_PREFIX_LENGTH_MAX + 2 * BECH32_BUFFER_SIZE_MAX] = {0};
    ui_getBech32Screen(encodedStr, SIZEOF(encodedStr), "pool", BODY_CTX->stageData.certificate.poolKeyHash, SIZEOF(BODY_CTX->stageData.certificate.poolKeyHash));
    fill_and_display_if_required("Pool", encodedStr, signTx_handleCertificate_ui_runStep, respond_with_user_reject);
}
#endif

void signTx_handleCertificate_ui_runStep()
{
	TRACE("UI step %d", ctx->ui_step);
	ui_callback_fn_t* this_fn = signTx_handleCertificate_ui_runStep;

	UI_STEP_BEGIN(ctx->ui_step, this_fn);

	UI_STEP(HANDLE_CERTIFICATE_STEP_DISPLAY_OPERATION) {
		switch (BODY_CTX->stageData.certificate.type) {
		case CERTIFICATE_TYPE_STAKE_REGISTRATION:
#ifdef HAVE_BAGL
			ui_displayPaginatedText(
			        "Register",
			        "staking key",
			        this_fn
			);
#elif defined(HAVE_NBGL)
            set_light_confirmation(true);
            display_prompt("Register\nstaking key", "", this_fn, respond_with_user_reject);
#endif // HAVE_BAGL
			break;

		case CERTIFICATE_TYPE_STAKE_DEREGISTRATION:
#ifdef HAVE_BAGL
			ui_displayPaginatedText(
			        "Deregister",
			        "staking key",
			        this_fn
			);
#elif defined(HAVE_NBGL)
            set_light_confirmation(true);
            display_prompt("Deregister\nstaking key", "", this_fn, respond_with_user_reject);
#endif // HAVE_BAGL
			break;

		case CERTIFICATE_TYPE_STAKE_DELEGATION:
#ifdef HAVE_BAGL
			ui_displayBech32Screen(
			        "Delegate stake to",
			        "pool",
			        BODY_CTX->stageData.certificate.poolKeyHash, SIZEOF(BODY_CTX->stageData.certificate.poolKeyHash),
			        this_fn
			);
#elif defined(HAVE_NBGL)
            set_light_confirmation(true);
            display_prompt("Delegate staking\nconfirmation key", "", signTx_handleCertificate_ui_delegation_cb, respond_with_user_reject);
#endif // HAVE_BAGL
			break;

		default:
			// includes CERTIFICATE_TYPE_STAKE_POOL_REGISTRATION
			// and CERTIFICATE_TYPE_STAKE_POOL_RETIREMENT
			// which have separate UI; this handler must not be used
			ASSERT(false);
		}
	}
	UI_STEP(HANDLE_CERTIFICATE_STEP_DISPLAY_STAKING_KEY) {
		switch (BODY_CTX->stageData.certificate.stakeCredential.type) {
		case STAKE_CREDENTIAL_KEY_PATH:
#ifdef HAVE_BAGL
			ui_displayPathScreen(
			        "Staking key",
			        &BODY_CTX->stageData.certificate.stakeCredential.keyPath,
			        this_fn
			);
#elif defined(HAVE_NBGL)
            {
                char pathStr[BIP44_PATH_STRING_SIZE_MAX + 1] = {0};
                ui_getPathScreen(pathStr, SIZEOF(pathStr), &BODY_CTX->stageData.certificate.stakeCredential.keyPath);
                fill_and_display_if_required("Staking key", pathStr, this_fn, respond_with_user_reject);
            }
#endif // HAVE_BAGL
			break;
		case STAKE_CREDENTIAL_KEY_HASH:
#ifdef HAVE_BAGL
			ui_displayBech32Screen(
			        "Staking key hash",
			        "stake_vkh",
			        BODY_CTX->stageData.certificate.stakeCredential.keyHash,
			        SIZEOF(BODY_CTX->stageData.certificate.stakeCredential.keyHash),
			        this_fn
			);
#elif defined(HAVE_NBGL)
            {
                char encodedStr[11 + BECH32_PREFIX_LENGTH_MAX + 2 * BECH32_BUFFER_SIZE_MAX] = {0};
                ui_getBech32Screen(encodedStr, SIZEOF(encodedStr), "stake_vkh", BODY_CTX->stageData.certificate.stakeCredential.keyHash, SIZEOF(BODY_CTX->stageData.certificate.stakeCredential.keyHash));
                fill_and_display_if_required("Staking key hash", encodedStr, this_fn, respond_with_user_reject);
            }
#endif // HAVE_BAGL
			break;
		case STAKE_CREDENTIAL_SCRIPT_HASH:
#ifdef HAVE_BAGL
			ui_displayBech32Screen(
			        "Staking script hash",
			        "script",
			        BODY_CTX->stageData.certificate.stakeCredential.scriptHash,
			        SIZEOF(BODY_CTX->stageData.certificate.stakeCredential.scriptHash),
			        this_fn
			);
#elif defined(HAVE_NBGL)
            {
                char encodedStr[11 + BECH32_PREFIX_LENGTH_MAX + 2 * BECH32_BUFFER_SIZE_MAX] = {0};
                ui_getBech32Screen(encodedStr, SIZEOF(encodedStr), "script", BODY_CTX->stageData.certificate.stakeCredential.scriptHash, SIZEOF(BODY_CTX->stageData.certificate.stakeCredential.scriptHash));
                fill_and_display_if_required("Staking script hash", encodedStr, this_fn, respond_with_user_reject);
            }
#endif // HAVE_BAGL
			break;
		default:
			ASSERT(false);
			break;
		}
	}
	UI_STEP(HANDLE_CERTIFICATE_STEP_CONFIRM) {
		char description[50] = {0};
		explicit_bzero(description, SIZEOF(description));

		switch (BODY_CTX->stageData.certificate.type) {
		case CERTIFICATE_TYPE_STAKE_REGISTRATION:
#ifdef HAVE_BAGL
			snprintf(description, SIZEOF(description), "registration?");
#elif defined(HAVE_NBGL)
            display_confirmation("Confirm\nregistration", "", "REGISTRATION\nACCEPTED", "Registration\nrejected", this_fn, respond_with_user_reject);
#endif // HAVE_BAGL
			break;

		case CERTIFICATE_TYPE_STAKE_DEREGISTRATION:
#ifdef HAVE_BAGL
			snprintf(description, SIZEOF(description), "deregistration?");
#elif defined(HAVE_NBGL)
            display_confirmation("Confirm\nderegistration", "", "DEREGISTRATION\nACCEPTED", "Deregistration\nrejected", this_fn, respond_with_user_reject);
#endif // HAVE_BAGL
			break;

		case CERTIFICATE_TYPE_STAKE_DELEGATION:
#ifdef HAVE_BAGL
			snprintf(description, SIZEOF(description), "delegation?");
#elif defined(HAVE_NBGL)
            display_confirmation("Confirm\ndelegation", "", "DELEGATION\nACCEPTED", "Delegation\nrejected", this_fn, respond_with_user_reject);
#endif // HAVE_BAGL
			break;

		default:
			ASSERT(false);
		}
		// make sure all the information is displayed to the user
		ASSERT(strlen(description) + 1 < SIZEOF(description));

#ifdef HAVE_BAGL
		ui_displayPrompt(
		        "Confirm",
		        description,
		        this_fn,
		        respond_with_user_reject
		);
#elif defined(HAVE_NBGL)
#endif // HAVE_BAGL
	}
	UI_STEP(HANDLE_CERTIFICATE_STEP_RESPOND) {
		respondSuccessEmptyMsg();

		advanceCertificatesStateIfAppropriate();
	}
	UI_STEP_END(HANDLE_CERTIFICATE_STEP_INVALID);
}

void signTx_handleCertificatePoolRetirement_ui_runStep()
{
	TRACE("UI step %d", ctx->ui_step);
	ASSERT(BODY_CTX->stageData.certificate.type == CERTIFICATE_TYPE_STAKE_POOL_RETIREMENT);

	ui_callback_fn_t* this_fn = signTx_handleCertificatePoolRetirement_ui_runStep;

	UI_STEP_BEGIN(ctx->ui_step, this_fn);

	UI_STEP(HANDLE_CERTIFICATE_POOL_RETIREMENT_STEP_DISPLAY_OPERATION) {
#ifdef HAVE_BAGL
		ui_displayBech32Screen(
		        "Retire stake pool",
		        "pool",
		        BODY_CTX->stageData.certificate.poolKeyHash, SIZEOF(BODY_CTX->stageData.certificate.poolKeyHash),
		        this_fn
		);
#elif defined(HAVE_NBGL)
        set_light_confirmation(true);
        char encodedStr[11 + BECH32_PREFIX_LENGTH_MAX + 2 * BECH32_BUFFER_SIZE_MAX] = {0};
        ui_getBech32Screen(encodedStr, SIZEOF(encodedStr), "pool", BODY_CTX->stageData.certificate.poolKeyHash, SIZEOF(BODY_CTX->stageData.certificate.poolKeyHash));
        fill_and_display_if_required("Retire stake pool", encodedStr, this_fn, respond_with_user_reject);
#endif // HAVE_BAGL
	}
	UI_STEP(HANDLE_CERTIFICATE_POOL_RETIREMENT_STEP_DISPLAY_EPOCH) {
#ifdef HAVE_BAGL
		ui_displayUint64Screen(
		        "at the start of epoch",
		        BODY_CTX->stageData.certificate.epoch,
		        this_fn
		);
#elif defined(HAVE_NBGL)
        char line[30];
		ui_getUint64Screen(
                line,
                SIZEOF(line),
		        BODY_CTX->stageData.certificate.epoch
		);
        fill_and_display_if_required("Start of epoch", line, this_fn, respond_with_user_reject);
#endif // HAVE_BAGL
	}
	UI_STEP(HANDLE_CERTIFICATE_POOL_RETIREMENT_STEP_CONFIRM) {
#ifdef HAVE_BAGL
		ui_displayPrompt(
		        "Confirm",
		        "pool retirement",
		        this_fn,
		        respond_with_user_reject
		);
#elif defined(HAVE_NBGL)
        display_confirmation("Confirm\npool retirement", "", "POOL RETIREMENT\nCONFIRMED", "Pool retirement\nrejected", this_fn, respond_with_user_reject);
#endif // HAVE_BAGL
	}
	UI_STEP(HANDLE_CERTIFICATE_POOL_RETIREMENT_STEP_RESPOND) {
		respondSuccessEmptyMsg();

		advanceCertificatesStateIfAppropriate();
	}
	UI_STEP_END(HANDLE_CERTIFICATE_POOL_RETIREMENT_STEP_INVALID);
}

// ============================== WITHDRAWALS ==============================

void signTx_handleWithdrawal_ui_runStep()
{
	TRACE("UI step %d", ctx->ui_step);
	TRACE_STACK_USAGE();
	ui_callback_fn_t* this_fn = signTx_handleWithdrawal_ui_runStep;

	UI_STEP_BEGIN(ctx->ui_step, this_fn);

	UI_STEP(HANDLE_WITHDRAWAL_STEP_DISPLAY_AMOUNT) {
#ifdef HAVE_BAGL
		ui_displayAdaAmountScreen("Withdrawing rewards", BODY_CTX->stageData.withdrawal.amount, this_fn);
#elif defined(HAVE_NBGL)
        char adaAmountStr[50] = {0};
        ui_getAdaAmountScreen(adaAmountStr, SIZEOF(adaAmountStr), BODY_CTX->stageData.withdrawal.amount);
        fill_and_display_if_required("Withdrawing rewards", adaAmountStr, this_fn, respond_with_user_reject);
#endif // HAVE_BAGL
	}
	UI_STEP(HANDLE_WITHDRAWAL_STEP_DISPLAY_PATH) {
		reward_account_t rewardAccount;
		switch (BODY_CTX->stageData.withdrawal.stakeCredential.type) {
		case STAKE_CREDENTIAL_KEY_PATH: {
			rewardAccount.keyReferenceType = KEY_REFERENCE_PATH;
			rewardAccount.path = BODY_CTX->stageData.withdrawal.stakeCredential.keyPath;
			break;
		}
		case STAKE_CREDENTIAL_KEY_HASH: {
			rewardAccount.keyReferenceType = KEY_REFERENCE_HASH;
			constructRewardAddressFromHash(
			        ctx->commonTxData.networkId,
			        REWARD_HASH_SOURCE_KEY,
			        BODY_CTX->stageData.withdrawal.stakeCredential.keyHash,
			        SIZEOF(BODY_CTX->stageData.withdrawal.stakeCredential.keyHash),
			        rewardAccount.hashBuffer,
			        SIZEOF(rewardAccount.hashBuffer)
			);
			break;
		}
		case STAKE_CREDENTIAL_SCRIPT_HASH: {
			rewardAccount.keyReferenceType = KEY_REFERENCE_HASH;
			constructRewardAddressFromHash(
			        ctx->commonTxData.networkId,
			        REWARD_HASH_SOURCE_SCRIPT,
			        BODY_CTX->stageData.withdrawal.stakeCredential.scriptHash,
			        SIZEOF(BODY_CTX->stageData.withdrawal.stakeCredential.scriptHash),
			        rewardAccount.hashBuffer,
			        SIZEOF(rewardAccount.hashBuffer)
			);
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
        ui_getRewardAccountScreen(firstLine, SIZEOF(firstLine), secondLine, SIZEOF(secondLine), &rewardAccount, ctx->commonTxData.networkId);
        fill_and_display_if_required(firstLine, secondLine, this_fn, respond_with_user_reject);
#endif // HAVE_BAGL
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

void signTx_handleValidityInterval_ui_runStep()
{
	TRACE("UI step %d", ctx->ui_step);
	ui_callback_fn_t* this_fn = signTx_handleValidityInterval_ui_runStep;

	UI_STEP_BEGIN(ctx->ui_step, this_fn);

	UI_STEP(HANDLE_VALIDITY_INTERVAL_START_STEP_DISPLAY) {
#ifdef HAVE_BAGL
		ui_displayValidityBoundaryScreen(
		        "Validity interval start",
		        BODY_CTX->stageData.validityIntervalStart,
		        ctx->commonTxData.networkId, ctx->commonTxData.protocolMagic,
		        this_fn
		);
#elif defined(HAVE_NBGL)
        char boundaryStr[30] = {0};
		ui_getValidityBoundaryScreen(boundaryStr, SIZEOF(boundaryStr), BODY_CTX->stageData.validityIntervalStart, ctx->commonTxData.networkId, ctx->commonTxData.protocolMagic);
        fill_and_display_if_required("Validity interval start", boundaryStr, this_fn, respond_with_user_reject);
#endif // HAVE_BAGL
	}
	UI_STEP(HANDLE_VALIDITY_INTERVAL_START_STEP_RESPOND) {
		respondSuccessEmptyMsg();
		tx_advanceStage();
	}
	UI_STEP_END(HANDLE_VALIDITY_INTERVAL_START_STEP_INVALID);
}

// ========================= SCRIPT DATA HASH ==========================

void signTx_handleScriptDataHash_ui_runStep()
{
	TRACE("UI step %d", ctx->ui_step);
	ui_callback_fn_t* this_fn = signTx_handleScriptDataHash_ui_runStep;

	UI_STEP_BEGIN(ctx->ui_step, this_fn);

	UI_STEP(HANDLE_SCRIPT_DATA_HASH_STEP_DISPLAY) {
#ifdef HAVE_BAGL
		ui_displayBech32Screen(
		        "Script data hash",
		        "script_data",
		        BODY_CTX->stageData.scriptDataHash, SCRIPT_DATA_HASH_LENGTH,
		        this_fn
		);
#elif defined(HAVE_NBGL)
        char encodedStr[11 + BECH32_PREFIX_LENGTH_MAX + 2 * BECH32_BUFFER_SIZE_MAX] = {0};
        ui_getBech32Screen(encodedStr, SIZEOF(encodedStr), "script_data", BODY_CTX->stageData.scriptDataHash, SIZEOF(BODY_CTX->stageData.scriptDataHash));
        fill_and_display_if_required("Script data hash", encodedStr, this_fn, respond_with_user_reject);
#endif // HAVE_BAGL
	}
	UI_STEP(HANDLE_SCRIPT_DATA_HASH_STEP_RESPOND) {
		respondSuccessEmptyMsg();
		tx_advanceStage();
	}
	UI_STEP_END(HANDLE_FEE_STEP_INVALID);
}

// ========================= REQUIRED SIGNERS ===========================

void signTx_handleRequiredSigner_ui_runStep()
{
	TRACE("UI step %d", ctx->ui_step);
	ui_callback_fn_t* this_fn = signTx_handleRequiredSigner_ui_runStep;

	UI_STEP_BEGIN(ctx->ui_step, this_fn);

	UI_STEP(HANDLE_REQUIRED_SIGNERS_STEP_DISPLAY) {
		switch (BODY_CTX->stageData.requiredSigner.type) {
		case REQUIRED_SIGNER_WITH_PATH:
#ifdef HAVE_BAGL
			ui_displayPathScreen("Required signer", &BODY_CTX->stageData.requiredSigner.keyPath, this_fn);
#elif defined(HAVE_NBGL)
            char pathStr[BIP44_PATH_STRING_SIZE_MAX + 1] = {0};
            ui_getPathScreen(pathStr, SIZEOF(pathStr), &BODY_CTX->stageData.requiredSigner.keyPath);
            fill_and_display_if_required("Required signer", pathStr, this_fn, respond_with_user_reject);
#endif // HAVE_BAGL
			break;
		case REQUIRED_SIGNER_WITH_HASH:
#ifdef HAVE_BAGL
			ui_displayBech32Screen(
			        "Required signer",
			        "req_signer_vkh",
			        BODY_CTX->stageData.requiredSigner.keyHash,
			        SIZEOF(BODY_CTX->stageData.requiredSigner.keyHash),
			        this_fn
			);
#elif defined(HAVE_NBGL)
            char encodedStr[11 + BECH32_PREFIX_LENGTH_MAX + 2 * BECH32_BUFFER_SIZE_MAX] = {0};
            ui_getBech32Screen(encodedStr, SIZEOF(encodedStr), "req_signer_vfk", BODY_CTX->stageData.requiredSigner.keyHash, SIZEOF(BODY_CTX->stageData.requiredSigner.keyHash));
            fill_and_display_if_required("Required signer", encodedStr, this_fn, respond_with_user_reject);
#endif // HAVE_BAGL
			break;

		default:
			ASSERT(false);
			break;
		}
	}

	UI_STEP(HANDLE_REQUIRED_SIGNERS_STEP_RESPOND) {
		respondSuccessEmptyMsg();

		// Advance stage to the next input
		ASSERT(BODY_CTX->currentRequiredSigner < ctx->numRequiredSigners);
		BODY_CTX->currentRequiredSigner++;

		if (BODY_CTX->currentRequiredSigner == ctx->numRequiredSigners) {
			tx_advanceStage();
		}
	}
	UI_STEP_END(HANDLE_REQUIRED_SIGNERS_STEP_INVALID);
}

// ========================= TOTAL COLLATERAL ===========================

void signTx_handleTotalCollateral_ui_runStep()
{
	TRACE("UI step %d", ctx->ui_step);
	ui_callback_fn_t* this_fn = signTx_handleTotalCollateral_ui_runStep;

	TRACE_ADA_AMOUNT("total collateral ", BODY_CTX->stageData.totalCollateral);

	UI_STEP_BEGIN(ctx->ui_step, this_fn);

	UI_STEP(HANDLE_TOTAL_COLLATERAL_STEP_DISPLAY) {
#ifdef HAVE_BAGL
		ui_displayAdaAmountScreen("Total collateral", BODY_CTX->stageData.totalCollateral, this_fn);
#elif defined(HAVE_NBGL)
        char adaAmountStr[50] = {0};
        ui_getAdaAmountScreen(adaAmountStr, SIZEOF(adaAmountStr), BODY_CTX->stageData.totalCollateral);
        fill_and_display_if_required("Total collateral", adaAmountStr, this_fn, respond_with_user_reject);
#endif // HAVE_BAGL
	}
	UI_STEP(HANDLE_TOTAL_COLLATERAL_STEP_RESPOND) {
		respondSuccessEmptyMsg();
		tx_advanceStage();
	}
	UI_STEP_END(HANDLE_TOTAL_COLLATERAL_STEP_INVALID);
}

// ============================== CONFIRM ==============================

void signTx_handleConfirm_ui_runStep()
{
	TRACE("UI step %d", ctx->ui_step);
	TRACE_STACK_USAGE();
	ui_callback_fn_t* this_fn = signTx_handleConfirm_ui_runStep;

	UI_STEP_BEGIN(ctx->ui_step, this_fn);

	UI_STEP(HANDLE_CONFIRM_STEP_TXID) {
#ifdef HAVE_BAGL
		ui_displayHexBufferScreen(
		        "Transaction id",
		        ctx->txHash, SIZEOF(ctx->txHash),
		        this_fn
		);
#elif defined(HAVE_NBGL)
        char bufferHex[2 * 32 + 1] = {0};
        ui_getHexBufferScreen(bufferHex, SIZEOF(bufferHex), ctx->txHash, SIZEOF(ctx->txHash));
        fill_and_display_if_required("Transaction id", bufferHex, this_fn, respond_with_user_reject);
#endif // HAVE_BAGL
	}
	UI_STEP(HANDLE_CONFIRM_STEP_FINAL_CONFIRM) {
#ifdef HAVE_BAGL
		ui_displayPrompt(
		        "Confirm",
		        "transaction?",
		        this_fn,
		        respond_with_user_reject
		);
#elif defined(HAVE_NBGL)
        display_confirmation("Sign\ntransaction", "", "TRANSACTION\nSIGNED", "Transaction\nrejected", this_fn, respond_with_user_reject);
#endif // HAVE_BAGL
	}
	UI_STEP(HANDLE_CONFIRM_STEP_RESPOND) {
		io_send_buf(SUCCESS, ctx->txHash, SIZEOF(ctx->txHash));
#ifdef HAVE_BAGL
		ui_displayBusy(); // displays dots, called only after I/O to avoid freezing
#endif // HAVE_BAGL

		tx_advanceStage();
	}
	UI_STEP_END(HANDLE_CONFIRM_STEP_INVALID);
}

// ============================== WITNESS ==============================

static void _wipeWitnessSignature()
{
	// safer not to keep the signature in memory
	explicit_bzero(WITNESS_CTX->stageData.witness.signature, SIZEOF(WITNESS_CTX->stageData.witness.signature));
	respond_with_user_reject();
}

void signTx_handleWitness_ui_runStep()
{
	TRACE("UI step %d", ctx->ui_step);
	TRACE_STACK_USAGE();
	ui_callback_fn_t* this_fn = signTx_handleWitness_ui_runStep;

	UI_STEP_BEGIN(ctx->ui_step, this_fn);

	UI_STEP(HANDLE_WITNESS_STEP_WARNING) {
#ifdef HAVE_BAGL
		ui_displayPaginatedText(
		        "WARNING:",
		        "unusual witness requested",
		        this_fn
		);
#elif defined(HAVE_NBGL)
        set_light_confirmation(true);
        display_warning("Unusual\nwitness requested", this_fn, respond_with_user_reject);
#endif // HAVE_BAGL
	}
	UI_STEP(HANDLE_WITNESS_STEP_DISPLAY) {
#ifdef HAVE_BAGL
		ui_displayPathScreen("Witness path", &WITNESS_CTX->stageData.witness.path, this_fn);
#elif defined(HAVE_NBGL)
        set_light_confirmation(true);
        char pathStr[BIP44_PATH_STRING_SIZE_MAX + 1] = {0};
        ui_getPathScreen(pathStr, SIZEOF(pathStr), &WITNESS_CTX->stageData.witness.path);
        fill_and_display_if_required("Witness path", pathStr, this_fn, respond_with_user_reject);
#endif // HAVE_BAGL
	}
	UI_STEP(HANDLE_WITNESS_STEP_CONFIRM) {
#ifdef HAVE_BAGL
		ui_displayPrompt(
		        "Sign using",
		        "this witness?",
		        this_fn,
		        _wipeWitnessSignature
		);
#elif defined(HAVE_NBGL)
        display_confirmation("Sign using witness", "", "SIGNATURE\nCONFIRMED", "Signature\nrejected", this_fn, _wipeWitnessSignature);
#endif // HAVE_BAGL
	}
	UI_STEP(HANDLE_WITNESS_STEP_RESPOND) {
		TRACE("Sending witness data");
		TRACE_BUFFER(WITNESS_CTX->stageData.witness.signature, SIZEOF(WITNESS_CTX->stageData.witness.signature));
		io_send_buf(SUCCESS, WITNESS_CTX->stageData.witness.signature, SIZEOF(WITNESS_CTX->stageData.witness.signature));
#ifdef HAVE_BAGL
		ui_displayBusy(); // displays dots, called only after I/O to avoid freezing
#endif // HAVE_BAGL

		WITNESS_CTX->currentWitness++;
		if (WITNESS_CTX->currentWitness == ctx->numWitnesses) {
			tx_advanceStage();
		}
	}
	UI_STEP_END(HANDLE_WITNESS_STEP_INVALID);
}
