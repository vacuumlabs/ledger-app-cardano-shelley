#include "signTx.h"
#include "signTxPoolRegistration_ui.h"
#include "state.h"
#include "cardano.h"
#include "addressUtilsShelley.h"
#include "keyDerivation.h"
#include "uiHelpers.h"
#include "signTxUtils.h"
#include "txHashBuilder.h"
#include "textUtils.h"
#include "hexUtils.h"
#include "bufView.h"
#include "securityPolicy.h"
#include "signTxPoolRegistration.h"
#include "ipUtils.h"

#ifdef HAVE_BAGL
#include "uiScreens_bagl.h"
#elif defined(HAVE_NBGL)
#include "uiScreens_nbgl.h"
#endif

static common_tx_data_t* commonTxData = &(instructionState.signTxContext.commonTxData);

static pool_registration_context_t* accessSubcontext()
{
	return &BODY_CTX->stageContext.pool_registration_subctx;
}

static inline void advanceState()
{
	pool_registration_context_t* subctx = accessSubcontext();
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
		txHashBuilder_addPoolRegistrationCertificate_enterOwners(&BODY_CTX->txHashBuilder);
		subctx->state = STAKE_POOL_REGISTRATION_OWNERS;

		if (subctx->numOwners > 0) {
			break;
		}

	// intentional fallthrough

	case STAKE_POOL_REGISTRATION_OWNERS:
		ASSERT(subctx->currentOwner == subctx->numOwners);

		txHashBuilder_addPoolRegistrationCertificate_enterRelays(&BODY_CTX->txHashBuilder);
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

void handlePoolInit_ui_runStep()
{
	pool_registration_context_t* subctx = accessSubcontext();
	TRACE("UI step %d", subctx->ui_step);
	TRACE_STACK_USAGE();
	ui_callback_fn_t* this_fn = handlePoolInit_ui_runStep;

	UI_STEP_BEGIN(subctx->ui_step, this_fn);

	UI_STEP(HANDLE_POOL_INIT_STEP_DISPLAY) {
		#ifdef HAVE_BAGL
		ui_displayPaginatedText(
		        "Pool registration",
		        "certificate",
		        this_fn
		);
		#elif defined(HAVE_NBGL)
		display_prompt(
		        "Pool registration\ncertificate",
		        "",
		        this_fn,
		        respond_with_user_reject
		);
		#endif // HAVE_BAGL
	}
	UI_STEP(HANDLE_POOL_INIT_STEP_RESPOND) {
		respondSuccessEmptyMsg();
		advanceState();
	}
	UI_STEP_END(HANDLE_POOL_INIT_STEP_INVALID);
}

// ============================== POOL KEY HASH / ID ==============================

static void _toPoolKeyHash(const pool_id_t* poolId, uint8_t* poolKeyHash)
{
	switch (poolId->keyReferenceType) {

	case KEY_REFERENCE_HASH: {
		STATIC_ASSERT(SIZEOF(poolId->hash) == POOL_KEY_HASH_LENGTH, "wrong pool key hash length");
		memmove(poolKeyHash, poolId->hash, POOL_KEY_HASH_LENGTH);
		break;
	}
	case KEY_REFERENCE_PATH: {
		bip44_pathToKeyHash(&poolId->path, poolKeyHash, POOL_KEY_HASH_LENGTH);
		break;
	}
	default:
		ASSERT(false);
	}
}

void handlePoolKey_ui_runStep()
{
	pool_registration_context_t* subctx = accessSubcontext();
	TRACE("UI step %d", subctx->ui_step);
	TRACE_STACK_USAGE();
	ui_callback_fn_t* this_fn = handlePoolKey_ui_runStep;

	UI_STEP_BEGIN(subctx->ui_step, this_fn);

	UI_STEP(HANDLE_POOL_KEY_STEP_DISPLAY_POOL_PATH) {
		#ifdef HAVE_BAGL
		ui_displayPathScreen(
		        "Pool ID path",
		        &subctx->stateData.poolId.path,
		        this_fn
		);
		#elif defined(HAVE_NBGL)
		char pathStr[BIP44_PATH_STRING_SIZE_MAX + 1] = {0};
		ui_getPathScreen(
		        pathStr, SIZEOF(pathStr),
		        &subctx->stateData.poolId.path
		);
		fill_and_display_if_required(
		        "Pool ID path",
		        pathStr,
		        this_fn,
		        respond_with_user_reject);
		#endif // HAVE_BAGL
	}
	UI_STEP(HANDLE_POOL_KEY_STEP_DISPLAY_POOL_ID) {
		uint8_t poolKeyHash[POOL_KEY_HASH_LENGTH] = {0};
		_toPoolKeyHash(&subctx->stateData.poolId, poolKeyHash);

		#ifdef HAVE_BAGL
		ui_displayBech32Screen(
		        "Pool ID",
		        "pool",
		        poolKeyHash, SIZEOF(poolKeyHash),
		        this_fn
		);
		#elif defined(HAVE_NBGL)
		char encodedStr[11 + BECH32_PREFIX_LENGTH_MAX + 2 * BECH32_BUFFER_SIZE_MAX] = {0};
		ui_getBech32Screen(
		        encodedStr, SIZEOF(encodedStr),
		        "pool",
		        poolKeyHash, SIZEOF(poolKeyHash)
		);

		fill_and_display_if_required(
		        "Pool ID",
		        encodedStr,
		        this_fn,
		        respond_with_user_reject);
		#endif // HAVE_BAGL
	}
	UI_STEP(HANDLE_POOL_KEY_STEP_RESPOND) {
		respondSuccessEmptyMsg();
		advanceState();
	}
	UI_STEP_END(HANDLE_POOL_KEY_STEP_INVALID);
}

// ============================== VRF KEY HASH ==============================

void handlePoolVrfKey_ui_runStep()
{
	pool_registration_context_t* subctx = accessSubcontext();
	TRACE("UI step %d", subctx->ui_step);
	TRACE_STACK_USAGE();
	ui_callback_fn_t* this_fn = handlePoolVrfKey_ui_runStep;

	UI_STEP_BEGIN(subctx->ui_step, this_fn);

	UI_STEP(HANDLE_POOL_VRF_KEY_STEP_DISPLAY) {
		#ifdef HAVE_BAGL
		ui_displayBech32Screen(
		        "VRF key hash",
		        "vrf_vk",
		        subctx->stateData.vrfKeyHash, SIZEOF(subctx->stateData.vrfKeyHash),
		        this_fn
		);
		#elif defined(HAVE_NBGL)
		char encodedStr[11 + BECH32_PREFIX_LENGTH_MAX + 2 * BECH32_BUFFER_SIZE_MAX] = {0};
		ui_getBech32Screen(
		        encodedStr, SIZEOF(encodedStr),
		        "vrf_vk",
		        subctx->stateData.vrfKeyHash, SIZEOF(subctx->stateData.vrfKeyHash));

		fill_and_display_if_required(
		        "VRF key hash",
		        encodedStr,
		        this_fn,
		        respond_with_user_reject);
		#endif // HAVE_BAGL
	}
	UI_STEP(HANDLE_POOL_VRF_KEY_STEP_RESPOND) {
		respondSuccessEmptyMsg();
		advanceState();
	}
	UI_STEP_END(HANDLE_POOL_VRF_KEY_STEP_INVALID);
}

// ============================== POOL FINANCIALS ==============================

void handlePoolFinancials_ui_runStep()
{
	pool_registration_context_t* subctx = accessSubcontext();
	TRACE("UI step %d", subctx->ui_step);
	TRACE_STACK_USAGE();
	ui_callback_fn_t* this_fn = handlePoolFinancials_ui_runStep;

	UI_STEP_BEGIN(subctx->ui_step, this_fn);

	UI_STEP(HANDLE_POOL_FINANCIALS_STEP_DISPLAY_PLEDGE) {
		#ifdef HAVE_BAGL
		ui_displayAdaAmountScreen(
		        "Pledge",
		        subctx->stateData.pledge,
		        this_fn
		);
		#elif defined(HAVE_NBGL)
		char adaAmountStr[50] = {0};
		ui_getAdaAmountScreen(
		        adaAmountStr, SIZEOF(adaAmountStr),
		        subctx->stateData.pledge
		);

		fill_and_display_if_required(
		        "Pledge",
		        adaAmountStr,
		        this_fn,
		        respond_with_user_reject
		);
		#endif // HAVE_BAGL
	}
	UI_STEP(HANDLE_POOL_FINANCIALS_STEP_DISPLAY_COST) {
		#ifdef HAVE_BAGL
		ui_displayAdaAmountScreen(
		        "Cost",
		        subctx->stateData.cost,
		        this_fn
		);
		#elif defined(HAVE_NBGL)
		char adaAmountStr[50] = {0};
		ui_getAdaAmountScreen(
		        adaAmountStr, SIZEOF(adaAmountStr),
		        subctx->stateData.cost
		);

		fill_and_display_if_required(
		        "Cost",
		        adaAmountStr,
		        this_fn,
		        respond_with_user_reject
		);
		#endif // HAVE_BAGL
	}
	UI_STEP(HANDLE_POOL_FINANCIALS_STEP_DISPLAY_MARGIN) {
		#ifdef HAVE_BAGL
		ui_displayPoolMarginScreen(
		        subctx->stateData.marginNumerator,
		        subctx->stateData.marginDenominator,
		        this_fn
		);
		#elif defined(HAVE_NBGL)
		char marginStr[20] = {0};
		ui_getPoolMarginScreen(
		        marginStr, SIZEOF(marginStr),
		        subctx->stateData.marginNumerator,
		        subctx->stateData.marginDenominator
		);
		fill_and_display_if_required(
		        "Profit margin",
		        marginStr,
		        this_fn,
		        respond_with_user_reject
		);
		#endif // HAVE_BAGL
	}
	UI_STEP(HANDLE_POOL_FINANCIALS_STEP_RESPOND) {
		respondSuccessEmptyMsg();
		advanceState();
	}
	UI_STEP_END(HANDLE_POOL_FINANCIALS_STEP_INVALID);
}

// ============================== POOL REWARD ACCOUNT ==============================

#ifdef HAVE_NBGL
static void handlePoolRewardAccount_ui_runStep_cb(void)
{
    force_display(handlePoolRewardAccount_ui_runStep, respond_with_user_reject);
}
#endif

void handlePoolRewardAccount_ui_runStep()
{
	pool_registration_context_t* subctx = accessSubcontext();
	TRACE("UI step %d", subctx->ui_step);
	TRACE_STACK_USAGE();
	ui_callback_fn_t* this_fn = handlePoolRewardAccount_ui_runStep;

	UI_STEP_BEGIN(subctx->ui_step, this_fn);

	UI_STEP(HANDLE_POOL_REWARD_ACCOUNT_STEP_DISPLAY) {
		#ifdef HAVE_BAGL
		ui_displayRewardAccountScreen(
		        &subctx->stateData.poolRewardAccount,
		        commonTxData->networkId,
		        this_fn
		);
		#elif defined(HAVE_NBGL)
		char firstLine[32] = {0};
		char secondLine[BIP44_PATH_STRING_SIZE_MAX + MAX_HUMAN_REWARD_ACCOUNT_SIZE + 2] = {0};
		ui_getRewardAccountScreen(
		        firstLine, SIZEOF(firstLine),
		        secondLine, SIZEOF(secondLine),
		        &subctx->stateData.poolRewardAccount,
		        commonTxData->networkId
		);
		fill_and_display_if_required(
		        firstLine,
		        secondLine,
		        handlePoolRewardAccount_ui_runStep_cb,
		        respond_with_user_reject
		);
		#endif // HAVE_BAGL
	}
	UI_STEP(HANDLE_POOL_REWARD_ACCOUNT_STEP_RESPOND) {
		respondSuccessEmptyMsg();
		advanceState();
	}
	UI_STEP_END(HANDLE_POOL_REWARD_ACCOUNT_STEP_INVALID);
}

// ============================== OWNER ==============================

void handleOwner_ui_runStep()
{
	pool_registration_context_t* subctx = accessSubcontext();
	TRACE("UI step %d", subctx->ui_step);
	TRACE_STACK_USAGE();
	ui_callback_fn_t* this_fn = handleOwner_ui_runStep;

	UI_STEP_BEGIN(subctx->ui_step, this_fn);

	UI_STEP(HANDLE_OWNER_STEP_DISPLAY) {
		#ifdef HAVE_BAGL
		ui_displayPoolOwnerScreen(&subctx->stateData.owner, subctx->currentOwner, commonTxData->networkId, this_fn);
		#elif defined(HAVE_NBGL)
		char firstLine[32] = {0};
		char secondLine[BIP44_PATH_STRING_SIZE_MAX + MAX_HUMAN_REWARD_ACCOUNT_SIZE + 2] = {0};
		ui_getPoolOwnerScreen(
		        firstLine, SIZEOF(firstLine),
		        secondLine, SIZEOF(secondLine),
		        &subctx->stateData.owner, subctx->currentOwner,
		        commonTxData->networkId
		);
		fill_and_display_if_required(
		        firstLine,
		        secondLine,
		        this_fn,
		        respond_with_user_reject
		);
		#endif // HAVE_BAGL
	}
	UI_STEP(HANDLE_OWNER_STEP_RESPOND) {
		respondSuccessEmptyMsg();

		subctx->currentOwner++;
		if (subctx->currentOwner == subctx->numOwners) {
			advanceState();
		}
	}
	UI_STEP_END(HANDLE_OWNER_STEP_INVALID);
}

// ============================== RELAY ==============================

void handleRelay_ip_ui_runStep()
{
	pool_registration_context_t* subctx = accessSubcontext();
	TRACE("UI step %d", subctx->ui_step);
	TRACE_STACK_USAGE();
	ui_callback_fn_t* this_fn = handleRelay_ip_ui_runStep;

	pool_relay_t* relay = &subctx->stateData.relay;

	UI_STEP_BEGIN(subctx->ui_step, this_fn);

	UI_STEP(HANDLE_RELAY_IP_STEP_DISPLAY_NUMBER) {
		#ifdef HAVE_BAGL
		ui_displayPoolRelayScreen(
		        relay,
		        subctx->currentRelay,
		        this_fn
		);
		#elif defined(HAVE_NBGL)
		char line[20] = {0};
		ui_getPoolRelayScreen(
		        line, SIZEOF(line),
		        subctx->currentRelay
		);
		fill_and_display_if_required("Relay index", line, this_fn, respond_with_user_reject);
		#endif // HAVE_BAGL
	}
	UI_STEP(HANDLE_RELAY_IP_STEP_DISPLAY_IPV4) {
		#ifdef HAVE_BAGL
		ui_displayIpv4Screen(
		        &relay->ipv4,
		        this_fn
		);
		#elif defined(HAVE_NBGL)
		char ipStr[IPV4_STR_SIZE_MAX + 1] = {0};
		ui_getIpv4Screen(
		        ipStr, SIZEOF(ipStr),
		        &relay->ipv4
		);
		fill_and_display_if_required(
		        "IPv4 address",
		        ipStr,
		        this_fn,
		        respond_with_user_reject
		);
		#endif // HAVE_BAGL
	}
	UI_STEP(HANDLE_RELAY_IP_STEP_DISPLAY_IPV6) {
		#ifdef HAVE_BAGL
		ui_displayIpv6Screen(
		        &relay->ipv6,
		        this_fn
		);
		#elif defined(HAVE_NBGL)
		char ipStr[IPV6_STR_SIZE_MAX + 1] = {0};
		ui_getIpv6Screen(
		        ipStr, SIZEOF(ipStr),
		        &relay->ipv6
		);
		fill_and_display_if_required(
		        "IPv6 address",
		        ipStr,
		        this_fn,
		        respond_with_user_reject
		);
		#endif // HAVE_BAGL
	}
	UI_STEP(HANDLE_RELAY_IP_STEP_DISPLAY_PORT) {
		#ifdef HAVE_BAGL
		ui_displayIpPortScreen(
		        &relay->port,
		        this_fn
		);
		#elif defined(HAVE_NBGL)
		char portStr[1 + (sizeof "65536")] = {0};
		ui_getIpPortScreen(
		        portStr, SIZEOF(portStr),
		        &relay->port
		);
		fill_and_display_if_required(
		        "Port",
		        portStr,
		        this_fn,
		        respond_with_user_reject
		);
		#endif // HAVE_BAGL
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

void handleRelay_dns_ui_runStep()
{
	pool_registration_context_t* subctx = accessSubcontext();
	TRACE("UI step %d", subctx->ui_step);
	TRACE_STACK_USAGE();
	ui_callback_fn_t* this_fn = handleRelay_dns_ui_runStep;

	pool_relay_t* relay = &subctx->stateData.relay;

	UI_STEP_BEGIN(subctx->ui_step, this_fn);

	UI_STEP(HANDLE_RELAY_DNS_STEP_DISPLAY_NUMBER) {
		#ifdef HAVE_BAGL
		ui_displayPoolRelayScreen(
		        relay,
		        subctx->currentRelay,
		        this_fn
		);
		#elif defined(HAVE_NBGL)
		char line[20] = {0};
		ui_getPoolRelayScreen(
		        line, SIZEOF(line),
		        subctx->currentRelay
		);
		fill_and_display_if_required("Relay index", line, this_fn, respond_with_user_reject);
		#endif // HAVE_BAGL
	}
	UI_STEP(HANDLE_RELAY_DNS_STEP_DISPLAY_DNSNAME) {
		char dnsNameStr[1 + DNS_NAME_SIZE_MAX] = {0};
		explicit_bzero(dnsNameStr, SIZEOF(dnsNameStr));
		ASSERT(relay->dnsNameSize <= DNS_NAME_SIZE_MAX);
		memmove(dnsNameStr, relay->dnsName, relay->dnsNameSize);
		dnsNameStr[relay->dnsNameSize] = '\0';
		ASSERT(strlen(dnsNameStr) == relay->dnsNameSize);

		#ifdef HAVE_BAGL
		ui_displayPaginatedText(
		        "DNS name",
		        dnsNameStr,
		        this_fn
		);
		#elif defined(HAVE_NBGL)
		fill_and_display_if_required(
		        "DNS name",
		        dnsNameStr,
		        this_fn,
		        respond_with_user_reject
		);
		#endif // HAVE_BAGL
	}
	UI_STEP(HANDLE_RELAY_DNS_STEP_DISPLAY_PORT) {
		if (relay->format == RELAY_MULTIPLE_HOST_NAME) {
			// nothing to display in this step, so we skip it
			UI_STEP_JUMP(HANDLE_RELAY_DNS_STEP_RESPOND);
		}

		#ifdef HAVE_BAGL
		ui_displayIpPortScreen(
		        &relay->port,
		        this_fn
		);
		#elif defined(HAVE_NBGL)
		char portStr[1 + (sizeof "65536")] = {0};
		ui_getIpPortScreen(
		        portStr, SIZEOF(portStr),
		        &relay->port
		);
		fill_and_display_if_required(
		        "Port",
		        portStr,
		        this_fn,
		        respond_with_user_reject
		);
		#endif // HAVE_BAGL
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


// ============================== METADATA ==============================

void handleNullMetadata_ui_runStep()
{
	pool_registration_context_t* subctx = accessSubcontext();
	TRACE("UI step %d", subctx->ui_step);
	TRACE_STACK_USAGE();
	ui_callback_fn_t* this_fn = handleNullMetadata_ui_runStep;

	UI_STEP_BEGIN(subctx->ui_step, this_fn);

	UI_STEP(HANDLE_NULL_METADATA_STEP_DISPLAY) {
		#ifdef HAVE_BAGL
		ui_displayPaginatedText(
		        "No metadata",
		        "(anonymous pool)",
		        this_fn
		);
		#elif defined(HAVE_NBGL)
		fill_and_display_if_required(
		        "Metadata",
		        "None: anymous pool",
		        this_fn,
		        respond_with_user_reject
		);
		#endif // HAVE_BAGL
	}
	UI_STEP(HANDLE_NULL_METADATA_STEP_RESPOND) {
		respondSuccessEmptyMsg();
		advanceState();
	}
	UI_STEP_END(HANDLE_NULL_METADATA_STEP_INVALID);
}

void handleMetadata_ui_runStep()
{
	pool_registration_context_t* subctx = accessSubcontext();
	TRACE("UI step %d", subctx->ui_step);
	TRACE_STACK_USAGE();
	ui_callback_fn_t* this_fn = handleMetadata_ui_runStep;

	pool_metadata_t* md = &subctx->stateData.metadata;

	UI_STEP_BEGIN(subctx->ui_step, this_fn);

	UI_STEP(HANDLE_METADATA_STEP_DISPLAY_URL) {
		char metadataUrlStr[1 + POOL_METADATA_URL_LENGTH_MAX] = {0};
		explicit_bzero(metadataUrlStr, SIZEOF(metadataUrlStr));
		ASSERT(md->urlSize <= POOL_METADATA_URL_LENGTH_MAX);
		memmove(metadataUrlStr, md->url, md->urlSize);
		metadataUrlStr[md->urlSize] = '\0';
		ASSERT(strlen(metadataUrlStr) == md->urlSize);

		#ifdef HAVE_BAGL
		ui_displayPaginatedText(
		        "Pool metadata url",
		        metadataUrlStr,
		        this_fn
		);
		#elif defined(HAVE_NBGL)
		fill_and_display_if_required(
		        "Pool metadata url",
		        metadataUrlStr,
		        this_fn,
		        respond_with_user_reject
		);
		#endif // HAVE_BAGL
	}
	UI_STEP(HANDLE_METADATA_STEP_DISPLAY_HASH) {
		char metadataHashHex[1 + 2 * POOL_METADATA_HASH_LENGTH] = {0};
		explicit_bzero(metadataHashHex, SIZEOF(metadataHashHex));
		size_t len = str_formatMetadata(
		                     md->hash, SIZEOF(md->hash),
		                     metadataHashHex, SIZEOF(metadataHashHex)
		             );
		ASSERT(len + 1 == SIZEOF(metadataHashHex));

		#ifdef HAVE_BAGL
		ui_displayPaginatedText(
		        "Pool metadata hash",
		        metadataHashHex,
		        this_fn
		);
		#elif defined(HAVE_NBGL)
		fill_and_display_if_required(
		        "Pool metadata hash",
		        metadataHashHex,
		        this_fn,
		        respond_with_user_reject
		);
		#endif // HAVE_BAGL
	}
	UI_STEP(HANDLE_METADATA_STEP_RESPOND) {
		respondSuccessEmptyMsg();
		advanceState();
	}
	UI_STEP_END(HANDLE_METADATA_STEP_INVALID);
}

// ============================== CONFIRM ==============================

void signTxPoolRegistration_handleConfirm_ui_runStep()
{
	pool_registration_context_t* subctx = accessSubcontext();
	TRACE("UI step %d", subctx->ui_step);
	TRACE_STACK_USAGE();
	ui_callback_fn_t* this_fn = signTxPoolRegistration_handleConfirm_ui_runStep;

	UI_STEP_BEGIN(subctx->ui_step, this_fn);

	// we display potentially suspicious facts about the certificate
	// that have not been explicitly shown to the user before:
	// missing owners or relays
	UI_STEP(HANDLE_CONFIRM_STEP_FINAL_NO_OWNERS) {
		if (subctx->numOwners == 0) {
			#ifdef HAVE_BAGL
			ui_displayPaginatedText(
			        "No",
			        "pool owners",
			        this_fn
			);
			#elif defined(HAVE_NBGL)
			fill_and_display_if_required(
			        "Pool owners",
			        "None",
			        this_fn,
			        respond_with_user_reject
			);
			#endif // HAVE_BAGL
		} else {
			UI_STEP_JUMP(HANDLE_CONFIRM_STEP_FINAL_NO_RELAYS);
		}
	}
	UI_STEP(HANDLE_CONFIRM_STEP_FINAL_NO_RELAYS) {
		bool isOperator = commonTxData->txSigningMode == SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OPERATOR;
		if ((subctx->numRelays == 0) && isOperator) {
			#ifdef HAVE_BAGL
			ui_displayPaginatedText(
			        "No",
			        "pool relays",
			        this_fn
			);
			#elif defined(HAVE_NBGL)
			fill_and_display_if_required(
			        "Pool relays",
			        "None",
			        this_fn,
			        respond_with_user_reject
			);
			#endif // HAVE_BAGL
		} else {
			UI_STEP_JUMP(HANDLE_CONFIRM_STEP_FINAL_CONFIRM);
		}
	}
	UI_STEP(HANDLE_CONFIRM_STEP_FINAL_CONFIRM) {
		#ifdef HAVE_BAGL
		ui_displayPrompt(
		        "Confirm stake",
		        "pool registration?",
		        this_fn,
		        respond_with_user_reject
		);
		#elif defined(HAVE_NBGL)
		display_confirmation(
		        "Confirm stake pool\nregistration",
		        "",
		        "STAKE POOL\nREGISTERED",
		        "Stake pool\nrejected",
		        this_fn,
		        respond_with_user_reject
		);
		#endif // HAVE_BAGL
	}
	UI_STEP(HANDLE_CONFIRM_STEP_RESPOND) {
		respondSuccessEmptyMsg();
		advanceState();
	}
	UI_STEP_END(HANDLE_CONFIRM_STEP_INVALID);
}
