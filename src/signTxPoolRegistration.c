#include "signTx.h"
#include "state.h"
#include "cardano.h"
#include "addressUtilsShelley.h"
#include "uiHelpers.h"
#include "signTxUtils.h"
#include "uiScreens.h"
#include "txHashBuilder.h"
#include "textUtils.h"
#include "hexUtils.h"
#include "messageSigning.h"
#include "bufView.h"
#include "securityPolicy.h"

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

	case STAKE_POOL_REGISTRATION_PARAMS:
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
	subctx->state = STAKE_POOL_REGISTRATION_PARAMS;
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

	case STAKE_POOL_REGISTRATION_PARAMS:
		subctx->state = STAKE_POOL_REGISTRATION_OWNERS;
		ASSERT(subctx->numOwners >= 1);

		txHashBuilder_addPoolRegistrationCertificate_enterOwners(txHashBuilder);
		break;

	case STAKE_POOL_REGISTRATION_OWNERS:
		ASSERT(subctx->currentOwner == subctx->numOwners);
		ASSERT(subctx->numOwnersGivenByPath == 1);

		subctx->state = STAKE_POOL_REGISTRATION_RELAYS;
		if (subctx->numRelays > 0) {
			txHashBuilder_addPoolRegistrationCertificate_enterRelays(txHashBuilder);
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


// ============================== POOL PARAMS ==============================

enum {
	HANDLE_POOLPARAMS_STEP_DISPLAY_OPERATION = 6300,
	HANDLE_POOLPARAMS_STEP_DISPLAY_POOL_KEY_HASH,
	HANDLE_POOLPARAMS_STEP_DISPLAY_PLEDGE,
	HANDLE_POOLPARAMS_STEP_DISPLAY_COST,
	HANDLE_POOLPARAMS_STEP_DISPLAY_MARGIN,
	HANDLE_POOLPARAMS_STEP_DISPLAY_REWARD_ACCOUNT,
	HANDLE_POOLPARAMS_STEP_RESPOND,
	HANDLE_POOLPARAMS_STEP_INVALID,
} ;

static void handlePoolParams_ui_runStep()
{
	TRACE("UI step %d", subctx->ui_step);
	ui_callback_fn_t* this_fn = handlePoolParams_ui_runStep;

	UI_STEP_BEGIN(subctx->ui_step);
	UI_STEP(HANDLE_POOLPARAMS_STEP_DISPLAY_OPERATION) {
		ui_displayPaginatedText(
		        "Pool registration",
		        "certificate",
		        this_fn
		);
	}
	UI_STEP(HANDLE_POOLPARAMS_STEP_DISPLAY_POOL_KEY_HASH) {
		ui_displayHexBufferScreen(
		        "Pool ID",
		        subctx->poolParams.poolKeyHash, SIZEOF(subctx->poolParams.poolKeyHash),
		        this_fn
		);
	}
	UI_STEP(HANDLE_POOLPARAMS_STEP_DISPLAY_PLEDGE) {
		ui_displayAmountScreen(
		        "Pledge",
		        subctx->poolParams.pledge,
		        this_fn
		);
	}
	UI_STEP(HANDLE_POOLPARAMS_STEP_DISPLAY_COST) {
		ui_displayAmountScreen(
		        "Cost",
		        subctx->poolParams.cost,
		        this_fn
		);
	}
	UI_STEP(HANDLE_POOLPARAMS_STEP_DISPLAY_MARGIN) {
		ui_displayMarginScreen(
		        subctx->poolParams.marginNumerator,
		        subctx->poolParams.marginDenominator,
		        this_fn
		);
	}
	UI_STEP(HANDLE_POOLPARAMS_STEP_DISPLAY_REWARD_ACCOUNT) {
		ui_displayAddressScreen(
		        "Reward account",
		        subctx->poolParams.rewardAccount,
		        SIZEOF(subctx->poolParams.rewardAccount),
		        this_fn
		);
	}
	UI_STEP(HANDLE_POOLPARAMS_STEP_RESPOND) {
		respondSuccessEmptyMsg();
		advanceState();
	}
	UI_STEP_END(HANDLE_POOLPARAMS_STEP_INVALID);
}

static void signTxPoolRegistration_handlePoolParamsAPDU(uint8_t* wireDataBuffer, size_t wireDataSize)
{
	{
		// sanity checks
		CHECK_STATE(STAKE_POOL_REGISTRATION_PARAMS);

		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}
	{
		// initialization
		subctx->currentOwner = 0;
		subctx->currentRelay = 0;

		explicit_bzero(&subctx->poolParams, SIZEOF(subctx->poolParams));
	}
	{
		// parse data

		TRACE_BUFFER(wireDataBuffer, wireDataSize);

		struct {
			uint8_t poolKeyHash[POOL_KEY_HASH_LENGTH];
			uint8_t vrfKeyHash[VRF_KEY_HASH_LENGTH];
			uint8_t pledge[8];
			uint8_t cost[8];
			uint8_t marginNumerator[8];
			uint8_t marginDenominator[8];
			uint8_t rewardAccount[1 + ADDRESS_KEY_HASH_LENGTH];

			uint8_t numOwners[4];
			uint8_t numRelays[4];
		}* wireHeader = (void*) wireDataBuffer;

		TRACE("%d %d", SIZEOF(*wireHeader), wireDataSize);
		VALIDATE(SIZEOF(*wireHeader) == wireDataSize, ERR_INVALID_DATA);

		{
			pool_registration_params_t* p = &subctx->poolParams;

			TRACE_BUFFER(wireHeader->poolKeyHash, SIZEOF(wireHeader->poolKeyHash));
			STATIC_ASSERT(SIZEOF(wireHeader->poolKeyHash) == SIZEOF(p->poolKeyHash), "wrong poolKeyHash size");
			os_memmove(p->poolKeyHash, wireHeader->poolKeyHash, SIZEOF(p->poolKeyHash));
			// nothing to validate, all values are valid

			TRACE_BUFFER(wireHeader->vrfKeyHash, SIZEOF(wireHeader->vrfKeyHash));
			STATIC_ASSERT(SIZEOF(wireHeader->vrfKeyHash) == SIZEOF(p->vrfKeyHash), "wrong vrfKeyHash size");
			os_memmove(p->vrfKeyHash, wireHeader->vrfKeyHash, SIZEOF(p->vrfKeyHash));
			// nothing to validate, all values are valid

			ASSERT_TYPE(p->pledge, uint64_t);
			p->pledge = u8be_read(wireHeader->pledge);
			TRACE_ADA_AMOUNT("pledge ", p->pledge);
			VALIDATE(p->pledge < LOVELACE_MAX_SUPPLY, ERR_INVALID_DATA);

			ASSERT_TYPE(p->cost, uint64_t);
			p->cost = u8be_read(wireHeader->cost);
			TRACE_ADA_AMOUNT("cost ", p->cost);
			VALIDATE(p->cost < LOVELACE_MAX_SUPPLY, ERR_INVALID_DATA);

			ASSERT_TYPE(p->marginNumerator, uint64_t);
			p->marginNumerator = u8be_read(wireHeader->marginNumerator);
			TRACE_BUFFER((uint8_t *) &p->marginNumerator, 8);
			VALIDATE(p->marginNumerator <= MARGIN_DENOMINATOR_MAX, ERR_INVALID_DATA);

			ASSERT_TYPE(p->marginDenominator, uint64_t);
			p->marginDenominator = u8be_read(wireHeader->marginDenominator);
			TRACE_BUFFER((uint8_t *) &p->marginDenominator, 8);
			VALIDATE(p->marginDenominator != 0, ERR_INVALID_DATA);
			VALIDATE(p->marginDenominator <= MARGIN_DENOMINATOR_MAX, ERR_INVALID_DATA);
			VALIDATE(p->marginNumerator <= p->marginDenominator, ERR_INVALID_DATA);

			TRACE_BUFFER(wireHeader->rewardAccount, SIZEOF(wireHeader->rewardAccount));
			STATIC_ASSERT(SIZEOF(wireHeader->rewardAccount) == SIZEOF(p->rewardAccount), "wrong reward account size");
			os_memmove(p->rewardAccount, wireHeader->rewardAccount, SIZEOF(p->rewardAccount));
			const uint8_t header = getAddressHeader(p->rewardAccount, SIZEOF(p->rewardAccount));
			VALIDATE(getAddressType(header) == REWARD, ERR_INVALID_DATA);
			VALIDATE(getNetworkId(header) == commonTxData->networkId, ERR_INVALID_DATA);
		}

		ASSERT_TYPE(subctx->numOwners, uint16_t);
		ASSERT_TYPE(subctx->numRelays, uint16_t);
		subctx->numOwners = (uint16_t) u4be_read(wireHeader->numOwners);
		subctx->numRelays = (uint16_t) u4be_read(wireHeader->numRelays);

		TRACE(
		        "num owners, relays: %d %d",
		        subctx->numOwners, subctx->numRelays
		);
		VALIDATE(subctx->numOwners <= POOL_MAX_OWNERS, ERR_INVALID_DATA);
		VALIDATE(subctx->numRelays <= POOL_MAX_RELAYS, ERR_INVALID_DATA);

		// there should be exactly one owner given by path for which we provide a witness
		VALIDATE(subctx->numOwners >= 1, ERR_INVALID_DATA);
	}

	// Note: make sure that everything in subctx is initialized properly
	txHashBuilder_addPoolRegistrationCertificate(
	        txHashBuilder,
	        &subctx->poolParams,
	        subctx->numOwners, subctx->numRelays
	);

	security_policy_t policy = policyForSignTxCertificateStakePoolRegistration();
	TRACE("Policy: %d", (int) policy);
	ENSURE_NOT_DENIED(policy);
	{
		// select UI steps
		switch (policy) {
#	define  CASE(POLICY, UI_STEP) case POLICY: {subctx->ui_step=UI_STEP; break;}
			CASE(POLICY_PROMPT_BEFORE_RESPONSE, HANDLE_POOLPARAMS_STEP_DISPLAY_OPERATION);
			CASE(POLICY_ALLOW_WITHOUT_PROMPT,   HANDLE_POOLPARAMS_STEP_RESPOND);
#	undef   CASE
		default:
			THROW(ERR_NOT_IMPLEMENTED);
		}
	}

	handlePoolParams_ui_runStep();
}

// ============================== OWNER ==============================

enum {
	HANDLE_OWNER_STEP_DISPLAY = 6320,
	HANDLE_OWNER_STEP_RESPOND,
	HANDLE_OWNER_STEP_INVALID,
};

static void handleOwner_ui_runStep()
{
	TRACE("UI step %d", subctx->ui_step);
	ui_callback_fn_t* this_fn = handleOwner_ui_runStep;

	UI_STEP_BEGIN(subctx->ui_step);

	UI_STEP(HANDLE_OWNER_STEP_DISPLAY) {
		ui_displayOwnerScreen(&subctx->owner, subctx->currentOwner, commonTxData->networkId, this_fn);
	}
	UI_STEP(HANDLE_OWNER_STEP_RESPOND) {
		respondSuccessEmptyMsg();

		subctx->currentOwner++;
		if (subctx->currentOwner == subctx->numOwners) {
			VALIDATE(subctx->numOwnersGivenByPath == 1, ERR_INVALID_DATA);

			advanceState();
		}
	}
	UI_STEP_END(HANDLE_OWNER_STEP_INVALID);
}

static void signTxPoolRegistration_handleOwnerAPDU(uint8_t* wireDataBuffer, size_t wireDataSize)
{
	{
		// sanity checks
		CHECK_STATE(STAKE_POOL_REGISTRATION_OWNERS);

		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}

	explicit_bzero(&subctx->owner, SIZEOF(subctx->owner));

	{
		// parse data
		TRACE_BUFFER(wireDataBuffer, wireDataSize);

		read_view_t view = make_read_view(wireDataBuffer, wireDataBuffer + wireDataSize);

		VALIDATE(view_remainingSize(&view) >= 1, ERR_INVALID_DATA);
		subctx->owner.ownerType = parse_u1be(&view);
		switch (subctx->owner.ownerType) {

		case SIGN_TX_POOL_OWNER_TYPE_KEY_HASH:
			VALIDATE(view_remainingSize(&view) == ADDRESS_KEY_HASH_LENGTH, ERR_INVALID_DATA);
			STATIC_ASSERT(SIZEOF(subctx->owner.keyHash) == ADDRESS_KEY_HASH_LENGTH, "wrong owner.keyHash size");
			os_memmove(subctx->owner.keyHash, VIEW_REMAINING_TO_TUPLE_BUF_SIZE(&view));
			TRACE_BUFFER(subctx->owner.keyHash, SIZEOF(subctx->owner.keyHash));
			break;

		case SIGN_TX_POOL_OWNER_TYPE_PATH:
			view_skipBytes(&view, bip44_parseFromWire(&subctx->owner.path, VIEW_REMAINING_TO_TUPLE_BUF_SIZE(&view)));
			// further validation of the path in security policy below
			TRACE("Owner given by path:");
			BIP44_PRINTF(&subctx->owner.path);
			PRINTF("\n");
			VALIDATE(view_remainingSize(&view) == 0, ERR_INVALID_DATA);

			subctx->numOwnersGivenByPath++;
			VALIDATE(subctx->numOwnersGivenByPath <= 1, ERR_INVALID_DATA);

			break;

		default:
			THROW(ERR_INVALID_DATA);
		}
	}

	security_policy_t policy = POLICY_DENY;
	switch (subctx->owner.ownerType) {
	case SIGN_TX_POOL_OWNER_TYPE_KEY_HASH:
		policy = policyForSignTxStakePoolRegistrationOwnerByKeyHash();
		break;

	case SIGN_TX_POOL_OWNER_TYPE_PATH:
		policy = policyForSignTxStakePoolRegistrationOwnerByPath(&subctx->owner.path);
		break;

	default:
		ASSERT(false);
	}
	TRACE("Policy: %d", (int) policy);
	ENSURE_NOT_DENIED(policy);

	{
		// compute key hash if needed
		if (subctx->owner.ownerType == SIGN_TX_POOL_OWNER_TYPE_PATH) {
			write_view_t view = make_write_view(subctx->owner.keyHash, subctx->owner.keyHash + SIZEOF(subctx->owner.keyHash));
			view_appendPublicKeyHash(&view, &subctx->owner.path);
		}
	}

	{
		// add data to tx
		TRACE("Adding owner to tx hash");
		txHashBuilder_addPoolRegistrationCertificate_addOwner(
		        txHashBuilder,
		        subctx->owner.keyHash, SIZEOF(subctx->owner.keyHash)
		);
		TRACE();
	}

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
	RELAY_SINGLE_HOST_IP = 0,
	RELAY_SINGLE_HOST_NAME = 1,
	RELAY_MULTIPLE_HOST_NAME = 2
};

enum {
	RELAY_NO = 1,
	RELAY_YES = 2
};

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
static void signTxPoolRegistration_handleRelayAPDU(uint8_t* wireDataBuffer, size_t wireDataSize)
{
	{
		// sanity checks
		CHECK_STATE(STAKE_POOL_REGISTRATION_RELAYS);

		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}

	{
		// parse data and add it to tx
		TRACE_BUFFER(wireDataBuffer, wireDataSize);

		read_view_t view = make_read_view(wireDataBuffer, wireDataBuffer + wireDataSize);

		VALIDATE(view_remainingSize(&view) >= 1, ERR_INVALID_DATA);
		uint8_t format = parse_u1be(&view);
		TRACE("Relay format %u", format);
		switch (format) {

		case RELAY_SINGLE_HOST_IP: {
			uint16_t port;
			uint16_t *portPtr = NULL;
			{
				VALIDATE(view_remainingSize(&view) >= 1, ERR_INVALID_DATA);
				uint8_t includePort = parse_u1be(&view);
				if (includePort == RELAY_YES) {
					port = parse_u2be(&view);
					TRACE("Port: %u", port);
					portPtr = &port;
				} else {
					VALIDATE(includePort == RELAY_NO, ERR_INVALID_DATA);
				}
			}

			ipv4_t ipv4;
			ipv4_t* ipv4Ptr = NULL;
			{
				VALIDATE(view_remainingSize(&view) >= 1, ERR_INVALID_DATA);
				uint8_t includeIpv4 = parse_u1be(&view);
				if (includeIpv4 == RELAY_YES) {
					VALIDATE(view_remainingSize(&view) >= IPV4_SIZE, ERR_INVALID_DATA);
					STATIC_ASSERT(sizeof(ipv4.ip) == IPV4_SIZE, "wrong ipv4 size"); // SIZEOF does not work for 4-byte buffers
					view_memmove(ipv4.ip, &view, IPV4_SIZE);
					TRACE("ipv4");
					TRACE_BUFFER(ipv4.ip, IPV4_SIZE);
					ipv4Ptr = &ipv4;
				} else {
					VALIDATE(includeIpv4 == RELAY_NO, ERR_INVALID_DATA);
				}
			}

			ipv6_t ipv6;
			ipv6_t* ipv6Ptr = NULL;
			{
				VALIDATE(view_remainingSize(&view) >= 1, ERR_INVALID_DATA);
				uint8_t includeIpv6 = parse_u1be(&view);
				if (includeIpv6 == RELAY_YES) {
					VALIDATE(view_remainingSize(&view) >= IPV6_SIZE, ERR_INVALID_DATA);
					STATIC_ASSERT(SIZEOF(ipv6.ip) == IPV6_SIZE, "wrong ipv6 size");
					view_memmove(ipv6.ip, &view, IPV6_SIZE);
					TRACE("ipv6");
					TRACE_BUFFER(ipv6.ip, IPV6_SIZE);
					ipv6Ptr = &ipv6;
				} else {
					VALIDATE(includeIpv6 == RELAY_NO, ERR_INVALID_DATA);
				}
			}

			VALIDATE(view_remainingSize(&view) == 0, ERR_INVALID_DATA);

			TRACE("Adding relay format 0 to tx hash");
			txHashBuilder_addPoolRegistrationCertificate_addRelay0(
			        txHashBuilder, portPtr, ipv4Ptr, ipv6Ptr
			);
			break;
		}

		case RELAY_SINGLE_HOST_NAME: {
			uint16_t port;
			uint16_t *portPtr = NULL;
			{
				VALIDATE(view_remainingSize(&view) >= 1, ERR_INVALID_DATA);
				uint8_t includePort = parse_u1be(&view);
				if (includePort == RELAY_YES) {
					port = parse_u2be(&view);
					TRACE("Port: %u", port);
					portPtr = &port;
				} else {
					VALIDATE(includePort == RELAY_NO, ERR_INVALID_DATA);
				}
			}

			VALIDATE(view_remainingSize(&view) <= DNS_NAME_MAX_LENGTH, ERR_INVALID_DATA);
			str_validateTextBuffer(VIEW_REMAINING_TO_TUPLE_BUF_SIZE(&view));

			TRACE("Adding relay format 1 to tx hash");
			txHashBuilder_addPoolRegistrationCertificate_addRelay1(
			        txHashBuilder,
			        portPtr,
			        VIEW_REMAINING_TO_TUPLE_BUF_SIZE(&view)
			);
			break;
		}

		case RELAY_MULTIPLE_HOST_NAME: {
			VALIDATE(view_remainingSize(&view) <= DNS_NAME_MAX_LENGTH, ERR_INVALID_DATA);
			str_validateTextBuffer(VIEW_REMAINING_TO_TUPLE_BUF_SIZE(&view));

			TRACE("Adding relay format 2 to tx hash");
			txHashBuilder_addPoolRegistrationCertificate_addRelay2(
			        txHashBuilder,
			        VIEW_REMAINING_TO_TUPLE_BUF_SIZE(&view)
			);
			break;
		}

		default:
			THROW(ERR_INVALID_DATA);
		}
	}

	respondSuccessEmptyMsg();

	{
		subctx->currentRelay++;
		TRACE("current relay %d", subctx->currentRelay);

		if (subctx->currentRelay == subctx->numRelays) {
			advanceState();
		}
	}
}


// ============================== METADATA ==============================

enum {
	HANDLE_NULL_METADATA_STEP_DISPLAY = 6340,
	HANDLE_NULL_METADATA_STEP_RESPOND,
	HANDLE_NULL_METADATA_STEP_INVALID,
};

static void handleNullMetadata_ui_runStep()
{
	TRACE("UI step %d", subctx->ui_step);
	ui_callback_fn_t* this_fn = handleNullMetadata_ui_runStep;

	UI_STEP_BEGIN(subctx->ui_step);

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
	HANDLE_METADATA_STEP_DISPLAY_URL = 6350,
	HANDLE_METADATA_STEP_DISPLAY_HASH,
	HANDLE_METADATA_STEP_RESPOND,
	HANDLE_METADATA_STEP_INVALID,
};

static void handleMetadata_ui_runStep()
{
	TRACE("UI step %d", subctx->ui_step);
	ui_callback_fn_t* this_fn = handleMetadata_ui_runStep;

	pool_metadata_t* md = &subctx->metadata;

	UI_STEP_BEGIN(subctx->ui_step);

	UI_STEP(HANDLE_METADATA_STEP_DISPLAY_URL) {
		char metadataUrlStr[1 + POOL_METADATA_URL_MAX_LENGTH];
		ASSERT(md->urlSize <= POOL_METADATA_URL_MAX_LENGTH);
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

enum {
	POOL_CERTIFICATE_METADATA_NO = 1,
	POOL_CERTIFICATE_METADATA_YES = 2
};

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

static void signTxPoolRegistration_handlePoolMetadataAPDU(uint8_t* wireDataBuffer, size_t wireDataSize)
{
	{
		// sanity checks
		CHECK_STATE(STAKE_POOL_REGISTRATION_METADATA);

		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}

	explicit_bzero(&subctx->metadata, SIZEOF(subctx->metadata));

	{
		// parse data
		TRACE_BUFFER(wireDataBuffer, wireDataSize);

		pool_metadata_t* md = &subctx->metadata;

		read_view_t view = make_read_view(wireDataBuffer, wireDataBuffer + wireDataSize);

		{
			// deal with null metadata

			VALIDATE(view_remainingSize(&view) >= 1, ERR_INVALID_DATA);
			int includeMetadata = parse_u1be(&view);

			if (includeMetadata == POOL_CERTIFICATE_METADATA_NO) {
				VALIDATE(view_remainingSize(&view) == 0, ERR_INVALID_DATA);
				handleNullMetadata();
				return;
			} else {
				VALIDATE(includeMetadata == POOL_CERTIFICATE_METADATA_YES, ERR_INVALID_DATA);
			}
		}
		{
			VALIDATE(view_remainingSize(&view) >= METADATA_HASH_LENGTH, ERR_INVALID_DATA);
			ASSERT(SIZEOF(md->hash) == METADATA_HASH_LENGTH);
			view_memmove(md->hash, &view, METADATA_HASH_LENGTH);
		}
		{
			md->urlSize = view_remainingSize(&view);
			VALIDATE(md->urlSize <= POOL_METADATA_URL_MAX_LENGTH, ERR_INVALID_DATA);
			ASSERT(SIZEOF(md->url) >= md->urlSize);
			view_memmove(md->url, &view, md->urlSize);
			str_validateTextBuffer(md->url, md->urlSize);
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
		        subctx->metadata.url, subctx->metadata.urlSize,
		        subctx->metadata.hash, SIZEOF(subctx->metadata.hash)
		);
	}

	handleMetadata_ui_runStep();
}

// ============================== CONFIRM ==============================

enum {
	HANDLE_CONFIRM_STEP_FINAL_CONFIRM = 6360,
	HANDLE_CONFIRM_STEP_RESPOND,
	HANDLE_CONFIRM_STEP_INVALID,
};

static void signTxPoolRegistration_handleConfirm_ui_runStep()
{
	TRACE("UI step %d", subctx->ui_step);
	ui_callback_fn_t* this_fn = signTxPoolRegistration_handleConfirm_ui_runStep;

	UI_STEP_BEGIN(subctx->ui_step);

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

static void signTxPoolRegistration_handleConfirmAPDU(uint8_t* wireDataBuffer MARK_UNUSED, size_t wireDataSize)
{
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
	APDU_INSTRUCTION_PARAMS = 0x30,
	APDU_INSTRUCTION_OWNERS = 0x31,
	APDU_INSTRUCTION_RELAYS = 0x32,
	APDU_INSTRUCTION_METADATA = 0x33,
	APDU_INSTRUCTION_CONFIRMATION = 0x34
};

bool signTxPoolRegistration_isValidInstruction(uint8_t p2)
{
	switch (p2) {
	case APDU_INSTRUCTION_PARAMS:
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
	TRACE("p2 = %d", p2);

	switch (p2) {
	case APDU_INSTRUCTION_PARAMS:
		signTxPoolRegistration_handlePoolParamsAPDU(wireDataBuffer, wireDataSize);
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
