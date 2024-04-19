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

#ifdef HAVE_BAGL
#include "uiScreens_bagl.h"
#elif defined(HAVE_NBGL)
#include "uiScreens_nbgl.h"
#endif

static ins_sign_tx_context_t* ctx = &(instructionState.signTxContext);
static common_tx_data_t* commonTxData = &(instructionState.signTxContext.commonTxData);

static pool_registration_context_t* accessSubcontext()
{
	return &BODY_CTX->stageContext.pool_registration_subctx;
}

bool signTxPoolRegistration_isFinished()
{
	// we are also asserting that the state is valid
	switch (accessSubcontext()->state) {
	case STAKE_POOL_REGISTRATION_FINISHED:
		return true;

	case STAKE_POOL_REGISTRATION_INIT:
	case STAKE_POOL_REGISTRATION_POOL_KEY:
	case STAKE_POOL_REGISTRATION_VRF_KEY:
	case STAKE_POOL_REGISTRATION_FINANCIALS:
	case STAKE_POOL_REGISTRATION_REWARD_ACCOUNT:
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
	explicit_bzero(&BODY_CTX->stageContext, SIZEOF(BODY_CTX->stageContext));

	accessSubcontext()->state = STAKE_POOL_REGISTRATION_INIT;
}

static inline void CHECK_STATE(sign_tx_pool_registration_state_t expected)
{
	pool_registration_context_t* subctx = accessSubcontext();
	TRACE("Pool registration certificate stage: current %d, expected %d", subctx->state, expected);
	VALIDATE(subctx->state == expected, ERR_INVALID_STATE);
}

// ============================== INIT ==============================

__noinline_due_to_stack__
static void signTxPoolRegistration_handleInitAPDU(const uint8_t* wireDataBuffer, size_t wireDataSize)
{
	TRACE_STACK_USAGE();
	{
		// sanity checks
		CHECK_STATE(STAKE_POOL_REGISTRATION_INIT);

		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}
	pool_registration_context_t* subctx = accessSubcontext();
	{
		// initialization
		subctx->currentOwner = 0;
		subctx->currentRelay = 0;

		explicit_bzero(&subctx->stateData, SIZEOF(subctx->stateData));
	}
	{
		// parse data
		TRACE_BUFFER(wireDataBuffer, wireDataSize);

		struct {
			uint8_t numOwners[4];
			uint8_t numRelays[4];
		}* wireHeader = (void*) wireDataBuffer;

		// can't use SIZEOF because it fails for x86 for fuzzing
		VALIDATE(wireDataSize == sizeof(*wireHeader), ERR_INVALID_DATA);

		uint64_t numOwners = u4be_read(wireHeader->numOwners);
		uint64_t numRelays = u4be_read(wireHeader->numRelays);
		TRACE(
		        "num owners, relays: %d %d",
		        subctx->numOwners, subctx->numRelays
		);

		VALIDATE(subctx->numOwners <= POOL_MAX_OWNERS, ERR_INVALID_DATA);
		VALIDATE(subctx->numRelays <= POOL_MAX_RELAYS, ERR_INVALID_DATA);
		ASSERT_TYPE(subctx->numOwners, uint16_t);
		ASSERT_TYPE(subctx->numRelays, uint16_t);
		subctx->numOwners = (uint16_t) numOwners;
		subctx->numRelays = (uint16_t) numRelays;
	}
	{
		security_policy_t policy = policyForSignTxStakePoolRegistrationInit(
		                                   commonTxData->txSigningMode,
		                                   subctx->numOwners
		                           );
		TRACE("Policy: %d", (int) policy);
		ENSURE_NOT_DENIED(policy);
	}
	{
		txHashBuilder_poolRegistrationCertificate_enter(
		        &BODY_CTX->txHashBuilder,
		        subctx->numOwners, subctx->numRelays
		);
	}

	subctx->ui_step = HANDLE_POOL_INIT_STEP_DISPLAY;
	handlePoolInit_ui_runStep();
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

static void _parsePoolId(read_view_t* view)
{
	pool_id_t* key = &accessSubcontext()->stateData.poolId;

	key->keyReferenceType = parse_u1be(view);

	switch (key->keyReferenceType) {

	case KEY_REFERENCE_HASH: {
		STATIC_ASSERT(SIZEOF(key->hash) == POOL_KEY_HASH_LENGTH, "wrong pool id key hash size");
		view_parseBuffer(key->hash, view, POOL_KEY_HASH_LENGTH);
		TRACE_BUFFER(key->hash, SIZEOF(key->hash));
		break;
	}

	case KEY_REFERENCE_PATH: {
		view_skipBytes(view, bip44_parseFromWire(&key->path, VIEW_REMAINING_TO_TUPLE_BUF_SIZE(view)));
		BIP44_PRINTF(&key->path);
		PRINTF("\n");
		break;
	}

	default:
		THROW(ERR_INVALID_DATA);
	}
}

__noinline_due_to_stack__
static void signTxPoolRegistration_handlePoolKeyAPDU(const uint8_t* wireDataBuffer, size_t wireDataSize)
{
	TRACE_STACK_USAGE();
	{
		// sanity checks
		CHECK_STATE(STAKE_POOL_REGISTRATION_POOL_KEY);

		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}
	{
		// parse data

		TRACE_BUFFER(wireDataBuffer, wireDataSize);

		read_view_t view = make_read_view(wireDataBuffer, wireDataBuffer + wireDataSize);

		_parsePoolId(&view);

		VALIDATE(view_remainingSize(&view) == 0, ERR_INVALID_DATA);
	}

	pool_registration_context_t* subctx = accessSubcontext();
	security_policy_t policy = policyForSignTxStakePoolRegistrationPoolId(
	                                   commonTxData->txSigningMode,
	                                   &subctx->stateData.poolId
	                           );
	TRACE("Policy: %d", (int) policy);
	ENSURE_NOT_DENIED(policy);

	{
		// key derivation must not be done before DENY security policy is enforced
		uint8_t poolKeyHash[POOL_KEY_HASH_LENGTH] = {0};
		_toPoolKeyHash(&subctx->stateData.poolId, poolKeyHash);

		txHashBuilder_poolRegistrationCertificate_poolKeyHash(
		        &BODY_CTX->txHashBuilder,
		        poolKeyHash, SIZEOF(poolKeyHash)
		);
	}
	{
		// ui step depends not only on security policy, but also on signing mode
		int displayUiStep = HANDLE_POOL_KEY_STEP_INVALID;
		switch (commonTxData->txSigningMode) {
		case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OWNER:
			displayUiStep = HANDLE_POOL_KEY_STEP_DISPLAY_POOL_ID;
			break;

		case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OPERATOR:
			displayUiStep = HANDLE_POOL_KEY_STEP_DISPLAY_POOL_PATH;
			break;

		default:
			ASSERT(false);
		}
		ASSERT(displayUiStep != HANDLE_POOL_KEY_STEP_INVALID);

		// select UI steps
		switch (policy) {
#define  CASE(POLICY, UI_STEP) case POLICY: {subctx->ui_step=UI_STEP; break;}
			CASE(POLICY_SHOW_BEFORE_RESPONSE, displayUiStep);
			CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_POOL_KEY_STEP_RESPOND);
#undef   CASE
		default:
			THROW(ERR_NOT_IMPLEMENTED);
		}
	}

	handlePoolKey_ui_runStep();
}

// ============================== VRF KEY HASH ==============================

__noinline_due_to_stack__
static void signTxPoolRegistration_handleVrfKeyAPDU(const uint8_t* wireDataBuffer, size_t wireDataSize)
{
	TRACE_STACK_USAGE();
	{
		// sanity checks
		CHECK_STATE(STAKE_POOL_REGISTRATION_VRF_KEY);

		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}
	pool_registration_context_t* subctx = accessSubcontext();
	{
		// parse data

		TRACE_BUFFER(wireDataBuffer, wireDataSize);

		VALIDATE(wireDataSize == SIZEOF(subctx->stateData.vrfKeyHash), ERR_INVALID_DATA);

		{
			STATIC_ASSERT(SIZEOF(subctx->stateData.vrfKeyHash) == VRF_KEY_HASH_LENGTH, "wrong vrfKeyHash size");
			memmove(subctx->stateData.vrfKeyHash, wireDataBuffer, VRF_KEY_HASH_LENGTH);
			// nothing to validate, all values are valid
		}
	}

	security_policy_t policy = policyForSignTxStakePoolRegistrationVrfKey(
	                                   commonTxData->txSigningMode
	                           );
	TRACE("Policy: %d", (int) policy);
	ENSURE_NOT_DENIED(policy);

	{
		txHashBuilder_poolRegistrationCertificate_vrfKeyHash(
		        &BODY_CTX->txHashBuilder,
		        subctx->stateData.vrfKeyHash, SIZEOF(subctx->stateData.vrfKeyHash)
		);
	}

	{
		// select UI steps
		switch (policy) {
#define  CASE(POLICY, UI_STEP) case POLICY: {subctx->ui_step=UI_STEP; break;}
			CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_POOL_VRF_KEY_STEP_DISPLAY);
			CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_POOL_VRF_KEY_STEP_RESPOND);
#undef   CASE
		default:
			THROW(ERR_NOT_IMPLEMENTED);
		}
	}

	handlePoolVrfKey_ui_runStep();
}

// ============================== POOL FINANCIALS ==============================

__noinline_due_to_stack__
static void signTxPoolRegistration_handlePoolFinancialsAPDU(const uint8_t* wireDataBuffer, size_t wireDataSize)
{
	TRACE_STACK_USAGE();
	{
		// sanity checks
		CHECK_STATE(STAKE_POOL_REGISTRATION_FINANCIALS);

		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}
	pool_registration_context_t* subctx = accessSubcontext();
	{
		// parse data

		TRACE_BUFFER(wireDataBuffer, wireDataSize);

		struct {
			uint8_t pledge[8];
			uint8_t cost[8];
			uint8_t marginNumerator[8];
			uint8_t marginDenominator[8];
		}* wireHeader = (void*) wireDataBuffer;

		VALIDATE(wireDataSize == SIZEOF(*wireHeader), ERR_INVALID_DATA);

		{
			ASSERT_TYPE(subctx->stateData.pledge, uint64_t);
			subctx->stateData.pledge = u8be_read(wireHeader->pledge);
			TRACE_ADA_AMOUNT("pledge ", subctx->stateData.pledge);
			VALIDATE(subctx->stateData.pledge < LOVELACE_MAX_SUPPLY, ERR_INVALID_DATA);

			ASSERT_TYPE(subctx->stateData.cost, uint64_t);
			subctx->stateData.cost = u8be_read(wireHeader->cost);
			TRACE_ADA_AMOUNT("cost ", subctx->stateData.cost);
			VALIDATE(subctx->stateData.cost < LOVELACE_MAX_SUPPLY, ERR_INVALID_DATA);

			ASSERT_TYPE(subctx->stateData.marginNumerator, uint64_t);
			subctx->stateData.marginNumerator = u8be_read(wireHeader->marginNumerator);
			TRACE_BUFFER((uint8_t*) &subctx->stateData.marginNumerator, 8);
			VALIDATE(subctx->stateData.marginNumerator <= MARGIN_DENOMINATOR_MAX, ERR_INVALID_DATA);

			ASSERT_TYPE(subctx->stateData.marginDenominator, uint64_t);
			subctx->stateData.marginDenominator = u8be_read(wireHeader->marginDenominator);
			TRACE_BUFFER((uint8_t*) &subctx->stateData.marginDenominator, 8);
			VALIDATE(subctx->stateData.marginDenominator != 0, ERR_INVALID_DATA);
			VALIDATE(subctx->stateData.marginDenominator <= MARGIN_DENOMINATOR_MAX, ERR_INVALID_DATA);
			VALIDATE(subctx->stateData.marginNumerator <= subctx->stateData.marginDenominator, ERR_INVALID_DATA);
		}
	}
	{
		txHashBuilder_poolRegistrationCertificate_financials(
		        &BODY_CTX->txHashBuilder,
		        subctx->stateData.pledge, subctx->stateData.cost,
		        subctx->stateData.marginNumerator, subctx->stateData.marginDenominator
		);
	}

	subctx->ui_step = HANDLE_POOL_FINANCIALS_STEP_DISPLAY_PLEDGE;
	handlePoolFinancials_ui_runStep();
}

// ============================== POOL REWARD ACCOUNT ==============================

static void _parsePoolRewardAccount(read_view_t* view)
{
	reward_account_t* rewardAccount = &accessSubcontext()->stateData.poolRewardAccount;

	rewardAccount->keyReferenceType = parse_u1be(view);

	switch (rewardAccount->keyReferenceType) {

	case KEY_REFERENCE_HASH: {
		STATIC_ASSERT(SIZEOF(rewardAccount->hashBuffer) == REWARD_ACCOUNT_SIZE, "wrong reward account hash buffer size");
		view_parseBuffer(rewardAccount->hashBuffer, view, REWARD_ACCOUNT_SIZE);
		TRACE_BUFFER(rewardAccount->hashBuffer, SIZEOF(rewardAccount->hashBuffer));

		const uint8_t header = getAddressHeader(rewardAccount->hashBuffer, SIZEOF(rewardAccount->hashBuffer));
		VALIDATE(getAddressType(header) == REWARD_KEY || getAddressType(header) == REWARD_SCRIPT, ERR_INVALID_DATA);
		VALIDATE(getNetworkId(header) == commonTxData->networkId, ERR_INVALID_DATA);
		break;
	}

	case KEY_REFERENCE_PATH: {
		view_skipBytes(view, bip44_parseFromWire(&rewardAccount->path, VIEW_REMAINING_TO_TUPLE_BUF_SIZE(view)));
		BIP44_PRINTF(&rewardAccount->path);
		PRINTF("\n");
		break;
	}

	default:
		THROW(ERR_INVALID_DATA);
	}
}

__noinline_due_to_stack__
static void signTxPoolRegistration_handleRewardAccountAPDU(const uint8_t* wireDataBuffer, size_t wireDataSize)
{
	TRACE_STACK_USAGE();
	{
		// sanity checks
		CHECK_STATE(STAKE_POOL_REGISTRATION_REWARD_ACCOUNT);

		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}
	{
		// parse data

		TRACE_BUFFER(wireDataBuffer, wireDataSize);

		read_view_t view = make_read_view(wireDataBuffer, wireDataBuffer + wireDataSize);

		_parsePoolRewardAccount(&view);

		VALIDATE(view_remainingSize(&view) == 0, ERR_INVALID_DATA);
	}

	pool_registration_context_t* subctx = accessSubcontext();
	security_policy_t policy = policyForSignTxStakePoolRegistrationRewardAccount(
	                                   commonTxData->txSigningMode,
	                                   &subctx->stateData.poolRewardAccount
	                           );
	TRACE("Policy: %d", (int) policy);
	ENSURE_NOT_DENIED(policy);

	{
		// key derivation must not be done before DENY security policy is enforced
		uint8_t rewardAccountBuffer[REWARD_ACCOUNT_SIZE] = {0};
		rewardAccountToBuffer(&subctx->stateData.poolRewardAccount, commonTxData->networkId, rewardAccountBuffer);

		txHashBuilder_poolRegistrationCertificate_rewardAccount(
		        &BODY_CTX->txHashBuilder,
		        rewardAccountBuffer, SIZEOF(rewardAccountBuffer)
		);
	}

	{
		switch (policy) {
#define  CASE(POLICY, UI_STEP) case POLICY: {subctx->ui_step=UI_STEP; break;}
			CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_POOL_REWARD_ACCOUNT_STEP_DISPLAY);
			CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_POOL_REWARD_ACCOUNT_STEP_RESPOND);
#undef   CASE
		default:
			THROW(ERR_NOT_IMPLEMENTED);
		}
	}

	handlePoolRewardAccount_ui_runStep();
}

// ============================== OWNER ==============================

__noinline_due_to_stack__
static void _addOwnerToTxHash()
{
	pool_owner_t* owner = &accessSubcontext()->stateData.owner;

	uint8_t ownerKeyHash[ADDRESS_KEY_HASH_LENGTH] = {0};

	switch (owner->keyReferenceType) {

	case KEY_REFERENCE_PATH:
		bip44_pathToKeyHash(&owner->path, ownerKeyHash, SIZEOF(ownerKeyHash));
		break;

	case KEY_REFERENCE_HASH:
		memmove(ownerKeyHash, owner->keyHash, SIZEOF(ownerKeyHash));
		break;

	default:
		ASSERT(false);
	}

	// add data to tx
	TRACE("Adding owner to tx hash");
	txHashBuilder_addPoolRegistrationCertificate_addOwner(
	        &BODY_CTX->txHashBuilder,
	        ownerKeyHash, SIZEOF(ownerKeyHash)
	);
	TRACE();
}

__noinline_due_to_stack__
static void signTxPoolRegistration_handleOwnerAPDU(const uint8_t* wireDataBuffer, size_t wireDataSize)
{
	TRACE_STACK_USAGE();
	{
		// sanity checks
		CHECK_STATE(STAKE_POOL_REGISTRATION_OWNERS);

		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}

	pool_registration_context_t* subctx = accessSubcontext();
	pool_owner_t* owner = &subctx->stateData.owner;

	explicit_bzero(owner, SIZEOF(*owner));

	{
		// parse data
		TRACE_BUFFER(wireDataBuffer, wireDataSize);

		read_view_t view = make_read_view(wireDataBuffer, wireDataBuffer + wireDataSize);

		owner->keyReferenceType = parse_u1be(&view);
		switch (owner->keyReferenceType) {

		case KEY_REFERENCE_HASH: {
			STATIC_ASSERT(SIZEOF(owner->keyHash) == ADDRESS_KEY_HASH_LENGTH, "wrong owner.keyHash size");
			view_parseBuffer(owner->keyHash, &view, ADDRESS_KEY_HASH_LENGTH);
			TRACE_BUFFER(owner->keyHash, SIZEOF(owner->keyHash));
			break;
		}

		case KEY_REFERENCE_PATH: {
			view_skipBytes(&view, bip44_parseFromWire(&owner->path, VIEW_REMAINING_TO_TUPLE_BUF_SIZE(&view)));
			// further validation of the path in security policy below
			TRACE("Owner given by path:");
			BIP44_PRINTF(&owner->path);
			PRINTF("\n");

			subctx->numOwnersGivenByPath++;
			VALIDATE(!ctx->poolOwnerByPath, ERR_INVALID_DATA);
			ctx->poolOwnerByPath = true;
			memmove(&ctx->poolOwnerPath, &owner->path, SIZEOF(owner->path));
			break;
		}

		default:
			THROW(ERR_INVALID_DATA);
		}

		VALIDATE(view_remainingSize(&view) == 0, ERR_INVALID_DATA);
	}

	security_policy_t policy = policyForSignTxStakePoolRegistrationOwner(commonTxData->txSigningMode, owner, subctx->numOwnersGivenByPath);
	TRACE("Policy: %d", (int) policy);
	ENSURE_NOT_DENIED(policy);

	_addOwnerToTxHash();

	{
		// select UI steps
		switch (policy) {
#define  CASE(POLICY, UI_STEP) case POLICY: {subctx->ui_step=UI_STEP; break;}
			CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_OWNER_STEP_DISPLAY);
			CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_OWNER_STEP_RESPOND);
#undef   CASE
		default:
			THROW(ERR_NOT_IMPLEMENTED);
		}
	}

	handleOwner_ui_runStep();
}


// ============================== RELAY ==============================

static void _parsePort(ipport_t* port, read_view_t* view)
{
	uint8_t isPortGiven = parse_u1be(view);
	if (isPortGiven == ITEM_INCLUDED_YES) {
		port->isNull = false;
		ASSERT_TYPE(port->number, uint16_t);
		port->number = parse_u2be(view);
		TRACE("Port: %u", port->number);
	} else {
		VALIDATE(isPortGiven == ITEM_INCLUDED_NO, ERR_INVALID_DATA);
		port->isNull = true;
	}
}

static void _parseIpv4(ipv4_t* ipv4, read_view_t* view)
{
	uint8_t isIpv4Given = parse_u1be(view);
	if (isIpv4Given == ITEM_INCLUDED_YES) {
		ipv4->isNull = false;
		STATIC_ASSERT(sizeof(ipv4->ip) == IPV4_SIZE, "wrong ipv4 size"); // SIZEOF does not work for 4-byte buffers
		view_parseBuffer(ipv4->ip, view, IPV4_SIZE);
		TRACE("ipv4");
		TRACE_BUFFER(ipv4->ip, IPV4_SIZE);
	} else {
		VALIDATE(isIpv4Given == ITEM_INCLUDED_NO, ERR_INVALID_DATA);
		ipv4->isNull = true;
	}
}

static void _parseIpv6(ipv6_t* ipv6, read_view_t* view)
{
	uint8_t isIpv6Given = parse_u1be(view);
	if (isIpv6Given == ITEM_INCLUDED_YES) {
		ipv6->isNull = false;
		STATIC_ASSERT(SIZEOF(ipv6->ip) == IPV6_SIZE, "wrong ipv6 size");
		view_parseBuffer(ipv6->ip, view, IPV6_SIZE);
		TRACE("ipv6");
		TRACE_BUFFER(ipv6->ip, IPV6_SIZE);
	} else {
		VALIDATE(isIpv6Given == ITEM_INCLUDED_NO, ERR_INVALID_DATA);
		ipv6->isNull = true;
	}
}

static void _parseDnsName(pool_relay_t* relay, read_view_t* view)
{
	relay->dnsNameSize = view_remainingSize(view);
	VALIDATE(relay->dnsNameSize <= DNS_NAME_SIZE_MAX, ERR_INVALID_DATA);
	VALIDATE(str_isAllowedDnsName(VIEW_REMAINING_TO_TUPLE_BUF_SIZE(view)), ERR_INVALID_DATA);

	STATIC_ASSERT(SIZEOF(relay->dnsName) == DNS_NAME_SIZE_MAX, "wrong dns name buffer size");
	view_parseBuffer(relay->dnsName, view, relay->dnsNameSize);
}

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
__noinline_due_to_stack__
static void signTxPoolRegistration_handleRelayAPDU(const uint8_t* wireDataBuffer, size_t wireDataSize)
{
	TRACE_STACK_USAGE();
	{
		// sanity checks
		CHECK_STATE(STAKE_POOL_REGISTRATION_RELAYS);

		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}

	pool_relay_t* relay = &accessSubcontext()->stateData.relay;
	{
		// parse data
		TRACE_BUFFER(wireDataBuffer, wireDataSize);

		read_view_t view = make_read_view(wireDataBuffer, wireDataBuffer + wireDataSize);

		relay->format = parse_u1be(&view);
		TRACE("Relay format %u", relay->format);
		switch (relay->format) {

		// validation differs from the CDDL spec
		// the CDDL spec allows combinations of parameters that lead
		// to meaningless relays that are ignored by nodes
		// so we only allow meaningful relays

		case RELAY_SINGLE_HOST_IP: {
			_parsePort(&relay->port, &view);
			VALIDATE(!relay->port.isNull, ERR_INVALID_DATA);
			_parseIpv4(&relay->ipv4, &view);
			_parseIpv6(&relay->ipv6, &view);
			VALIDATE(!relay->ipv4.isNull || !relay->ipv6.isNull, ERR_INVALID_DATA);
			break;
		}

		case RELAY_SINGLE_HOST_NAME: {
			_parsePort(&relay->port, &view);
			VALIDATE(!relay->port.isNull, ERR_INVALID_DATA);
			_parseDnsName(relay, &view);
			VALIDATE(relay->dnsNameSize > 0, ERR_INVALID_DATA);
			break;
		}

		case RELAY_MULTIPLE_HOST_NAME: {
			_parseDnsName(relay, &view);
			VALIDATE(relay->dnsNameSize > 0, ERR_INVALID_DATA);
			break;
		}

		default:
			THROW(ERR_INVALID_DATA);
		}

		VALIDATE(view_remainingSize(&view) == 0, ERR_INVALID_DATA);
	}

	security_policy_t policy = policyForSignTxStakePoolRegistrationRelay(commonTxData->txSigningMode, relay);
	TRACE("Policy: %d", (int) policy);
	ENSURE_NOT_DENIED(policy);

	TRACE("Adding relay format %d to tx hash", (int) relay->format);
	txHashBuilder_addPoolRegistrationCertificate_addRelay(&BODY_CTX->txHashBuilder, relay);

	{
		int respondStep = -1;
		int displayStep = -1;
		void (*uiFn)() = NULL;

		switch (relay->format) {

		case RELAY_SINGLE_HOST_IP: {
			respondStep = HANDLE_RELAY_IP_STEP_RESPOND;
			displayStep = HANDLE_RELAY_IP_STEP_DISPLAY_NUMBER;
			uiFn = handleRelay_ip_ui_runStep;
			break;
		}

		case RELAY_SINGLE_HOST_NAME:
		case RELAY_MULTIPLE_HOST_NAME: {
			respondStep = HANDLE_RELAY_DNS_STEP_RESPOND;
			displayStep = HANDLE_RELAY_DNS_STEP_DISPLAY_NUMBER;
			uiFn = handleRelay_dns_ui_runStep;
			break;
		}

		default:
			THROW(ERR_INVALID_DATA);
		}

		ASSERT(respondStep != -1);
		ASSERT(displayStep != -1);
		ASSERT(uiFn != NULL);

		// select UI steps and call ui handler
		switch (policy) {
#define  CASE(POLICY, UI_STEP) case POLICY: {accessSubcontext()->ui_step=UI_STEP; break;}
			CASE(POLICY_ALLOW_WITHOUT_PROMPT, respondStep);
			CASE(POLICY_SHOW_BEFORE_RESPONSE, displayStep);
#undef   CASE
		default:
			THROW(ERR_NOT_IMPLEMENTED);
		}

		uiFn();
	}
}


// ============================== METADATA ==============================

static void handleNullMetadata()
{
	security_policy_t policy = policyForSignTxStakePoolRegistrationNoMetadata();
	TRACE("Policy: %d", (int) policy);
	ENSURE_NOT_DENIED(policy);

	{
		// add null metadata to certificate
		TRACE("Adding null pool metadata to tx hash");
		txHashBuilder_addPoolRegistrationCertificate_addPoolMetadata_null(&BODY_CTX->txHashBuilder);
	}

	{
		// select UI step
		switch (policy) {
#define  CASE(POLICY, UI_STEP) case POLICY: {accessSubcontext()->ui_step=UI_STEP; break;}
			CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_NULL_METADATA_STEP_DISPLAY);
			CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_NULL_METADATA_STEP_RESPOND);
#undef   CASE
		default:
			THROW(ERR_NOT_IMPLEMENTED);
		}
	}

	handleNullMetadata_ui_runStep();
}

__noinline_due_to_stack__
static void signTxPoolRegistration_handlePoolMetadataAPDU(const uint8_t* wireDataBuffer, size_t wireDataSize)
{
	TRACE_STACK_USAGE();
	{
		// sanity checks
		CHECK_STATE(STAKE_POOL_REGISTRATION_METADATA);

		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}

	pool_registration_context_t* subctx = accessSubcontext();
	explicit_bzero(&subctx->stateData.metadata, SIZEOF(subctx->stateData.metadata));

	{
		// parse data
		TRACE_BUFFER(wireDataBuffer, wireDataSize);

		pool_metadata_t* md = &subctx->stateData.metadata;

		read_view_t view = make_read_view(wireDataBuffer, wireDataBuffer + wireDataSize);

		{
			// deal with null metadata
			uint8_t includeMetadataByte = parse_u1be(&view);
			int includeMetadata = signTx_parseIncluded(includeMetadataByte);

			if (!includeMetadata) {
				VALIDATE(view_remainingSize(&view) == 0, ERR_INVALID_DATA);
				handleNullMetadata();
				return;
			}
		}
		{
			STATIC_ASSERT(SIZEOF(md->hash) == POOL_METADATA_HASH_LENGTH, "wrong pool metadata buffer size");
			view_parseBuffer(md->hash, &view, POOL_METADATA_HASH_LENGTH);
		}
		{
			md->urlSize = view_remainingSize(&view);
			VALIDATE(md->urlSize <= POOL_METADATA_URL_LENGTH_MAX, ERR_INVALID_DATA);
			STATIC_ASSERT(SIZEOF(md->url) >= POOL_METADATA_URL_LENGTH_MAX, "wrong pool metadata url size");
			view_parseBuffer(md->url, &view, md->urlSize);

			// whitespace not allowed
			VALIDATE(str_isPrintableAsciiWithoutSpaces(md->url, md->urlSize), ERR_INVALID_DATA);
		}

		VALIDATE(view_remainingSize(&view) == 0, ERR_INVALID_DATA);
	}

	security_policy_t policy = policyForSignTxStakePoolRegistrationMetadata();
	TRACE("Policy: %d", (int) policy);
	ENSURE_NOT_DENIED(policy);

	{
		// add metadata to tx
		TRACE("Adding metadata hash to tx hash");
		txHashBuilder_addPoolRegistrationCertificate_addPoolMetadata(
		        &BODY_CTX->txHashBuilder,
		        subctx->stateData.metadata.url, subctx->stateData.metadata.urlSize,
		        subctx->stateData.metadata.hash, SIZEOF(subctx->stateData.metadata.hash)
		);
	}

	{
		// select UI step
		switch (policy) {
#define  CASE(POLICY, UI_STEP) case POLICY: {subctx->ui_step=UI_STEP; break;}
			CASE(POLICY_SHOW_BEFORE_RESPONSE, HANDLE_METADATA_STEP_DISPLAY_URL);
			CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_METADATA_STEP_RESPOND);
#undef   CASE
		default:
			THROW(ERR_NOT_IMPLEMENTED);
		}
	}

	handleMetadata_ui_runStep();
}

// ============================== CONFIRM ==============================

__noinline_due_to_stack__
static void signTxPoolRegistration_handleConfirmAPDU(const uint8_t* wireDataBuffer MARK_UNUSED, size_t wireDataSize)
{
	TRACE_STACK_USAGE();
	{
		//sanity checks
		CHECK_STATE(STAKE_POOL_REGISTRATION_CONFIRM);

		ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);
	}

	{
		// no data to receive
		VALIDATE(wireDataSize == 0, ERR_INVALID_DATA);
	}

	pool_registration_context_t* subctx = accessSubcontext();
	security_policy_t policy = policyForSignTxStakePoolRegistrationConfirm(subctx->numOwners, subctx->numRelays);
	TRACE("Policy: %d", (int) policy);
	ENSURE_NOT_DENIED(policy);

	{
		// select UI step
		switch (policy) {
#define  CASE(POLICY, UI_STEP) case POLICY: {subctx->ui_step=UI_STEP; break;}
			CASE(POLICY_PROMPT_BEFORE_RESPONSE, HANDLE_CONFIRM_STEP_FINAL_NO_OWNERS);
			CASE(POLICY_ALLOW_WITHOUT_PROMPT, HANDLE_CONFIRM_STEP_RESPOND);
#undef   CASE
		default:
			THROW(ERR_NOT_IMPLEMENTED);
		}
	}

	signTxPoolRegistration_handleConfirm_ui_runStep();
}


// ============================== main APDU handler ==============================

enum {
	APDU_INSTRUCTION_INIT = 0x30,
	APDU_INSTRUCTION_POOL_KEY = 0x31,
	APDU_INSTRUCTION_VRF_KEY = 0x32,
	APDU_INSTRUCTION_FINANCIALS = 0x33,
	APDU_INSTRUCTION_REWARD_ACCOUNT = 0x34,
	APDU_INSTRUCTION_OWNERS = 0x35,
	APDU_INSTRUCTION_RELAYS = 0x36,
	APDU_INSTRUCTION_METADATA = 0x37,
	APDU_INSTRUCTION_CONFIRMATION = 0x38
};

bool signTxPoolRegistration_isValidInstruction(uint8_t p2)
{
	switch (p2) {
	case APDU_INSTRUCTION_INIT:
	case APDU_INSTRUCTION_POOL_KEY:
	case APDU_INSTRUCTION_VRF_KEY:
	case APDU_INSTRUCTION_FINANCIALS:
	case APDU_INSTRUCTION_REWARD_ACCOUNT:
	case APDU_INSTRUCTION_OWNERS:
	case APDU_INSTRUCTION_RELAYS:
	case APDU_INSTRUCTION_METADATA:
	case APDU_INSTRUCTION_CONFIRMATION:
		return true;

	default:
		return false;
	}
}

void signTxPoolRegistration_handleAPDU(uint8_t p2, const uint8_t* wireDataBuffer, size_t wireDataSize)
{
	TRACE_STACK_USAGE();
	TRACE("p2 = 0x%x", p2);
	ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);

	pool_registration_context_t* subctx = accessSubcontext();
	explicit_bzero(&subctx->stateData, SIZEOF(subctx->stateData));

	switch (p2) {
	case APDU_INSTRUCTION_INIT:
		signTxPoolRegistration_handleInitAPDU(wireDataBuffer, wireDataSize);
		break;

	case APDU_INSTRUCTION_POOL_KEY:
		signTxPoolRegistration_handlePoolKeyAPDU(wireDataBuffer, wireDataSize);
		break;

	case APDU_INSTRUCTION_VRF_KEY:
		signTxPoolRegistration_handleVrfKeyAPDU(wireDataBuffer, wireDataSize);
		break;

	case APDU_INSTRUCTION_FINANCIALS:
		signTxPoolRegistration_handlePoolFinancialsAPDU(wireDataBuffer, wireDataSize);
		break;

	case APDU_INSTRUCTION_REWARD_ACCOUNT:
		signTxPoolRegistration_handleRewardAccountAPDU(wireDataBuffer, wireDataSize);
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
