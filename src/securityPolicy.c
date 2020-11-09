#include "addressUtilsShelley.h"
#include "addressUtilsByron.h"
#include "bip44.h"

#include "securityPolicy.h"

// Helper macros

static inline bool spending_path_is_consistent_with_address_type(address_type_t addressType, const bip44_path_t* spendingPath)
{
#define CHECK(cond) if (!(cond)) return false
	// Byron derivation path is only valid for a Byron address
	// the rest should be Shelley derivation scheme
	if (addressType == BYRON) {
		CHECK(bip44_hasByronPrefix(spendingPath));
	} else {
		CHECK(bip44_hasShelleyPrefix(spendingPath));
	}

	if (addressType == REWARD) {
		CHECK(bip44_isValidStakingKeyPath(spendingPath));
	} else {
		CHECK(bip44_isValidAddressPath(spendingPath));
	}

	return true;
#undef CHECK
}

// staking key path has the same account as the spending key path
// assumes that the given address params are valid
static inline bool is_standard_base_address(const addressParams_t* addressParams)
{
#define CHECK(cond) if (!(cond)) return false
	CHECK(addressParams->type == BASE);
	CHECK(addressParams->stakingChoice == STAKING_KEY_PATH);
	ASSERT(bip44_containsAccount(&addressParams->stakingKeyPath));
	ASSERT(bip44_containsAccount(&addressParams->spendingKeyPath));
	CHECK(
	        bip44_getAccount(&addressParams->stakingKeyPath) ==
	        bip44_getAccount(&addressParams->spendingKeyPath)
	);

	return true;
#undef CHECK
}

static inline bool staking_info_is_valid(const addressParams_t* addressParams)
{
#define CHECK(cond) if (!(cond)) return false
	CHECK(isStakingInfoConsistentWithAddressType(addressParams));
	if (addressParams->stakingChoice == STAKING_KEY_PATH) {
		CHECK(bip44_isValidStakingKeyPath(&addressParams->stakingKeyPath));
	}
	return true;
#undef CHECK
}

static inline bool has_cardano_prefix_and_any_account(const bip44_path_t* pathSpec)
{
	return bip44_hasValidCardanoPrefix(pathSpec) &&
	       bip44_containsAccount(pathSpec);
}

static inline bool is_valid_stake_pool_owner_path(const bip44_path_t* pathSpec)
{
	return bip44_isValidStakingKeyPath(pathSpec);
}

// general requirements on witnesses
static inline bool is_valid_witness(const bip44_path_t* pathSpec)
{
	if (!bip44_hasValidCardanoPrefix(pathSpec))
		return false;

	if (bip44_isValidStakingKeyPath(pathSpec))
		return true;

	return bip44_isValidAddressPath(pathSpec);
}

// Both account and address are from small brute-forcable range
static inline bool has_reasonable_account_and_address(const bip44_path_t* pathSpec)
{
	return bip44_hasReasonableAccount(pathSpec) &&
	       bip44_hasReasonableAddress(pathSpec);
}

static inline bool is_too_deep(const bip44_path_t* pathSpec)
{
	return bip44_containsMoreThanAddress(pathSpec);
}

#define DENY_IF(expr)      if (expr)    return POLICY_DENY;
#define DENY_UNLESS(expr)  if (!(expr)) return POLICY_DENY;
#define WARN_IF(expr)      if (expr)    return POLICY_PROMPT_WARN_UNUSUAL;
#define WARN_UNLESS(expr)  if (!(expr)) return POLICY_PROMPT_WARN_UNUSUAL;
#define PROMPT_IF(expr)    if (expr)    return POLICY_PROMPT_BEFORE_RESPONSE;
#define ALLOW_IF(expr)     if (expr)    return POLICY_ALLOW_WITHOUT_PROMPT;
#define SHOW_IF(expr)      if (expr)    return POLICY_SHOW_BEFORE_RESPONSE;
#define SHOW_UNLESS(expr)  if (!(expr)) return POLICY_SHOW_BEFORE_RESPONSE;


security_policy_t policyForGetPublicKeysInit(size_t remainingPaths)
{
	ASSERT(remainingPaths > 0);

	PROMPT_IF(true);
}

// Get extended public key and return it to the host
security_policy_t policyForGetExtendedPublicKey(const bip44_path_t* pathSpec)
{
	DENY_UNLESS(has_cardano_prefix_and_any_account(pathSpec));

	WARN_UNLESS(bip44_hasReasonableAccount(pathSpec));

	WARN_IF(bip44_containsMoreThanAddress(pathSpec));

	PROMPT_IF(true);
}

// Get extended public key and return it to the host within bulk key export
security_policy_t policyForGetExtendedPublicKeyBulkExport(const bip44_path_t* pathSpec)
{
	// the expected values that need not to be confirmed start with
	// m/1852'/1815'/account' or m/44'/1815'/account', where account is not too big

	DENY_UNLESS(has_cardano_prefix_and_any_account(pathSpec));

	WARN_UNLESS(bip44_hasReasonableAccount(pathSpec));

	// if they contain more than account, then the suffix after account
	// has to be one of 2/0, 0/index, 1/index
	if (bip44_containsMoreThanAccount(pathSpec)) {
		WARN_IF(bip44_containsMoreThanAddress(pathSpec));
		WARN_IF(bip44_containsChainType(pathSpec) && !bip44_containsAddress(pathSpec));

		// we are left with paths of length 5
		ALLOW_IF(bip44_isValidStakingKeyPath(pathSpec));

		// only ordinary address paths remain
		WARN_UNLESS(bip44_isValidAddressPath(pathSpec));
		WARN_UNLESS(bip44_hasReasonableAddress(pathSpec));
	}

	ALLOW_IF(true);
}

// Derive address and return it to the host
security_policy_t policyForReturnDeriveAddress(const addressParams_t* addressParams)
{
	DENY_UNLESS(spending_path_is_consistent_with_address_type(addressParams->type, &addressParams->spendingKeyPath));
	DENY_UNLESS(staking_info_is_valid(addressParams));
	DENY_IF(is_too_deep(&addressParams->spendingKeyPath));

	WARN_UNLESS(has_reasonable_account_and_address(&addressParams->spendingKeyPath));

	PROMPT_IF(true);
}

// Derive address and show it to the user
security_policy_t policyForShowDeriveAddress(const addressParams_t* addressParams)
{
	DENY_UNLESS(spending_path_is_consistent_with_address_type(addressParams->type, &addressParams->spendingKeyPath));
	DENY_UNLESS(staking_info_is_valid(addressParams));
	DENY_IF(is_too_deep(&addressParams->spendingKeyPath));

	WARN_UNLESS(has_reasonable_account_and_address(&addressParams->spendingKeyPath));

	SHOW_IF(true);
}


// Initiate transaction signing
security_policy_t policyForSignTxInit(uint8_t networkId, uint32_t protocolMagic)
{
	// Deny shelley mainnet with weird byron protocol magic
	DENY_IF(networkId == MAINNET_NETWORK_ID && protocolMagic != MAINNET_PROTOCOL_MAGIC);
	// Note: testnets can still use byron mainnet protocol magic so we can't deny the opposite direction

	WARN_IF(networkId != MAINNET_NETWORK_ID);
	WARN_IF(protocolMagic != MAINNET_PROTOCOL_MAGIC);
	// Could be switched to POLICY_ALLOW_WITHOUT_PROMPT to skip initial "new transaction" question
	PROMPT_IF(true);
}

// For each transaction UTxO input
security_policy_t policyForSignTxInput()
{
	// No need to check tx inputs
	ALLOW_IF(true);
}

// For each transaction (third-party) address output
security_policy_t policyForSignTxOutputAddress(
        bool isSigningPoolRegistrationAsOwner,
        const uint8_t* rawAddressBuffer, size_t rawAddressSize,
        const uint8_t networkId, const uint32_t protocolMagic
)
{
	TRACE("isSigningPoolRegistrationAsOwner = %d", isSigningPoolRegistrationAsOwner);

	ALLOW_IF(isSigningPoolRegistrationAsOwner);

	ASSERT(rawAddressSize >= 1);
	address_type_t addressType = getAddressType(rawAddressBuffer[0]);
	if (addressType == BYRON) {
		uint32_t addressProtocolMagic = extractProtocolMagic(rawAddressBuffer, rawAddressSize);
		DENY_IF(addressProtocolMagic != protocolMagic);
	} else { // shelley
		uint8_t addressNetworkId = getNetworkId(rawAddressBuffer[0]);
		DENY_IF(addressNetworkId != networkId);
		DENY_IF(addressType == REWARD);
	}

	// We always show third-party output addresses
	SHOW_IF(true);
}

// For each output given by derivation path
security_policy_t policyForSignTxOutputAddressParams(
        bool isSigningPoolRegistrationAsOwner,
        const addressParams_t* params,
        const uint8_t networkId, const uint32_t protocolMagic
)
{
	// we forbid these to avoid leaking information
	// (since the outputs are not shown, the user is unaware of what addresses are being derived)
	// it also makes the tx signing faster if all outputs are given as addresses
	DENY_IF(isSigningPoolRegistrationAsOwner);

	DENY_UNLESS(spending_path_is_consistent_with_address_type(params->type, &params->spendingKeyPath));
	DENY_UNLESS(staking_info_is_valid(params));
	DENY_IF(is_too_deep(&params->spendingKeyPath));

	if (params->type == BYRON) {
		DENY_IF(params->protocolMagic != protocolMagic);
	} else { // shelley
		DENY_IF(params->networkId != networkId);
	}

	SHOW_UNLESS(has_reasonable_account_and_address(&params->spendingKeyPath));
	SHOW_UNLESS(is_standard_base_address(params));

	ALLOW_IF(true);
}

// For transaction fee
security_policy_t policyForSignTxFee(bool isSigningPoolRegistrationAsOwner, uint64_t fee MARK_UNUSED)
{
	ALLOW_IF(isSigningPoolRegistrationAsOwner);

	// always show the fee in ordinary transactions
	SHOW_IF(true);
}

// For transaction TTL
security_policy_t policyForSignTxTtl(uint32_t ttl)
{
	// ttl == 0 will not be accepted by a node
	// and indicates a likely bug somewhere
	DENY_IF(ttl == 0);

	// might be changed to POLICY_ALLOW_WITHOUT_PROMPT
	// to avoid bothering the user with TTL
	// (Daedalus does not show this)
	SHOW_IF(true);
}

// a generic policy for all certificates
// does not evaluate all aspects for specific certificates
security_policy_t policyForSignTxCertificate(
        const bool includeStakePoolRegistrationCertificate,
        const uint8_t certificateType
)
{
	if (includeStakePoolRegistrationCertificate) {
		DENY_UNLESS(certificateType == CERTIFICATE_TYPE_STAKE_POOL_REGISTRATION);

		ALLOW_IF(true);
	} else {
		DENY_IF(certificateType == CERTIFICATE_TYPE_STAKE_POOL_REGISTRATION);

		ALLOW_IF(true);
	}
}

// for certificates concerning staking keys and stake delegation
security_policy_t policyForSignTxCertificateStaking(
        const uint8_t certificateType,
        const bip44_path_t* stakingKeyPath
)
{
	switch (certificateType) {
	case CERTIFICATE_TYPE_STAKE_REGISTRATION:
	case CERTIFICATE_TYPE_STAKE_DEREGISTRATION:
	case CERTIFICATE_TYPE_STAKE_DELEGATION:
		break; // these are allowed

	default:
		ASSERT(false);
	}

	DENY_UNLESS(bip44_isValidStakingKeyPath(stakingKeyPath));

	PROMPT_IF(true);
}

// for stake pool registration certificates
security_policy_t policyForSignTxCertificateStakePoolRegistration()
{
	PROMPT_IF(true);
}

security_policy_t policyForSignTxStakePoolRegistrationOwner(pool_owner_t* owner)
{
	switch (owner->ownerType) {
	case SIGN_TX_POOL_OWNER_TYPE_KEY_HASH:
		SHOW_IF(true);
		break;

	case SIGN_TX_POOL_OWNER_TYPE_PATH:
		SHOW_IF(is_valid_stake_pool_owner_path(&owner->path));
		break;

	default:
		ASSERT(false);
	}
	DENY_IF(true);
}

security_policy_t policyForSignTxStakePoolRegistrationMetadata()
{
	SHOW_IF(true);
}

security_policy_t policyForSignTxStakePoolRegistrationNoMetadata()
{
	SHOW_IF(true);
}

security_policy_t policyForSignTxStakePoolRegistrationConfirm()
{
	ALLOW_IF(true);
}

// For each withdrawal
security_policy_t policyForSignTxWithdrawal()
{
	// No need to check withdrawals
	SHOW_IF(true);
}

// For each transaction witness
// Note: witnesses reveal public key of an address
// and Ledger *does not* check whether they correspond to previously declared UTxOs
security_policy_t policyForSignTxWitness(
        bool isSigningPoolRegistrationAsOwner,
        const bip44_path_t* pathSpec
)
{
	DENY_UNLESS(is_valid_witness(pathSpec));

	if (isSigningPoolRegistrationAsOwner) {
		DENY_UNLESS(is_valid_stake_pool_owner_path(pathSpec));
	} else {
		// TODO Perhaps we can relax this?
		WARN_UNLESS(has_reasonable_account_and_address(pathSpec));

		// TODO deny this? or check for depth in is_valid_witness?
		WARN_IF(is_too_deep(pathSpec));
	}

	ALLOW_IF(true);
}

security_policy_t policyForSignTxMetadata()
{
	SHOW_IF(true);
}

security_policy_t policyForSignTxConfirm()
{
	PROMPT_IF(true);
}
