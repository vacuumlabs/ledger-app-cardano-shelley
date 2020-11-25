#include "addressUtilsShelley.h"
#include "addressUtilsByron.h"
#include "bip44.h"

#include "securityPolicy.h"

// Helper macros

// staking key path has the same account as the spending key path
static inline bool is_standard_base_address(const addressParams_t* addressParams)
{
	ASSERT(isValidAddressParams(addressParams));

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

// account is from a small brute-forcable range
static inline bool has_reasonable_account(const bip44_path_t* pathSpec)
{
	return bip44_hasReasonableAccount(pathSpec);
}

// address is from a small brute-forcable range
static inline bool has_reasonable_address(const bip44_path_t* pathSpec)
{
	return bip44_hasReasonableAddress(pathSpec);
}

// both account and address are from a small brute-forcable range
static inline bool has_reasonable_account_and_address(const bip44_path_t* pathSpec)
{
	return has_reasonable_account(pathSpec) && has_reasonable_address(pathSpec);
}

static inline bool is_too_deep(const bip44_path_t* pathSpec)
{
	return bip44_containsMoreThanAddress(pathSpec);
}

bool is_tx_network_verifiable(
        uint16_t numOutputs,
        uint16_t numWithdrawals,
        bool isSigningPoolRegistrationAsOwner
)
{
	return (numOutputs > 0) || (numWithdrawals > 0) || (isSigningPoolRegistrationAsOwner);
}


#define DENY()                          return POLICY_DENY;
#define DENY_IF(expr)      if (expr)    return POLICY_DENY;
#define DENY_UNLESS(expr)  if (!(expr)) return POLICY_DENY;

#define WARN_IF(expr)      if (expr)    return POLICY_PROMPT_WARN_UNUSUAL;
#define WARN_UNLESS(expr)  if (!(expr)) return POLICY_PROMPT_WARN_UNUSUAL;

#define PROMPT()                        return POLICY_PROMPT_BEFORE_RESPONSE;
#define PROMPT_IF(expr)    if (expr)    return POLICY_PROMPT_BEFORE_RESPONSE;

#define ALLOW()                         return POLICY_ALLOW_WITHOUT_PROMPT;
#define ALLOW_IF(expr)     if (expr)    return POLICY_ALLOW_WITHOUT_PROMPT;

#define SHOW()                          return POLICY_SHOW_BEFORE_RESPONSE;
#define SHOW_IF(expr)      if (expr)    return POLICY_SHOW_BEFORE_RESPONSE;
#define SHOW_UNLESS(expr)  if (!(expr)) return POLICY_SHOW_BEFORE_RESPONSE;


security_policy_t policyForGetPublicKeysInit(size_t numPaths)
{
	PROMPT_IF(numPaths > 1);

	ALLOW();
}

// Get extended public key and return it to the host
security_policy_t policyForGetExtendedPublicKey(const bip44_path_t* pathSpec)
{
	DENY_UNLESS(has_cardano_prefix_and_any_account(pathSpec));

	WARN_UNLESS(has_reasonable_account(pathSpec));

	WARN_IF(is_too_deep(pathSpec));

	PROMPT();
}

// Get extended public key and return it to the host within bulk key export
security_policy_t policyForGetExtendedPublicKeyBulkExport(const bip44_path_t* pathSpec)
{
	// the expected values that need not to be confirmed start with
	// m/1852'/1815'/account' or m/44'/1815'/account', where account is not too big

	DENY_UNLESS(has_cardano_prefix_and_any_account(pathSpec));

	WARN_UNLESS(has_reasonable_account(pathSpec));

	WARN_IF(is_too_deep(pathSpec));

	// if they contain more than account, then the suffix after account
	// has to be one of 2/0, 0/index, 1/index
	if (bip44_containsMoreThanAccount(pathSpec)) {
		WARN_IF(bip44_containsChainType(pathSpec) && !bip44_containsAddress(pathSpec));

		// we are left with paths of length 5

		ALLOW_IF(bip44_isValidStakingKeyPath(pathSpec));

		// only ordinary address paths remain
		WARN_UNLESS(bip44_isValidAddressPath(pathSpec));
		WARN_UNLESS(has_reasonable_address(pathSpec));
	}

	ALLOW();
}

// Derive address and return it to the host
security_policy_t policyForReturnDeriveAddress(const addressParams_t* addressParams)
{
	DENY_UNLESS(isValidAddressParams(addressParams));

	DENY_IF(is_too_deep(&addressParams->spendingKeyPath));

	WARN_UNLESS(has_reasonable_account_and_address(&addressParams->spendingKeyPath));

	PROMPT();
}

// Derive address and show it to the user
security_policy_t policyForShowDeriveAddress(const addressParams_t* addressParams)
{
	DENY_UNLESS(isValidAddressParams(addressParams));

	DENY_IF(is_too_deep(&addressParams->spendingKeyPath));

	WARN_UNLESS(has_reasonable_account_and_address(&addressParams->spendingKeyPath));

	SHOW();
}


// Initiate transaction signing
security_policy_t policyForSignTxInit(
        uint8_t networkId,
        uint32_t protocolMagic,
        uint16_t numOutputs,
        uint16_t numWithdrawals,
        bool isSigningPoolRegistrationAsOwner
)
{
	// Deny shelley mainnet with weird byron protocol magic
	DENY_IF(networkId == MAINNET_NETWORK_ID && protocolMagic != MAINNET_PROTOCOL_MAGIC);
	// Note: testnets can still use byron mainnet protocol magic so we can't deny the opposite direction

	WARN_IF(!is_tx_network_verifiable(numOutputs, numWithdrawals, isSigningPoolRegistrationAsOwner));

	WARN_IF(networkId != MAINNET_NETWORK_ID);
	WARN_IF(protocolMagic != MAINNET_PROTOCOL_MAGIC);

	// Could be switched to POLICY_ALLOW_WITHOUT_PROMPT to skip initial "new transaction" question
	PROMPT();
}

// For each transaction UTxO input
security_policy_t policyForSignTxInput()
{
	// No need to check tx inputs
	ALLOW();
}

// For each transaction (third-party) address output
security_policy_t policyForSignTxOutputAddressBytes(
        bool isSigningPoolRegistrationAsOwner,
        const uint8_t* rawAddressBuffer, size_t rawAddressSize,
        const uint8_t networkId, const uint32_t protocolMagic
)
{
	TRACE("isSigningPoolRegistrationAsOwner = %d", isSigningPoolRegistrationAsOwner);

	ALLOW_IF(isSigningPoolRegistrationAsOwner);

	// network identification should be consistent across tx
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
	SHOW();
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

	DENY_UNLESS(isValidAddressParams(params));

	DENY_IF(is_too_deep(&params->spendingKeyPath));

	// network identification should be consistent across tx
	if (params->type == BYRON) {
		DENY_IF(params->protocolMagic != protocolMagic);
	} else { // shelley
		DENY_IF(params->networkId != networkId);
	}

	SHOW_UNLESS(has_reasonable_account_and_address(&params->spendingKeyPath));
	SHOW_UNLESS(is_standard_base_address(params));

	ALLOW();
}

security_policy_t policyForSignTxOutputConfirm(
        security_policy_t outputPolicy,
        uint64_t numAssetGroups
)
{
	switch (outputPolicy) {
	case POLICY_ALLOW_WITHOUT_PROMPT:
		ALLOW();
		break;

	case POLICY_SHOW_BEFORE_RESPONSE:
		PROMPT_IF(numAssetGroups > 0);
		ALLOW();
		break;

	default:
		ASSERT(false);
	}

	DENY(); // should not be reached
}

// For transaction fee
security_policy_t policyForSignTxFee(bool isSigningPoolRegistrationAsOwner, uint64_t fee MARK_UNUSED)
{
	ALLOW_IF(isSigningPoolRegistrationAsOwner);

	// always show the fee in ordinary transactions
	SHOW();
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
	SHOW();
}

// a generic policy for all certificates
// does not evaluate all aspects for specific certificates
security_policy_t policyForSignTxCertificate(
        const bool includeStakePoolRegistrationCertificate,
        const certificate_type_t certificateType
)
{
	if (includeStakePoolRegistrationCertificate) {
		DENY_UNLESS(certificateType == CERTIFICATE_TYPE_STAKE_POOL_REGISTRATION);

		ALLOW();
	} else {
		DENY_IF(certificateType == CERTIFICATE_TYPE_STAKE_POOL_REGISTRATION);

		ALLOW();
	}
}

// for certificates concerning staking keys and stake delegation
security_policy_t policyForSignTxCertificateStaking(
        const certificate_type_t certificateType,
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

	PROMPT();
}

// for stake pool registration certificates
security_policy_t policyForSignTxCertificateStakePoolRegistration()
{
	PROMPT();
}

security_policy_t policyForSignTxStakePoolRegistrationOwner(pool_owner_t* owner)
{
	switch (owner->ownerType) {
	case SIGN_TX_POOL_OWNER_TYPE_KEY_HASH:
		SHOW();
		break;

	case SIGN_TX_POOL_OWNER_TYPE_PATH:
		SHOW_IF(is_valid_stake_pool_owner_path(&owner->path));
		break;

	default:
		ASSERT(false);
	}
	DENY();
}

security_policy_t policyForSignTxStakePoolRegistrationMetadata()
{
	SHOW();
}

security_policy_t policyForSignTxStakePoolRegistrationNoMetadata()
{
	SHOW();
}

security_policy_t policyForSignTxStakePoolRegistrationConfirm()
{
	ALLOW();
}

// For each withdrawal
security_policy_t policyForSignTxWithdrawal()
{
	// No need to check withdrawals
	SHOW();
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
		// witness for input or withdrawal
		DENY_IF(is_too_deep(pathSpec));
	}

	WARN_UNLESS(has_reasonable_account_and_address(pathSpec));

	ALLOW();
}

security_policy_t policyForSignTxMetadata()
{
	SHOW();
}

security_policy_t policyForSignTxValidityIntervalStart()
{
	SHOW();
}

security_policy_t policyForSignTxConfirm()
{
	PROMPT();
}
