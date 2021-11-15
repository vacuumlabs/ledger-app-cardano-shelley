#include "addressUtilsShelley.h"
#include "addressUtilsByron.h"
#include "bip44.h"
#include "cardano.h"
#include "signTxUtils.h"

#include "securityPolicy.h"

// Helper macros

// staking key path has the same account as the spending key path
static inline bool is_standard_base_address(const addressParams_t* addressParams)
{
	ASSERT(isValidAddressParams(addressParams));

#define CHECK(cond) if (!(cond)) return false
	CHECK(addressParams->type == BASE_PAYMENT_KEY_STAKE_KEY);
	CHECK(addressParams->stakingDataSource == STAKING_KEY_PATH);

	CHECK(bip44_classifyPath(&addressParams->spendingKeyPath) == PATH_ORDINARY_SPENDING_KEY);
	CHECK(bip44_isPathReasonable(&addressParams->spendingKeyPath));

	CHECK(bip44_classifyPath(&addressParams->stakingKeyPath) == PATH_ORDINARY_STAKING_KEY);
	CHECK(bip44_isPathReasonable(&addressParams->stakingKeyPath));

	CHECK(
	        bip44_getAccount(&addressParams->stakingKeyPath) ==
	        bip44_getAccount(&addressParams->spendingKeyPath)
	);

	return true;
#undef CHECK
}

static inline bool is_reward_address(const addressParams_t* addressParams)
{
	ASSERT(isValidAddressParams(addressParams));

	return addressParams->type == REWARD_KEY || addressParams->type == REWARD_SCRIPT;
}

// useful shortcuts

// WARNING: unless you are doing something exceptional,
// policies must come in the order DENY > WARN > PROMPT/SHOW > ALLOW

#define DENY()                          return POLICY_DENY;
#define DENY_IF(expr)      if (expr)    return POLICY_DENY;
#define DENY_UNLESS(expr)  if (!(expr)) return POLICY_DENY;

#define WARN()                          return POLICY_PROMPT_WARN_UNUSUAL;
#define WARN_IF(expr)      if (expr)    return POLICY_PROMPT_WARN_UNUSUAL;
#define WARN_UNLESS(expr)  if (!(expr)) return POLICY_PROMPT_WARN_UNUSUAL;

#define PROMPT()                        return POLICY_PROMPT_BEFORE_RESPONSE;
#define PROMPT_IF(expr)    if (expr)    return POLICY_PROMPT_BEFORE_RESPONSE;

#define ALLOW()                         return POLICY_ALLOW_WITHOUT_PROMPT;
#define ALLOW_IF(expr)     if (expr)    return POLICY_ALLOW_WITHOUT_PROMPT;

#define SHOW()                          return POLICY_SHOW_BEFORE_RESPONSE;
#define SHOW_IF(expr)      if (expr)    return POLICY_SHOW_BEFORE_RESPONSE;
#define SHOW_UNLESS(expr)  if (!(expr)) return POLICY_SHOW_BEFORE_RESPONSE;


security_policy_t policyForDerivePrivateKey(const bip44_path_t* path)
{
	switch (bip44_classifyPath(path)) {

	case PATH_ORDINARY_ACCOUNT:
	case PATH_ORDINARY_SPENDING_KEY:
	case PATH_ORDINARY_STAKING_KEY:

	case PATH_MULTISIG_ACCOUNT:
	case PATH_MULTISIG_SPENDING_KEY:
	case PATH_MULTISIG_STAKING_KEY:

	case PATH_MINT_KEY:

	case PATH_POOL_COLD_KEY:

		ALLOW();

	default:
		DENY();
	}
}

security_policy_t policyForGetPublicKeysInit(uint32_t numPaths)
{
	PROMPT_IF(numPaths > 1);

	ALLOW();
}

// Get extended public key and return it to the host
security_policy_t policyForGetExtendedPublicKey(const bip44_path_t* pathSpec)
{
	switch (bip44_classifyPath(pathSpec)) {

	case PATH_ORDINARY_ACCOUNT:
	case PATH_ORDINARY_SPENDING_KEY:
	case PATH_ORDINARY_STAKING_KEY:
	case PATH_MULTISIG_ACCOUNT:
	case PATH_MULTISIG_SPENDING_KEY:
	case PATH_MULTISIG_STAKING_KEY:
	case PATH_MINT_KEY:
	case PATH_POOL_COLD_KEY:
		WARN_IF(!bip44_isPathReasonable(pathSpec));
		PROMPT();
		break;

	default:
		DENY();
		break;
	}

	DENY(); // should not be reached
}

// Get extended public key and return it to the host within bulk key export
security_policy_t policyForGetExtendedPublicKeyBulkExport(const bip44_path_t* pathSpec)
{
	switch (bip44_classifyPath(pathSpec)) {

	case PATH_ORDINARY_ACCOUNT:
	case PATH_ORDINARY_SPENDING_KEY:
	case PATH_ORDINARY_STAKING_KEY:
	case PATH_MULTISIG_ACCOUNT:
	case PATH_MULTISIG_SPENDING_KEY:
	case PATH_MULTISIG_STAKING_KEY:
	case PATH_MINT_KEY:
		WARN_IF(!bip44_isPathReasonable(pathSpec));
		ALLOW();
		break;

	case PATH_POOL_COLD_KEY:
		WARN_IF(!bip44_isPathReasonable(pathSpec));
		PROMPT();
		break;

	default:
		DENY();
		break;
	}

	DENY(); // should not be reached
}

// common policy for DENY and WARN
static security_policy_t _policyForDeriveAddress(const addressParams_t* addressParams, security_policy_t successPolicy)
{
	DENY_UNLESS(isValidAddressParams(addressParams));

	switch (addressParams->type) {

	case BASE_PAYMENT_KEY_STAKE_KEY:
		DENY_IF(bip44_classifyPath(&addressParams->spendingKeyPath) != PATH_ORDINARY_SPENDING_KEY);
		DENY_IF(
		        addressParams->stakingDataSource == STAKING_KEY_PATH &&
		        bip44_classifyPath(&addressParams->stakingKeyPath) != PATH_ORDINARY_STAKING_KEY
		);

		WARN_IF(!bip44_isPathReasonable(&addressParams->spendingKeyPath));
		WARN_IF(
		        addressParams->stakingDataSource == STAKING_KEY_PATH &&
		        !bip44_isPathReasonable(&addressParams->stakingKeyPath)
		);
		break;

	case BASE_PAYMENT_KEY_STAKE_SCRIPT:
	case POINTER_KEY:
	case ENTERPRISE_KEY:
	case BYRON:
		DENY_IF(bip44_classifyPath(&addressParams->spendingKeyPath) != PATH_ORDINARY_SPENDING_KEY);

		WARN_IF(!bip44_isPathReasonable(&addressParams->spendingKeyPath));
		break;

	case BASE_PAYMENT_SCRIPT_STAKE_KEY:
	case REWARD_KEY:
		DENY_IF(addressParams->stakingDataSource != STAKING_KEY_PATH);
		DENY_IF(bip44_classifyPath(&addressParams->stakingKeyPath) != PATH_ORDINARY_STAKING_KEY);

		WARN_IF(!bip44_isPathReasonable(&addressParams->stakingKeyPath));
		break;

	case BASE_PAYMENT_SCRIPT_STAKE_SCRIPT:
	case POINTER_SCRIPT:
	case ENTERPRISE_SCRIPT:
	case REWARD_SCRIPT:
		// no paths in the address
		break;

	default:
		DENY();
		break;
	}

	return successPolicy;
}

// Derive address and return it to the host
security_policy_t policyForReturnDeriveAddress(const addressParams_t* addressParams)
{
	return _policyForDeriveAddress(addressParams, POLICY_ALLOW_WITHOUT_PROMPT);
}

// Derive address and show it to the user
security_policy_t policyForShowDeriveAddress(const addressParams_t* addressParams)
{
	return _policyForDeriveAddress(addressParams, POLICY_SHOW_BEFORE_RESPONSE);
}


// Initiate transaction signing
security_policy_t policyForSignTxInit(
        sign_tx_signingmode_t txSigningMode,
        uint32_t networkId,
        uint32_t protocolMagic,
        uint16_t numCertificates,
        uint16_t numWithdrawals,
        bool includeMint,
        uint16_t numCollaterals,
        uint16_t numRequiredSigners,
        bool includeScriptDataHash
)
{
	DENY_UNLESS(isValidNetworkId(networkId));
	// Deny shelley mainnet with weird byron protocol magic
	DENY_IF(networkId == MAINNET_NETWORK_ID && protocolMagic != MAINNET_PROTOCOL_MAGIC);
	// Note: testnets can still use byron mainnet protocol magic so we can't deny the opposite direction

	// certain combinations of tx body elements are forbidden
	// because of potential cross-witnessing
	switch (txSigningMode) {

	case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OPERATOR:
	case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OWNER:
		// necessary to avoid intermingling witnesses from several certs
		DENY_UNLESS(numCertificates == 1);

		// witnesses for owners and withdrawals are the same
		// we forbid withdrawals so that users cannot be tricked into witnessing
		// something unintentionally (e.g. an owner given by the staking key hash)
		DENY_UNLESS(numWithdrawals == 0);

		// mint must not be combined with pool registration certificates
		DENY_IF(includeMint);
		DENY_IF(numCollaterals != 0 || numRequiredSigners != 0);
		break;

	case SIGN_TX_SIGNINGMODE_ORDINARY_TX:
	case SIGN_TX_SIGNINGMODE_MULTISIG_TX:
		DENY_IF(numCollaterals != 0 || numRequiredSigners != 0);
		break;

	case SIGN_TX_SIGNINGMODE_PLUTUS_TX:
		WARN_IF(numCollaterals == 0);
		WARN_UNLESS(includeScriptDataHash);
		WARN();
		break;

	default:
		ASSERT(false);
	}

	WARN_IF(networkId != MAINNET_NETWORK_ID && networkId != TESTNET_NETWORK_ID);
	WARN_IF(protocolMagic != MAINNET_PROTOCOL_MAGIC);

	// Could be switched to POLICY_ALLOW_WITHOUT_PROMPT to skip initial "new transaction" question
	PROMPT();
}

// For each transaction UTxO input
security_policy_t policyForSignTxInput(sign_tx_signingmode_t txSigningMode)
{
	switch (txSigningMode) {
	case SIGN_TX_SIGNINGMODE_PLUTUS_TX:
		SHOW();
		break;

	case SIGN_TX_SIGNINGMODE_ORDINARY_TX:
	case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OWNER:
	case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OPERATOR:
	case SIGN_TX_SIGNINGMODE_MULTISIG_TX:
		ALLOW();
		break;

	default:
		ASSERT(false);
		DENY();
	}
	// We can't get here normally
	DENY();
}

// For each transaction (third-party) address output
security_policy_t policyForSignTxOutputAddressBytes(
        sign_tx_signingmode_t txSigningMode,
        const uint8_t* rawAddressBuffer, size_t rawAddressSize,
        const uint8_t networkId, const uint32_t protocolMagic,
        bool includeDatumHash
)
{

	ASSERT(rawAddressSize < BUFFER_SIZE_PARANOIA);

	// address type and network identification
	ASSERT(rawAddressSize >= 1);
	const address_type_t addressType = getAddressType(rawAddressBuffer[0]);
	const uint8_t addressNetworkId = getNetworkId(rawAddressBuffer[0]);

	if (includeDatumHash) {
		bool containsScriptHash = determineSpendingChoice(addressType) == SPENDING_SCRIPT_HASH || determineStakingChoice(addressType) == STAKING_SCRIPT_HASH;
		DENY_UNLESS(containsScriptHash);
	}

	switch (addressType) {

	case BYRON:
		DENY_IF(extractProtocolMagic(rawAddressBuffer, rawAddressSize) != protocolMagic);
		break;

	case REWARD_KEY:
	case REWARD_SCRIPT:
		DENY();
		break;

	default: // shelley types allowed in output
		DENY_IF(addressNetworkId != networkId);
		break;
	}

	switch (txSigningMode) {
	case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OWNER:
		// all the funds are provided by the operator
		// and thus outputs are irrelevant to the owner
		ALLOW();
		break;

	case SIGN_TX_SIGNINGMODE_ORDINARY_TX:
	case SIGN_TX_SIGNINGMODE_MULTISIG_TX:
	case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OPERATOR:
	case SIGN_TX_SIGNINGMODE_PLUTUS_TX:
		// We always show third-party output addresses
		SHOW();
		break;

	default:
		ASSERT(false);
	}

	DENY(); // should not be reached
}

// For each output given by derivation path
security_policy_t policyForSignTxOutputAddressParams(
        sign_tx_signingmode_t txSigningMode,
        const addressParams_t* params,
        const uint8_t networkId, const uint32_t protocolMagic,
        bool includeDatumHash
)
{
	DENY_UNLESS(isValidAddressParams(params));
	if (includeDatumHash) {
		bool containsScriptHash = determineSpendingChoice(params->type) == SPENDING_SCRIPT_HASH || determineStakingChoice(params->type) == STAKING_SCRIPT_HASH;
		DENY_UNLESS(containsScriptHash);
	}

	// address type and network identification
	switch (params->type) {

	case BYRON:
		DENY_IF(params->protocolMagic != protocolMagic);
		break;

	case REWARD_KEY:
	case REWARD_SCRIPT:
		DENY();
		break;

	default: // shelley types allowed in output
		DENY_IF(params->networkId != networkId);
		break;
	}

	switch (txSigningMode) {

	case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OPERATOR:
	case SIGN_TX_SIGNINGMODE_ORDINARY_TX: {
		DENY_UNLESS(determineSpendingChoice(params->type) == SPENDING_PATH);
		DENY_IF(violatesSingleAccountOrStoreIt(&params->spendingKeyPath));
		SHOW_UNLESS(is_standard_base_address(params));
		SHOW_IF(includeDatumHash);
		ALLOW();
		break;
	}

	case SIGN_TX_SIGNINGMODE_PLUTUS_TX:
	case SIGN_TX_SIGNINGMODE_MULTISIG_TX: {
		// all outputs should be given as external addresses
		DENY();
		break;
	}

	case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OWNER: {
		// we forbid these to avoid leaking information
		// (since the outputs are not shown, the user is unaware of what addresses are being derived)
		// it also makes the tx signing faster if all outputs are given as addresses
		DENY();
		break;
	}

	default:
		ASSERT(false);
	}

	DENY(); // should not be reached
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
security_policy_t policyForSignTxFee(
        sign_tx_signingmode_t txSigningMode,
        uint64_t fee MARK_UNUSED
)
{
	switch (txSigningMode) {

	case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OPERATOR:
	case SIGN_TX_SIGNINGMODE_ORDINARY_TX:
	case SIGN_TX_SIGNINGMODE_MULTISIG_TX:
	case SIGN_TX_SIGNINGMODE_PLUTUS_TX:
		// always show the fee if it is paid by the signer
		SHOW();
		break;

	case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OWNER:
		// fees are paid by the operator and are thus irrelevant for owners
		ALLOW();
		break;

	default:
		ASSERT(false);
	}

	DENY(); // should not be reached
}

// For transaction TTL
security_policy_t policyForSignTxTtl(uint32_t ttl MARK_UNUSED)
{

	// might be changed to POLICY_ALLOW_WITHOUT_PROMPT
	// to avoid bothering the user with TTL
	// (Daedalus does not show this)
	SHOW();
}

// a generic policy for all certificates
// does not evaluate aspects of specific certificates
security_policy_t policyForSignTxCertificate(
        sign_tx_signingmode_t txSigningMode,
        const certificate_type_t certificateType
)
{
	switch (txSigningMode) {

	case SIGN_TX_SIGNINGMODE_PLUTUS_TX:
	case SIGN_TX_SIGNINGMODE_ORDINARY_TX:
		DENY_IF(certificateType == CERTIFICATE_TYPE_STAKE_POOL_REGISTRATION);
		ALLOW();
		break;

	case SIGN_TX_SIGNINGMODE_MULTISIG_TX:
		DENY_IF(certificateType == CERTIFICATE_TYPE_STAKE_POOL_REGISTRATION);
		DENY_IF(certificateType == CERTIFICATE_TYPE_STAKE_POOL_RETIREMENT);
		ALLOW();
		break;

	case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OPERATOR:
	case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OWNER:
		DENY_UNLESS(certificateType == CERTIFICATE_TYPE_STAKE_POOL_REGISTRATION);
		ALLOW();
		break;

	default:
		ASSERT(false);
	}

	DENY(); // should not be reached
}

// for certificates concerning staking keys and stake delegation
security_policy_t policyForSignTxCertificateStaking(
        sign_tx_signingmode_t txSigningMode,
        const certificate_type_t certificateType,
        const stake_credential_t* stakeCredential
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

	switch (stakeCredential->type) {
	case STAKE_CREDENTIAL_KEY_PATH:
		DENY_UNLESS(bip44_isOrdinaryStakingKeyPath(&stakeCredential->keyPath));
		DENY_IF(violatesSingleAccountOrStoreIt(&stakeCredential->keyPath));
		switch (txSigningMode) {
		case SIGN_TX_SIGNINGMODE_ORDINARY_TX:
		case SIGN_TX_SIGNINGMODE_PLUTUS_TX:
			break;

		case SIGN_TX_SIGNINGMODE_MULTISIG_TX:
			DENY();
			break;

		default:
			ASSERT(false);
			break;
		}
		break;

	case STAKE_CREDENTIAL_SCRIPT_HASH:
		switch (txSigningMode) {
		case SIGN_TX_SIGNINGMODE_MULTISIG_TX:
		case SIGN_TX_SIGNINGMODE_PLUTUS_TX:
			break;

		case SIGN_TX_SIGNINGMODE_ORDINARY_TX:
			DENY();
			break;

		default:
			ASSERT(false);
			break;
		}
		break;

	case STAKE_CREDENTIAL_KEY_HASH:
		switch (txSigningMode) {
		case SIGN_TX_SIGNINGMODE_PLUTUS_TX:
			break;

		case SIGN_TX_SIGNINGMODE_ORDINARY_TX:
		case SIGN_TX_SIGNINGMODE_MULTISIG_TX:
			DENY();
			break;

		default:
			ASSERT(false);
			break;
		}
		break;

	default:
		ASSERT(false);
		break;
	}

	PROMPT();
}

security_policy_t policyForSignTxCertificateStakePoolRetirement(
        sign_tx_signingmode_t txSigningMode,
        const bip44_path_t* poolIdPath,
        uint64_t epoch MARK_UNUSED
)
{
	switch (txSigningMode) {

	case SIGN_TX_SIGNINGMODE_ORDINARY_TX:
		DENY_UNLESS(bip44_isPoolColdKeyPath(poolIdPath));
		PROMPT();
		break;

	default:
		// in other signing modes, the tx containing pool retirement certificate
		// should have already been reported as invalid
		ASSERT(false);
	}

	DENY(); // should not be reached
}

security_policy_t policyForSignTxStakePoolRegistrationInit(
        sign_tx_signingmode_t txSigningMode,
        uint32_t numOwners
)
{
	switch (txSigningMode) {
	case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OWNER:
		// there should be exactly one owner given by path for which we provide a witness
		DENY_IF(numOwners == 0);
		ALLOW();
		break;

	case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OPERATOR:
		ALLOW();
		break;

	case SIGN_TX_SIGNINGMODE_ORDINARY_TX:
	case SIGN_TX_SIGNINGMODE_MULTISIG_TX:
	case SIGN_TX_SIGNINGMODE_PLUTUS_TX:
		DENY();
		break;

	default:
		ASSERT(false);
		break;
	}

	DENY(); // should not be reached
}

security_policy_t policyForSignTxStakePoolRegistrationPoolId(
        sign_tx_signingmode_t txSigningMode,
        const pool_id_t* poolId
)
{
	switch (txSigningMode) {
	case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OWNER:
		DENY_UNLESS(poolId->keyReferenceType == KEY_REFERENCE_HASH);
		SHOW();
		break;

	case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OPERATOR:
		DENY_UNLESS(poolId->keyReferenceType == KEY_REFERENCE_PATH);
		SHOW();
		break;

	default:
		ASSERT(false);
	}

	DENY(); // should not be reached
}

security_policy_t policyForSignTxStakePoolRegistrationVrfKey(
        sign_tx_signingmode_t txSigningMode
)
{
	switch (txSigningMode) {
	case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OWNER:
		ALLOW();
		break;

	case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OPERATOR:
		SHOW();
		break;

	default:
		ASSERT(false);
	}

	DENY(); // should not be reached
}

security_policy_t policyForSignTxStakePoolRegistrationRewardAccount(
        sign_tx_signingmode_t txSigningMode,
        const reward_account_t* poolRewardAccount MARK_UNUSED
)
{
	switch (txSigningMode) {
	case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OWNER:
	case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OPERATOR:
		SHOW();
		break;

	default:
		ASSERT(false);
	}

	DENY(); // should not be reached
}

security_policy_t policyForSignTxStakePoolRegistrationOwner(
        const sign_tx_signingmode_t txSigningMode,
        const pool_owner_t* owner,
        uint32_t numOwnersGivenByPath
)
{
	if (owner->keyReferenceType == KEY_REFERENCE_PATH) {
		DENY_UNLESS(bip44_isOrdinaryStakingKeyPath(&owner->path));
		DENY_IF(violatesSingleAccountOrStoreIt(&owner->path));
	}

	switch (txSigningMode) {
	case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OWNER:
		// can be 0 while processing owners given by hash
		// or if no path owner is given at all (then we just compute the tx hash and don't allow witnesses)
		DENY_UNLESS(numOwnersGivenByPath <= 1);
		SHOW();
		break;

	case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OPERATOR:
		ASSERT(numOwnersGivenByPath == 0);
		DENY_UNLESS(owner->keyReferenceType == KEY_REFERENCE_HASH);
		SHOW();
		break;

	default:
		ASSERT(false);
	}
	DENY(); // should not be reached
}

security_policy_t policyForSignTxStakePoolRegistrationRelay(
        const sign_tx_signingmode_t txSigningMode,
        const pool_relay_t* relay MARK_UNUSED
)
{
	switch (txSigningMode) {
	case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OWNER:
		ALLOW();
		break;

	case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OPERATOR:
		SHOW();
		break;

	default:
		ASSERT(false);
	}

	DENY(); // should not be reached
}

security_policy_t policyForSignTxStakePoolRegistrationMetadata()
{
	SHOW();
}

security_policy_t policyForSignTxStakePoolRegistrationNoMetadata()
{
	SHOW();
}

security_policy_t policyForSignTxStakePoolRegistrationConfirm(
        uint32_t numOwners, uint32_t numRelays
)
{
	PROMPT_IF(numOwners == 0);
	PROMPT_IF(numRelays == 0);

	ALLOW();
}

// For each withdrawal
security_policy_t policyForSignTxWithdrawal(
        sign_tx_signingmode_t txSigningMode,
        const stake_credential_t* stakeCredential
)
{
	switch (stakeCredential->type) {
	case STAKE_CREDENTIAL_KEY_PATH:
		DENY_UNLESS(bip44_isOrdinaryStakingKeyPath(&stakeCredential->keyPath));
		DENY_IF(violatesSingleAccountOrStoreIt(&stakeCredential->keyPath));
		switch (txSigningMode) {
		case SIGN_TX_SIGNINGMODE_ORDINARY_TX:
		case SIGN_TX_SIGNINGMODE_PLUTUS_TX:
			SHOW();
			break;

		case SIGN_TX_SIGNINGMODE_MULTISIG_TX:
			DENY();
			break;

		default:
			ASSERT(false);
			break;
		}
		break;

	case STAKE_CREDENTIAL_SCRIPT_HASH:
		switch (txSigningMode) {
		case SIGN_TX_SIGNINGMODE_MULTISIG_TX:
		case SIGN_TX_SIGNINGMODE_PLUTUS_TX:
			SHOW();
			break;

		case SIGN_TX_SIGNINGMODE_ORDINARY_TX:
			DENY();
			break;

		default:
			ASSERT(false);
			break;
		}
		break;

	case STAKE_CREDENTIAL_KEY_HASH:
		switch (txSigningMode) {
		case SIGN_TX_SIGNINGMODE_PLUTUS_TX:
			SHOW();
			break;

		case SIGN_TX_SIGNINGMODE_ORDINARY_TX:
		case SIGN_TX_SIGNINGMODE_MULTISIG_TX:
			DENY();
			break;

		default:
			ASSERT(false);
			break;
		}

	default:
		ASSERT(false);
		break;
	}

	DENY(); // should not be reached
}

static inline security_policy_t _ordinaryWitnessPolicy(const bip44_path_t* path, bool mintPresent)
{
	switch (bip44_classifyPath(path)) {
	case PATH_ORDINARY_SPENDING_KEY:
	case PATH_ORDINARY_STAKING_KEY:
		DENY_IF(violatesSingleAccountOrStoreIt(path));
		WARN_UNLESS(bip44_isPathReasonable(path));
		ALLOW();
		break;

	case PATH_POOL_COLD_KEY:
		WARN_UNLESS(bip44_isPathReasonable(path));
		SHOW();
		break;

	case PATH_MINT_KEY:
		DENY_UNLESS(mintPresent);
		SHOW();
		break;

	default:
		DENY();
		break;
	}
}

static inline security_policy_t _multisigWitnessPolicy(const bip44_path_t* path, bool mintPresent)
{
	switch (bip44_classifyPath(path)) {
	case PATH_MULTISIG_SPENDING_KEY:
	case PATH_MULTISIG_STAKING_KEY:
		WARN_UNLESS(bip44_isPathReasonable(path));
		SHOW();
		break;

	case PATH_MINT_KEY:
		DENY_UNLESS(mintPresent);
		SHOW();

	default:
		DENY();
		break;
	}
}

static inline security_policy_t _plutusWitnessPolicy(const bip44_path_t* path, bool mintPresent)
{
	switch (bip44_classifyPath(path)) {
	case PATH_ORDINARY_SPENDING_KEY:
	case PATH_ORDINARY_STAKING_KEY:
	case PATH_POOL_COLD_KEY:
	case PATH_MULTISIG_SPENDING_KEY:
	case PATH_MULTISIG_STAKING_KEY:
		WARN_UNLESS(bip44_isPathReasonable(path));
		SHOW();
		break;

	case PATH_MINT_KEY:
		DENY_UNLESS(mintPresent);
		SHOW();

	default:
		DENY();
		break;
	}
}

static inline security_policy_t _poolRegistrationOwnerWitnessPolicy(const bip44_path_t* witnessPath, const bip44_path_t* poolOwnerPath)
{
	switch (bip44_classifyPath(witnessPath)) {

	case PATH_ORDINARY_STAKING_KEY:
		if (poolOwnerPath != NULL) {
			// an owner was given by path
			// the witness path must be identical
			DENY_UNLESS(bip44_pathsEqual(witnessPath, poolOwnerPath));
		} else {
			// no owner was given by path
			// we must not allow witnesses because they might witness owners given by key hash
			DENY();
		}
		WARN_UNLESS(bip44_isPathReasonable(witnessPath));
		SHOW();
		break;

	default:
		DENY();
		break;
	}
}

static inline security_policy_t _poolRegistrationOperatorWitnessPolicy(const bip44_path_t* path)
{
	switch (bip44_classifyPath(path)) {

	case PATH_ORDINARY_SPENDING_KEY:
	case PATH_POOL_COLD_KEY:
		WARN_UNLESS(bip44_isPathReasonable(path));
		SHOW();
		break;

	default:
		DENY();
		break;
	}
}

// For each transaction witness
// Note: witnesses reveal public key of an address
// and Ledger *does not* check whether they correspond to
// previously declared inputs and certificates
security_policy_t policyForSignTxWitness(
        sign_tx_signingmode_t txSigningMode,
        const bip44_path_t* witnessPath,
        bool mintPresent,
        const bip44_path_t* poolOwnerPath
)
{
	switch (txSigningMode) {
	case SIGN_TX_SIGNINGMODE_ORDINARY_TX:
		return _ordinaryWitnessPolicy(witnessPath, mintPresent);

	case SIGN_TX_SIGNINGMODE_MULTISIG_TX:
		return _multisigWitnessPolicy(witnessPath, mintPresent);

	case SIGN_TX_SIGNINGMODE_PLUTUS_TX:
		return _plutusWitnessPolicy(witnessPath, mintPresent);

	case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OWNER:
		return _poolRegistrationOwnerWitnessPolicy(witnessPath, poolOwnerPath);

	case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OPERATOR:
		return _poolRegistrationOperatorWitnessPolicy(witnessPath);

	default:
		ASSERT(false);
	}

	DENY(); // should not be reached
}

security_policy_t policyForSignTxAuxData(aux_data_type_t auxDataType MARK_UNUSED)
{
	SHOW();
}

security_policy_t policyForSignTxValidityIntervalStart()
{
	SHOW();
}

security_policy_t policyForSignTxMintInit(const sign_tx_signingmode_t txSigningMode)
{
	switch (txSigningMode) {
	case SIGN_TX_SIGNINGMODE_ORDINARY_TX:
	case SIGN_TX_SIGNINGMODE_MULTISIG_TX:
	case SIGN_TX_SIGNINGMODE_PLUTUS_TX:
		SHOW();
		break;

	default:
		ASSERT(false);
	}

	DENY(); // should not be reached
}


security_policy_t policyForSignTxMintConfirm(security_policy_t outputPolicy)
{
	switch (outputPolicy) {
	case POLICY_ALLOW_WITHOUT_PROMPT:
		ALLOW();
		break;

	case POLICY_SHOW_BEFORE_RESPONSE:
		PROMPT();
		break;

	default:
		ASSERT(false);
	}

	DENY(); // should not be reached
}

security_policy_t policyForSignTxScriptDataHash(const sign_tx_signingmode_t txSigningMode)
{
	switch (txSigningMode) {
	case SIGN_TX_SIGNINGMODE_ORDINARY_TX:
	case SIGN_TX_SIGNINGMODE_MULTISIG_TX:
	case SIGN_TX_SIGNINGMODE_PLUTUS_TX:
		SHOW();
		break;

	case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OWNER:
	case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OPERATOR:
		DENY();
		break;
	default:
		ASSERT(false);
	}

	DENY(); // should not be reached
}

security_policy_t policyForSignTxCollaterals(const sign_tx_signingmode_t txSigningMode)
{
	switch (txSigningMode) {
	case SIGN_TX_SIGNINGMODE_PLUTUS_TX:
		SHOW();
		break;

	case SIGN_TX_SIGNINGMODE_ORDINARY_TX:
	case SIGN_TX_SIGNINGMODE_MULTISIG_TX:
	case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OWNER:
	case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OPERATOR:
		DENY();
		break;

	default:
		ASSERT(false);
	}

	DENY();
}

security_policy_t policyForSignTxRequiredSigners(const sign_tx_signingmode_t txSigningMode)
{
	//TODO rework when more information is available
	switch (txSigningMode) {
	case SIGN_TX_SIGNINGMODE_PLUTUS_TX:
		SHOW();
		break;

	case SIGN_TX_SIGNINGMODE_ORDINARY_TX:
	case SIGN_TX_SIGNINGMODE_MULTISIG_TX:
	case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OWNER:
	case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OPERATOR:
		DENY();
		break;

	default:
		ASSERT(false);
	}

	DENY();
}

security_policy_t policyForSignTxConfirm()
{
	PROMPT();
}

security_policy_t policyForCatalystRegistrationVotingRewardsAddressParams(
        const addressParams_t* params,
        const uint8_t networkId
)
{
	DENY_UNLESS(isValidAddressParams(params));
	DENY_UNLESS(isShelleyAddressType(params->type));
	DENY_IF(params->networkId != networkId);

	WARN_UNLESS(is_reward_address(params) || is_standard_base_address(params));

	SHOW();
}

security_policy_t policyForCatalystRegistrationStakingKey(
        const bip44_path_t* stakingKeyPath
)
{
	DENY_UNLESS(bip44_isOrdinaryStakingKeyPath(stakingKeyPath));
	WARN_UNLESS(bip44_hasReasonableAccount(stakingKeyPath));

	SHOW();
}

security_policy_t policyForCatalystRegistrationVotingKey()
{
	SHOW();
}

security_policy_t policyForCatalystRegistrationNonce()
{
	SHOW();
}

security_policy_t policyForCatalystRegistrationConfirm()
{
	PROMPT();
}

security_policy_t policyForSignOpCert(const bip44_path_t* poolColdKeyPathSpec)
{
	switch (bip44_classifyPath(poolColdKeyPathSpec)) {

	case PATH_POOL_COLD_KEY:
		if (bip44_isPathReasonable(poolColdKeyPathSpec)) {
			PROMPT();
		} else {
			WARN();
		}
		break;

	default:
		DENY();
		break;
	}

	DENY(); // should not be reached
}
