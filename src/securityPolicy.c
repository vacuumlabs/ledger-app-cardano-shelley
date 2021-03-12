#include "addressUtilsShelley.h"
#include "addressUtilsByron.h"
#include "bip44.h"
#include "cardano.h"

#include "securityPolicy.h"

// Helper macros

// staking key path has the same account as the spending key path
static inline bool is_standard_base_address(const addressParams_t* addressParams)
{
	ASSERT(isValidAddressParams(addressParams));

#define CHECK(cond) if (!(cond)) return false
	CHECK(addressParams->type == BASE);
	CHECK(addressParams->stakingChoice == STAKING_KEY_PATH);

	CHECK(bip44_classifyPath(&addressParams->spendingKeyPath) == PATH_WALLET_SPENDING_KEY);
	CHECK(bip44_isPathReasonable(&addressParams->spendingKeyPath));

	CHECK(bip44_classifyPath(&addressParams->stakingKeyPath) == PATH_WALLET_STAKING_KEY);
	CHECK(bip44_isPathReasonable(&addressParams->stakingKeyPath));

	CHECK(
	        bip44_getAccount(&addressParams->stakingKeyPath) ==
	        bip44_getAccount(&addressParams->spendingKeyPath)
	);

	return true;
#undef CHECK
}

bool is_tx_network_verifiable(
        sign_tx_usecase_t signTxUsecase,
        uint16_t numOutputs,
        uint16_t numWithdrawals
)
{
	if (numOutputs > 0) return true;
	if (numWithdrawals > 0) return true;

	switch (signTxUsecase) {

	case SIGN_TX_USECASE_POOL_REGISTRATION_OPERATOR:
	case SIGN_TX_USECASE_POOL_REGISTRATION_OWNER:
		// pool registration certificate contains pool reward account
		return true;

	default:
		return false;
	}
}


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


security_policy_t policyForGetPublicKeysInit(size_t numPaths)
{
	PROMPT_IF(numPaths > 1);

	ALLOW();
}

// Get extended public key and return it to the host
security_policy_t policyForGetExtendedPublicKey(const bip44_path_t* pathSpec)
{
	switch (bip44_classifyPath(pathSpec)) {

	case PATH_WALLET_ACCOUNT:
	case PATH_WALLET_SPENDING_KEY:
	case PATH_WALLET_STAKING_KEY:
	case PATH_POOL_COLD_KEY:
		if (bip44_isPathReasonable(pathSpec)) {
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

// Get extended public key and return it to the host within bulk key export
security_policy_t policyForGetExtendedPublicKeyBulkExport(const bip44_path_t* pathSpec)
{
	switch (bip44_classifyPath(pathSpec)) {

	case PATH_WALLET_ACCOUNT:
	case PATH_WALLET_SPENDING_KEY:
	case PATH_WALLET_STAKING_KEY:
		if (bip44_isPathReasonable(pathSpec)) {
			ALLOW();
		} else {
			WARN();
		}
		break;

	case PATH_POOL_COLD_KEY:
		if (bip44_isPathReasonable(pathSpec)) {
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

// Derive address and return it to the host
security_policy_t policyForReturnDeriveAddress(const addressParams_t* addressParams)
{
	DENY_UNLESS(isValidAddressParams(addressParams));

	switch (bip44_classifyPath(&addressParams->spendingKeyPath)) {

	case PATH_WALLET_SPENDING_KEY:
	case PATH_WALLET_STAKING_KEY:
		if (bip44_isPathReasonable(&addressParams->spendingKeyPath)) {
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

// Derive address and show it to the user
security_policy_t policyForShowDeriveAddress(const addressParams_t* addressParams)
{
	DENY_UNLESS(isValidAddressParams(addressParams));

	switch (bip44_classifyPath(&addressParams->spendingKeyPath)) {

	case PATH_WALLET_SPENDING_KEY:
	case PATH_WALLET_STAKING_KEY:
		if (bip44_isPathReasonable(&addressParams->spendingKeyPath)) {
			SHOW();
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


// Initiate transaction signing
security_policy_t policyForSignTxInit(
        sign_tx_usecase_t signTxUsecase,
        uint8_t networkId,
        uint32_t protocolMagic,
        uint16_t numOutputs,
        uint16_t numWithdrawals
)
{
	// Deny shelley mainnet with weird byron protocol magic
	DENY_IF(networkId == MAINNET_NETWORK_ID && protocolMagic != MAINNET_PROTOCOL_MAGIC);
	// Note: testnets can still use byron mainnet protocol magic so we can't deny the opposite direction

	WARN_IF(!is_tx_network_verifiable(numOutputs, numWithdrawals, signTxUsecase));

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
        sign_tx_usecase_t signTxUsecase,
        const uint8_t* rawAddressBuffer, size_t rawAddressSize,
        const uint8_t networkId, const uint32_t protocolMagic
)
{
	// network identification must be consistent across tx
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

	switch (signTxUsecase) {
	case SIGN_TX_USECASE_ORDINARY_TX:
		// We always show third-party output addresses
		SHOW();
		break;

	case SIGN_TX_USECASE_POOL_REGISTRATION_OWNER:
		// all the funds are provided by the operator
		// and thus outputs are irrelevant to the owner
		ALLOW();
		break;

	case SIGN_TX_USECASE_POOL_REGISTRATION_OPERATOR:
		SHOW();
		break;

	default:
		ASSERT(false);
	}

	DENY(); // should not be reached
}

// For each output given by derivation path
security_policy_t policyForSignTxOutputAddressParams(
        sign_tx_usecase_t signTxUsecase,
        const addressParams_t* params,
        const uint8_t networkId, const uint32_t protocolMagic
)
{
	DENY_UNLESS(isValidAddressParams(params));

	// network identification should be consistent across tx
	if (params->type == BYRON) {
		DENY_IF(params->protocolMagic != protocolMagic);
	} else { // shelley
		DENY_IF(params->networkId != networkId);
	}

	switch (signTxUsecase) {

	case SIGN_TX_USECASE_POOL_REGISTRATION_OPERATOR:
	case SIGN_TX_USECASE_ORDINARY_TX: {
		switch (bip44_classifyPath(&params->spendingKeyPath)) {

		case PATH_WALLET_SPENDING_KEY:
			SHOW_UNLESS(bip44_isPathReasonable(&params->spendingKeyPath));
			SHOW_UNLESS(is_standard_base_address(params));
			ALLOW();
			break;

		default:
			DENY();
			break;
		}

		break;
	}
	case SIGN_TX_USECASE_POOL_REGISTRATION_OWNER: {
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
        sign_tx_usecase_t signTxUsecase,
        uint64_t fee MARK_UNUSED
)
{
	switch (signTxUsecase) {

	case SIGN_TX_USECASE_POOL_REGISTRATION_OPERATOR:
	case SIGN_TX_USECASE_ORDINARY_TX:
		// always show the fee if it is paid by the signer
		SHOW();
		break;

	case SIGN_TX_USECASE_POOL_REGISTRATION_OWNER:
		// fees are paid by the operator and are thus irrelevant for owners
		ALLOW();
		break;

	default:
		ASSERT(false);
	}

	DENY(); // should not be reached
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
// does not evaluate aspects of specific certificates
security_policy_t policyForSignTxCertificate(
        sign_tx_usecase_t signTxUsecase,
        const certificate_type_t certificateType
)
{
	switch (signTxUsecase) {
	case SIGN_TX_USECASE_ORDINARY_TX:
		DENY_IF(certificateType == CERTIFICATE_TYPE_STAKE_POOL_REGISTRATION);
		ALLOW();
		break;

	case SIGN_TX_USECASE_POOL_REGISTRATION_OPERATOR:
	case SIGN_TX_USECASE_POOL_REGISTRATION_OWNER:
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

security_policy_t policyForSignTxCertificateStakePoolRetirement(
        sign_tx_usecase_t signTxUsecase,
        const bip44_path_t* poolIdPath,
        uint64_t epoch MARK_UNUSED
)
{
	switch (signTxUsecase) {

	case SIGN_TX_USECASE_ORDINARY_TX:
		DENY_UNLESS(bip44_isValidPoolColdKeyPath(poolIdPath));
		PROMPT();
		break;

	default:
		// in other usecases, the tx containing pool retirement certificate
		// should have already been reported as invalid
		ASSERT(false);
	}

	DENY(); // should not be reached
}

security_policy_t policyForSignTxStakePoolRegistrationPoolId(
        sign_tx_usecase_t signTxUsecase,
        const pool_id_t* poolId
)
{
	switch (signTxUsecase) {
	case SIGN_TX_USECASE_POOL_REGISTRATION_OWNER:
		DENY_UNLESS(poolId->keyReferenceType == KEY_REFERENCE_HASH);
		SHOW();
		break;

	case SIGN_TX_USECASE_POOL_REGISTRATION_OPERATOR:
		DENY_UNLESS(poolId->keyReferenceType == KEY_REFERENCE_PATH);
		SHOW();
		break;

	default:
		ASSERT(false);
	}

	DENY(); // should not be reached
}

security_policy_t policyForSignTxStakePoolRegistrationVrfKey(
        sign_tx_usecase_t signTxUsecase
)
{
	switch (signTxUsecase) {
	case SIGN_TX_USECASE_POOL_REGISTRATION_OWNER:
		ALLOW();
		break;

	case SIGN_TX_USECASE_POOL_REGISTRATION_OPERATOR:
		SHOW();
		break;

	default:
		ASSERT(false);
	}

	DENY(); // should not be reached
}

security_policy_t policyForSignTxStakePoolRegistrationRewardAccount(
        sign_tx_usecase_t signTxUsecase,
        const reward_account_t* poolRewardAccount MARK_UNUSED
)
{
	switch (signTxUsecase) {
	case SIGN_TX_USECASE_POOL_REGISTRATION_OWNER:
	case SIGN_TX_USECASE_POOL_REGISTRATION_OPERATOR:
		SHOW();
		break;

	default:
		ASSERT(false);
	}

	DENY(); // should not be reached
}

security_policy_t policyForSignTxStakePoolRegistrationOwner(
        const sign_tx_usecase_t signTxUsecase,
        const pool_owner_t* owner
)
{
	if (owner->keyReferenceType == KEY_REFERENCE_PATH) {
		DENY_UNLESS(bip44_isValidStakingKeyPath(&owner->path));
	}

	switch (signTxUsecase) {
	case SIGN_TX_USECASE_POOL_REGISTRATION_OWNER:
		SHOW();
		break;

	case SIGN_TX_USECASE_POOL_REGISTRATION_OPERATOR:
		DENY_UNLESS(owner->keyReferenceType == KEY_REFERENCE_HASH);
		SHOW();
		break;

	default:
		ASSERT(false);
	}
	DENY(); // should not be reached
}

security_policy_t policyForSignTxStakePoolRegistrationRelay(
        const sign_tx_usecase_t signTxUsecase,
        const pool_relay_t* relay MARK_UNUSED
)
{
	switch (signTxUsecase) {
	case SIGN_TX_USECASE_POOL_REGISTRATION_OWNER:
		ALLOW();
		break;

	case SIGN_TX_USECASE_POOL_REGISTRATION_OPERATOR:
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
security_policy_t policyForSignTxWithdrawal()
{
	// No need to check withdrawals
	SHOW();
}


// For each transaction witness
// Note: witnesses reveal public key of an address
// and Ledger *does not* check whether they correspond to
// previously declared inputs and certificates
security_policy_t policyForSignTxWitness(
        sign_tx_usecase_t signTxUsecase,
        const bip44_path_t* pathSpec
)
{
	switch (signTxUsecase) {

	case SIGN_TX_USECASE_ORDINARY_TX: {

		switch (bip44_classifyPath(pathSpec)) {

		case PATH_WALLET_SPENDING_KEY:
		case PATH_WALLET_STAKING_KEY:
		case PATH_POOL_COLD_KEY:
			if (bip44_isPathReasonable(pathSpec)) {
				ALLOW();
			} else {
				WARN();
			}
			break;

		default:
			DENY();
			break;
		}

		break;
	}

	case SIGN_TX_USECASE_POOL_REGISTRATION_OWNER: {

		switch (bip44_classifyPath(pathSpec)) {

		case PATH_WALLET_STAKING_KEY:
			if (bip44_isPathReasonable(pathSpec)) {
				ALLOW();
			} else {
				WARN();
			}
			break;

		default:
			DENY();
			break;
		}

		break;
	}

	case SIGN_TX_USECASE_POOL_REGISTRATION_OPERATOR: {

		switch (bip44_classifyPath(pathSpec)) {

		case PATH_WALLET_SPENDING_KEY:
		case PATH_POOL_COLD_KEY:
			if (bip44_isPathReasonable(pathSpec)) {
				ALLOW();
			} else {
				WARN();
			}
			break;

		default:
			DENY();
			break;
		}

		break;
	}

	default:
		ASSERT(false);
	}

	DENY(); // should not be reached
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
