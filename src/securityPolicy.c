#include "addressUtilsShelley.h"
#include "addressUtilsByron.h"
#include "app_mode.h"
#include "bip44.h"
#include "cardano.h"
#include "signTxUtils.h"

#include "securityPolicy.h"

// helper functions

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

static address_type_t getDestinationAddressType(const tx_output_destination_t* destination)
{
	switch (destination->type) {
	case DESTINATION_DEVICE_OWNED:
		return destination->params->type;
	case DESTINATION_THIRD_PARTY:
		return getAddressType(destination->address.buffer[0]);
	default:
		ASSERT(false);
	}
}

// useful shortcuts

// WARNING: unless you are doing something exceptional,
// policies must come in the order DENY > WARN > PROMPT/SHOW > ALLOW

#define DENY()                            return POLICY_DENY;
#define DENY_IF(expr)        if (expr)    return POLICY_DENY;
#define DENY_UNLESS(expr)    if (!(expr)) return POLICY_DENY;

#define WARN()                            return POLICY_PROMPT_WARN_UNUSUAL;
#define WARN_IF(expr)        if (expr)    return POLICY_PROMPT_WARN_UNUSUAL;
#define WARN_UNLESS(expr)    if (!(expr)) return POLICY_PROMPT_WARN_UNUSUAL;

#define PROMPT()                          return POLICY_PROMPT_BEFORE_RESPONSE;
#define PROMPT_IF(expr)      if (expr)    return POLICY_PROMPT_BEFORE_RESPONSE;
#define PROMPT_UNLESS(expr)  if (!(expr)) return POLICY_PROMPT_BEFORE_RESPONSE;

#define ALLOW()                           return POLICY_ALLOW_WITHOUT_PROMPT;
#define ALLOW_IF(expr)       if (expr)    return POLICY_ALLOW_WITHOUT_PROMPT;

#define SHOW()                            return POLICY_SHOW_BEFORE_RESPONSE;
#define SHOW_IF(expr)        if (expr)    return POLICY_SHOW_BEFORE_RESPONSE;
#define SHOW_UNLESS(expr)    if (!(expr)) return POLICY_SHOW_BEFORE_RESPONSE;


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

	case PATH_GOVERNANCE_VOTING_ACCOUNT:
	case PATH_GOVERNANCE_VOTING_KEY:

		ALLOW();
		break;

	default:
		DENY();
		break;
	}

	DENY(); // should not be reached
}

// Initiate getting extended public key or extended public key bulk
security_policy_t policyForGetPublicKeysInit(uint32_t numPaths)
{
	// in a bulk key export, some keys are hidden, the user must be notified
	PROMPT_IF(numPaths > 1);

	// for a single key, the policy for displaying it is determined later
	ALLOW();
}

// Get extended public key and return it to the host
security_policy_t policyForGetExtendedPublicKey(const bip44_path_t* pathSpec)
{
	switch (bip44_classifyPath(pathSpec)) {

	case PATH_ORDINARY_ACCOUNT:
		WARN_UNLESS(bip44_isPathReasonable(pathSpec));
		// show Byron paths
		PROMPT_UNLESS(bip44_hasShelleyPrefix(pathSpec));

		// in expert mode, do not export keys without permission
		PROMPT_IF(app_mode_expert());
		// do not bother the user with confirmation --- required by LedgerLive to improve UX
		ALLOW();
		break;

	case PATH_MULTISIG_ACCOUNT:
		WARN_UNLESS(bip44_isPathReasonable(pathSpec));
		// ask for confirmation, multisig users need high awareness of what keys are being used
		PROMPT();
		break;

	case PATH_MINT_KEY:
		WARN_UNLESS(bip44_isPathReasonable(pathSpec));
		// used rarely, so making the user aware of the export does not hamper him
		// but could be relaxed to expert mode if needed
		PROMPT();
		break;

	case PATH_POOL_COLD_KEY:
		WARN_UNLESS(bip44_isPathReasonable(pathSpec));
		// used rarely, so making the user aware of the export does not hamper him
		// but could be relaxed to expert mode if needed
		PROMPT();
		break;

	case PATH_GOVERNANCE_VOTING_ACCOUNT:
		WARN_UNLESS(bip44_isPathReasonable(pathSpec));

		// in expert mode, do not export keys without permission
		PROMPT_IF(app_mode_expert());
		// do not bother the user with confirmation, similar to ordinary account
		ALLOW();
		break;

	case PATH_ORDINARY_SPENDING_KEY:
	case PATH_ORDINARY_STAKING_KEY:
	case PATH_MULTISIG_SPENDING_KEY:
	case PATH_MULTISIG_STAKING_KEY:
	case PATH_GOVERNANCE_VOTING_KEY:
		WARN_UNLESS(bip44_isPathReasonable(pathSpec));
		// ask for permission (it is unusual if client asks this instead of the account key)
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
	case PATH_GOVERNANCE_VOTING_ACCOUNT:
	case PATH_GOVERNANCE_VOTING_KEY:
		WARN_UNLESS(bip44_isPathReasonable(pathSpec));
		// we do not show these paths since there may be many of them
		ALLOW();
		break;

	case PATH_POOL_COLD_KEY:
		WARN_UNLESS(bip44_isPathReasonable(pathSpec));
		// but ask for permission when pool cold key is requested
		PROMPT();
		break;

	default:
		DENY();
		break;
	}

	DENY(); // should not be reached
}

// common policy for DENY and WARN cases in returnDeriveAddress and showDeriveAddress
// successPolicy is returned if no DENY or WARN applies
static security_policy_t _policyForDeriveAddress(const addressParams_t* addressParams, security_policy_t successPolicy)
{
	DENY_UNLESS(isValidAddressParams(addressParams));

	switch (addressParams->type) {

	case BASE_PAYMENT_KEY_STAKE_KEY:
		// unusual path
		WARN_UNLESS(bip44_isPathReasonable(&addressParams->spendingKeyPath));
		WARN_IF(
		        addressParams->stakingDataSource == STAKING_KEY_PATH &&
		        !bip44_isPathReasonable(&addressParams->stakingKeyPath)
		);
		break;

	case BASE_PAYMENT_KEY_STAKE_SCRIPT:
	case POINTER_KEY:
	case ENTERPRISE_KEY:
	case BYRON:
		// unusual path
		WARN_UNLESS(bip44_isPathReasonable(&addressParams->spendingKeyPath));
		break;

	case BASE_PAYMENT_SCRIPT_STAKE_KEY:
	case REWARD_KEY:
		// we only support derivation based on key path
		DENY_IF(addressParams->stakingDataSource != STAKING_KEY_PATH);

		// unusual path
		WARN_UNLESS(bip44_isPathReasonable(&addressParams->stakingKeyPath));
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
	// in expert mode, do not export addresses without permission
	security_policy_t policy = app_mode_expert() ?
	                           POLICY_PROMPT_BEFORE_RESPONSE :
	                           POLICY_ALLOW_WITHOUT_PROMPT;

	return _policyForDeriveAddress(addressParams, policy);
}

// Derive address and show it to the user
security_policy_t policyForShowDeriveAddress(const addressParams_t* addressParams)
{
	return _policyForDeriveAddress(addressParams, POLICY_SHOW_BEFORE_RESPONSE);
}

// true iff network is the standard mainnet or testnet
bool isNetworkUsual(uint32_t networkId, uint32_t protocolMagic)
{
	if (networkId == MAINNET_NETWORK_ID && protocolMagic == MAINNET_PROTOCOL_MAGIC) {
		return true;
	}

	const bool knownTestnetProtocolMagic =
	        protocolMagic == TESTNET_PROTOCOL_MAGIC_LEGACY ||
	        protocolMagic == TESTNET_PROTOCOL_MAGIC_PREPROD ||
	        protocolMagic == TESTNET_PROTOCOL_MAGIC_PREVIEW;

	if (networkId == TESTNET_NETWORK_ID && knownTestnetProtocolMagic) {
		return true;
	}

	return false;
}

// true iff tx contains an element with network id
bool isTxNetworkIdVerifiable(
        bool includeNetworkId,
        uint32_t numOutputs,
        uint32_t numWithdrawals,
        sign_tx_signingmode_t txSigningMode
)
{
	if (includeNetworkId) return true;

	if (numOutputs > 0) return true;
	if (numWithdrawals > 0) return true;

	switch (txSigningMode) {

	case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OPERATOR:
	case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OWNER:
		// pool registration certificate contains pool reward account
		return true;

	default:
		return false;
	}
}

bool needsRunningScriptWarning(int32_t numCollateralInputs)
{
	return numCollateralInputs > 0;
}

bool needsMissingCollateralWarning(sign_tx_signingmode_t signingMode, uint32_t numCollateralInputs)
{
	const bool collateralExpected = (signingMode == SIGN_TX_SIGNINGMODE_PLUTUS_TX);
	return collateralExpected && (numCollateralInputs == 0);
}

bool needsUnknownCollateralWarning(sign_tx_signingmode_t signingMode, bool includesTotalCollateral)
{
	const bool collateralExpected = (signingMode == SIGN_TX_SIGNINGMODE_PLUTUS_TX);
	return collateralExpected && (!includesTotalCollateral);
}

bool needsMissingScriptDataHashWarning(sign_tx_signingmode_t signingMode, bool includesScriptDataHash)
{
	const bool scriptDataHashExpected = (signingMode == SIGN_TX_SIGNINGMODE_PLUTUS_TX);
	return scriptDataHashExpected && !includesScriptDataHash;
}

// Initiate transaction signing
security_policy_t policyForSignTxInit(
        sign_tx_signingmode_t txSigningMode,
        uint32_t networkId,
        uint32_t protocolMagic,
        uint16_t numOutputs,
        uint16_t numCertificates,
        uint16_t numWithdrawals,
        bool includeMint,
        bool includeScriptDataHash,
        uint16_t numCollateralInputs,
        uint16_t numRequiredSigners,
        bool includeNetworkId,
        bool includeCollateralOutput,
        bool includeTotalCollateral,
        uint16_t numReferenceInputs
)
{
	DENY_UNLESS(isValidNetworkId(networkId));
	// Deny shelley mainnet with weird byron protocol magic
	DENY_IF(networkId == MAINNET_NETWORK_ID && protocolMagic != MAINNET_PROTOCOL_MAGIC);
	// Note: testnets can still use byron mainnet protocol magic so we can't deny the opposite direction

	// certain combinations of tx body elements are forbidden
	// mostly because of potential cross-witnessing
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

		// no Plutus elements for pool registrations
		DENY_IF(includeScriptDataHash);
		DENY_IF(numCollateralInputs > 0);
		DENY_IF(numRequiredSigners > 0);
		DENY_IF(includeCollateralOutput);
		DENY_IF(includeTotalCollateral);
		DENY_IF(numReferenceInputs > 0);
		break;

	case SIGN_TX_SIGNINGMODE_ORDINARY_TX:
	case SIGN_TX_SIGNINGMODE_MULTISIG_TX:
		// collateral inputs are allowed only in PLUTUS_TX
		DENY_IF(numCollateralInputs > 0);
		DENY_IF(includeCollateralOutput);
		DENY_IF(includeTotalCollateral);
		DENY_IF(numReferenceInputs > 0);
		break;

	case SIGN_TX_SIGNINGMODE_PLUTUS_TX:
		// Plutus script cannot be executed without collateral inputs
		WARN_IF(numCollateralInputs == 0);

		// Plutus script cannot be executed without script data hash
		WARN_UNLESS(includeScriptDataHash);

		// warn the user about Plutus script execution itself
		WARN();
		break;

	default:
		ASSERT(false);
	}

	// there are separate screens for various warnings
	// the return value of the policy only says that at least one should be applied
	// and the need for individual warnings is reassessed in the UI machine
	WARN_UNLESS(isTxNetworkIdVerifiable(includeNetworkId, numOutputs, numWithdrawals, txSigningMode));
	WARN_UNLESS(isNetworkUsual(networkId, protocolMagic));

	WARN_IF(needsRunningScriptWarning(numCollateralInputs));

	// these warnings are relevant for Plutus only, but the functions determining
	// if a warning is needed are called from UI machines in signTx that are not
	// specific for Plutus, so we rather want to keep them here
	// instead of moving them to the switch above to be consistent
	WARN_IF(needsMissingCollateralWarning(txSigningMode, numCollateralInputs));
	WARN_IF(needsUnknownCollateralWarning(txSigningMode, numCollateralInputs));
	WARN_IF(needsMissingScriptDataHashWarning(txSigningMode, includeScriptDataHash));

	// Could be switched to POLICY_ALLOW_WITHOUT_PROMPT to skip initial "new transaction" question
	// but it is safe only for a very narrow set of transactions (e.g. no Plutus)
	PROMPT();
}

// For each transaction UTxO input
security_policy_t policyForSignTxInput(sign_tx_signingmode_t txSigningMode)
{
	switch (txSigningMode) {
	case SIGN_TX_SIGNINGMODE_PLUTUS_TX:
		// user should check inputs because they are not interchangeable for Plutus scripts
		SHOW_IF(app_mode_expert());
		ALLOW();
		break;

	case SIGN_TX_SIGNINGMODE_ORDINARY_TX:
	case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OWNER:
	case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OPERATOR:
	case SIGN_TX_SIGNINGMODE_MULTISIG_TX:
		// inputs are not interesting for the user (transferred funds are shown in the outputs)
		ALLOW();
		break;

	default:
		ASSERT(false);
	}

	DENY(); // should not be reached
}

static bool is_addressBytes_suitable_for_tx_output(
        const uint8_t* addressBuffer, size_t addressSize,
        const uint8_t networkId, const uint32_t protocolMagic
)
{
	ASSERT(addressSize < BUFFER_SIZE_PARANOIA);
	ASSERT(addressSize >= 1);

#define CHECK(cond) if (!(cond)) return false

	const address_type_t addressType = getAddressType(addressBuffer[0]);
	{
		// check address type and network identification
		switch (addressType) {

		case REWARD_KEY:
		case REWARD_SCRIPT:
			// outputs may not contain reward addresses
			return false;

		case BYRON:
			CHECK(extractProtocolMagic(addressBuffer, addressSize) == protocolMagic);
			break;

		default: {
			// shelley types allowed in output
			const uint8_t addressNetworkId = getNetworkId(addressBuffer[0]);
			CHECK(addressNetworkId == networkId);
			break;
		}
		}
	}
	{
		// check address length
		switch (addressType) {

		case BASE_PAYMENT_KEY_STAKE_KEY:
			CHECK(addressSize == 1 + ADDRESS_KEY_HASH_LENGTH + ADDRESS_KEY_HASH_LENGTH);
			break;
		case BASE_PAYMENT_KEY_STAKE_SCRIPT:
			CHECK(addressSize == 1 + ADDRESS_KEY_HASH_LENGTH + SCRIPT_HASH_LENGTH);
			break;
		case BASE_PAYMENT_SCRIPT_STAKE_KEY:
			CHECK(addressSize == 1 + SCRIPT_HASH_LENGTH + ADDRESS_KEY_HASH_LENGTH);
			break;
		case BASE_PAYMENT_SCRIPT_STAKE_SCRIPT:
			CHECK(addressSize == 1 + SCRIPT_HASH_LENGTH + SCRIPT_HASH_LENGTH);
			break;

		case ENTERPRISE_KEY:
			CHECK(addressSize == 1 + ADDRESS_KEY_HASH_LENGTH);
			break;
		case ENTERPRISE_SCRIPT:
			CHECK(addressSize == 1 + SCRIPT_HASH_LENGTH);
			break;

		default: // not meaningful or complicated to verify address length in the other cases
			break;
		}
	}
	return true;
#undef CHECK
}

static bool contains_forbidden_plutus_elements(
        const tx_output_description_t* output,
        sign_tx_signingmode_t txSigningMode
)
{
	if (output->includeDatum || output->includeRefScript) {
		// no Plutus elements for pool registration, only allow in other modes
		switch (txSigningMode) {

		case SIGN_TX_SIGNINGMODE_ORDINARY_TX:
		case SIGN_TX_SIGNINGMODE_MULTISIG_TX:
		case SIGN_TX_SIGNINGMODE_PLUTUS_TX:
			break;

		default:
			return true;
		}
	}

	return false;
}

bool needsMissingDatumWarning(const tx_output_destination_t* destination, bool includeDatum)
{
	const bool mightRequireDatum = determineSpendingChoice(getDestinationAddressType(destination)) == SPENDING_SCRIPT_HASH;
	return mightRequireDatum && !includeDatum;
}

// For each transaction output with third-party address
security_policy_t policyForSignTxOutputAddressBytes(
        const tx_output_description_t* output,
        sign_tx_signingmode_t txSigningMode,
        const uint8_t networkId, const uint32_t protocolMagic
)
{
	ASSERT(output->destination.type == DESTINATION_THIRD_PARTY);
	const uint8_t* addressBuffer = output->destination.address.buffer;
	const size_t addressSize = output->destination.address.size;

	DENY_UNLESS(is_addressBytes_suitable_for_tx_output(addressBuffer, addressSize, networkId, protocolMagic));

	DENY_IF(contains_forbidden_plutus_elements(output, txSigningMode));

	switch (txSigningMode) {

	case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OWNER:
		// all the funds are provided by the operator
		// and thus outputs are irrelevant to the owner (even those having tokens or datum hash)
		ALLOW();
		break;

	case SIGN_TX_SIGNINGMODE_ORDINARY_TX:
	case SIGN_TX_SIGNINGMODE_MULTISIG_TX:
	case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OPERATOR:
	case SIGN_TX_SIGNINGMODE_PLUTUS_TX:
		// utxo on a Plutus script address without datum hash is unspendable
		// but we can't DENY because it is valid for native scripts
		WARN_IF(needsMissingDatumWarning(&output->destination, output->includeDatum));
		// we always show third-party output addresses
		SHOW();
		break;

	default:
		ASSERT(false);
	}

	DENY(); // should not be reached
}

static bool is_addressParams_suitable_for_tx_output(
        const addressParams_t* params,
        const uint8_t networkId, const uint32_t protocolMagic
)
{
#define CHECK(cond) if (!(cond)) return false
	CHECK(isValidAddressParams(params));

	// only allow valid address types
	// and check network identification as appropriate
	switch (params->type) {

	case REWARD_KEY:
	case REWARD_SCRIPT:
		// outputs must not contain reward addresses (true not only for HW wallets)
		return false;

	case BYRON:
		CHECK(params->protocolMagic == protocolMagic);
		break;

	default: // all Shelley types allowed in output
		CHECK(params->networkId == networkId);
		break;
	}

	{
		// outputs to a different account within this HW wallet,
		// or to a different wallet, should be given as raw address bytes

		// this captures the essence of a change output: money stays
		// on an address where payment is fully controlled by this device
		CHECK(determineSpendingChoice(params->type) == SPENDING_PATH);
		// Note: if we allowed script hash in spending part, we must add a warning
		// for missing datum (see policyForSignTxOutputAddressBytes)

		ASSERT(determineSpendingChoice(params->type) == SPENDING_PATH);
		CHECK(!violatesSingleAccountOrStoreIt(&params->spendingKeyPath));
	}

	return true;
#undef CHECK
}

// For each output given by payment derivation path
security_policy_t policyForSignTxOutputAddressParams(
        const tx_output_description_t* output,
        sign_tx_signingmode_t txSigningMode,
        const uint8_t networkId, const uint32_t protocolMagic
)
{
	ASSERT(output->destination.type == DESTINATION_DEVICE_OWNED);
	const addressParams_t* params = output->destination.params;

	DENY_UNLESS(is_addressParams_suitable_for_tx_output(params, networkId, protocolMagic));

	DENY_IF(contains_forbidden_plutus_elements(output, txSigningMode));

	switch (txSigningMode) {

	case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OPERATOR:
	case SIGN_TX_SIGNINGMODE_ORDINARY_TX: {
		// unusual paths or spending and staking path mismatch
		SHOW_UNLESS(is_standard_base_address(params));

		// outputs (eUTXOs) with datum or ref script are not interchangeable
		if (output->includeDatum || output->includeRefScript) {
			// can't happen for SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OPERATOR
			SHOW_IF(app_mode_expert());
		}

		// it is safe to hide the remaining change outputs
		ALLOW();
		break;
	}

	case SIGN_TX_SIGNINGMODE_MULTISIG_TX: {
		// for simplicity, all outputs should be given as external addresses;
		// generally, more than one party is needed to sign
		// spending from a multisig address, so we do not expect
		// there will be 1852 outputs (that would be considered change)
		DENY();
		break;
	}

	case SIGN_TX_SIGNINGMODE_PLUTUS_TX: {
		// the output could affect script validation so it must not be entirely hidden
		// Note: if we relax this, some of the above restrictions may apply
		SHOW_IF(app_mode_expert());
		ALLOW();
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

security_policy_t policyForSignTxOutputDatumHash(
        security_policy_t outputPolicy
)
{
	switch (outputPolicy) {
	case POLICY_ALLOW_WITHOUT_PROMPT:
		// output was not shown, showing datum won't make sense
		ALLOW();
		break;

	case POLICY_SHOW_BEFORE_RESPONSE:
	case POLICY_PROMPT_WARN_UNUSUAL:
		// non-expert users are not supposed to be able to verify datum or its hash even if they saw it
		SHOW_IF(app_mode_expert());
		ALLOW();
		break;

	default:
		ASSERT(false);
	}

	DENY(); // should not be reached
}

security_policy_t policyForSignTxOutputRefScript(
        security_policy_t outputPolicy
)
{
	switch (outputPolicy) {
	case POLICY_ALLOW_WITHOUT_PROMPT:
		// output was not shown, showing ref script won't make sense
		ALLOW();
		break;

	case POLICY_SHOW_BEFORE_RESPONSE:
	case POLICY_PROMPT_WARN_UNUSUAL:
		// non-expert users are not supposed to be able to verify a script even if they saw it
		SHOW_IF(app_mode_expert());
		ALLOW();
		break;

	default:
		ASSERT(false);
	}

	DENY(); // should not be reached
}

// For final output confirmation
security_policy_t policyForSignTxOutputConfirm(
        security_policy_t outputPolicy,
        uint64_t numAssetGroups,
        bool containsDatum,
        bool containsRefScript
)
{
	switch (outputPolicy) {
	case POLICY_ALLOW_WITHOUT_PROMPT:
		// output was not shown, no confirmation is needed
		ALLOW();
		break;

	case POLICY_SHOW_BEFORE_RESPONSE:
		// output was shown and it contained (possibly many) included items (e.g. tokens)
		// show a confirmation prompt, so that the user may abort the transaction sooner
		PROMPT_IF(numAssetGroups > 0);
		PROMPT_IF(containsDatum && app_mode_expert());
		PROMPT_IF(containsRefScript && app_mode_expert());
		// otherwise no separate confirmation is needed
		ALLOW();
		break;

	case POLICY_PROMPT_WARN_UNUSUAL:
		PROMPT();
		break;

	default:
		ASSERT(false);
	}

	DENY(); // should not be reached
}

static bool is_address_suitable_for_collateral_output(
        const tx_output_description_t* output
)
{
	switch(getDestinationAddressType(&output->destination)) {

	case BASE_PAYMENT_KEY_STAKE_KEY:
	case BASE_PAYMENT_KEY_STAKE_SCRIPT:
	case POINTER_KEY:
	case ENTERPRISE_KEY:
		// we only allow addresses with payment controlled by key
		return true;

	default:
		return false;
	}
}

security_policy_t policyForSignTxCollateralOutputAddressBytes(
        const tx_output_description_t* output,
        sign_tx_signingmode_t txSigningMode,
        const uint8_t networkId, const uint32_t protocolMagic
)
{
	// WARNING: policies for collateral inputs, collateral return output and total collateral are interdependent

	ASSERT(output->destination.type == DESTINATION_THIRD_PARTY);
	const uint8_t* addressBuffer = output->destination.address.buffer;
	const size_t addressSize = output->destination.address.size;

	DENY_UNLESS(is_addressBytes_suitable_for_tx_output(addressBuffer, addressSize, networkId, protocolMagic));
	DENY_UNLESS(is_address_suitable_for_collateral_output(output));

	DENY_IF(output->includeDatum);
	DENY_IF(output->includeRefScript);

	DENY_IF(txSigningMode != SIGN_TX_SIGNINGMODE_PLUTUS_TX);

	SHOW();
}

security_policy_t policyForSignTxCollateralOutputAddressParams(
        const tx_output_description_t* output,
        sign_tx_signingmode_t txSigningMode,
        const uint8_t networkId, const uint32_t protocolMagic,
        bool isTotalCollateralIncluded
)
{
	// WARNING: policies for collateral inputs, collateral return output and total collateral are interdependent

	ASSERT(output->destination.type == DESTINATION_DEVICE_OWNED);
	const addressParams_t* params = output->destination.params;

	DENY_UNLESS(is_addressParams_suitable_for_tx_output(params, networkId, protocolMagic));
	DENY_UNLESS(is_address_suitable_for_collateral_output(output));

	DENY_IF(output->includeDatum);
	DENY_IF(output->includeRefScript);

	switch (txSigningMode) {

	case SIGN_TX_SIGNINGMODE_PLUTUS_TX:
		if (isTotalCollateralIncluded) {
			// change outputs can be hidden
			SHOW_UNLESS(is_standard_base_address(params));
			ALLOW();
		} else {
			// collateral output ADA must be shown, so the whole output must be shown
			SHOW();
		}
		break;

	default:
		// should be used only in Plutus transactions
		DENY();
		break;
	}

	DENY(); // should not be reached
}

security_policy_t policyForSignTxCollateralOutputAdaAmount(
        security_policy_t outputPolicy,
        bool isTotalCollateralPresent
)
{
	if (outputPolicy == POLICY_ALLOW_WITHOUT_PROMPT) {
		// output not shown, so none of its elements should be shown
		ALLOW();
	}

	// ADA amount is calculable from total collateral
	// but only expert users are to be bothered by a possible collateral loss
	SHOW_IF(!isTotalCollateralPresent && app_mode_expert());
	ALLOW();
}

security_policy_t policyForSignTxCollateralOutputTokens(
        security_policy_t outputPolicy,
        const tx_output_description_t* output
)
{
	if (outputPolicy == POLICY_ALLOW_WITHOUT_PROMPT) {
		// output not shown, so none of its elements should be shown
		ALLOW();
	}

	// for non-change outputs, control over the collateral tokens is potentially transferred to
	// another party, so we should show them in the expert mode
	// (non-expert users are supposed to not be interested in any collateral loss)
	const bool lossOfControl = (output->destination.type != DESTINATION_DEVICE_OWNED);
	SHOW_IF(lossOfControl && app_mode_expert());
	ALLOW();
}

// For final collateral return output confirmation
security_policy_t policyForSignTxCollateralOutputConfirm(
        security_policy_t outputPolicy,
        uint64_t numAssetGroups
)
{
	// WARNING: policies for collateral inputs, collateral return output and total collateral are interdependent

	switch (outputPolicy) {
	case POLICY_ALLOW_WITHOUT_PROMPT:
		// output was not shown, no confirmation is needed
		ALLOW();
		break;

	case POLICY_SHOW_BEFORE_RESPONSE:
		// output was shown and it contained (possibly many) tokens
		// show a confirmation prompt, so that the user may abort the transaction sooner
		PROMPT_IF(numAssetGroups > 0);
		// however, if there were no tokens, no separate confirmation is needed
		ALLOW();
		break;

	case POLICY_PROMPT_WARN_UNUSUAL:
		PROMPT();
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
	SHOW_IF(app_mode_expert());
	ALLOW();
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
		// pool registration is allowed only in POOL_REGISTRATION signging modes
		DENY_IF(certificateType == CERTIFICATE_TYPE_STAKE_POOL_REGISTRATION);
		ALLOW();
		break;

	case SIGN_TX_SIGNINGMODE_MULTISIG_TX:
		// pool registration is allowed only in POOL_REGISTRATION signging modes
		DENY_IF(certificateType == CERTIFICATE_TYPE_STAKE_POOL_REGISTRATION);
		// pool retirement is impossible with multisig keys
		DENY_IF(certificateType == CERTIFICATE_TYPE_STAKE_POOL_RETIREMENT);
		ALLOW();
		break;

	case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OPERATOR:
	case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OWNER:
		// only pool registration is allowed
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
			PROMPT();
			break;

		case SIGN_TX_SIGNINGMODE_MULTISIG_TX:
			DENY();
			break;

		default:
			// in POOL_REGISTRATION signing modes, this certificate should have already been
			// reported as invalid (only pool registration certificate is allowed)
			ASSERT(false);
			break;
		}
		break;

	case STAKE_CREDENTIAL_KEY_HASH:
		switch (txSigningMode) {
		case SIGN_TX_SIGNINGMODE_PLUTUS_TX:
			PROMPT();
			break;

		case SIGN_TX_SIGNINGMODE_ORDINARY_TX:
		case SIGN_TX_SIGNINGMODE_MULTISIG_TX:
			DENY();
			break;

		default:
			// in POOL_REGISTRATION signing modes, this certificate should have already been
			// reported as invalid (only pool registration certificate is allowed)
			ASSERT(false);
			break;
		}
		break;

	case STAKE_CREDENTIAL_SCRIPT_HASH:
		switch (txSigningMode) {
		case SIGN_TX_SIGNINGMODE_MULTISIG_TX:
		case SIGN_TX_SIGNINGMODE_PLUTUS_TX:
			PROMPT();
			break;

		case SIGN_TX_SIGNINGMODE_ORDINARY_TX:
			DENY();
			break;

		default:
			// in POOL_REGISTRATION signing modes, this certificate should have already been
			// reported as invalid (only pool registration certificate is allowed)
			ASSERT(false);
			break;
		}
		break;

	default:
		ASSERT(false);
		break;
	}

	DENY(); // should not be reached
}

security_policy_t policyForSignTxCertificateStakePoolRetirement(
        sign_tx_signingmode_t txSigningMode,
        const bip44_path_t* poolIdPath,
        uint64_t epoch MARK_UNUSED
)
{
	switch (txSigningMode) {

	case SIGN_TX_SIGNINGMODE_ORDINARY_TX:
		// pool retirement may only be present in ORDINARY_TX signing mode
		// the path hash should be a valid pool cold key path
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
		// owner should see a hash
		DENY_UNLESS(poolId->keyReferenceType == KEY_REFERENCE_HASH);
		SHOW();
		break;

	case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OPERATOR:
		// operator should see a path
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
		// not interesting for an owner
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
		// when path is present, it should be a valid staking path
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
		// operator should receive owners given by hash
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
		// not interesting for an owner
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
	// notify the user if there are no owners and/or relays
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
			SHOW_IF(app_mode_expert());
			ALLOW();
			break;

		case SIGN_TX_SIGNINGMODE_MULTISIG_TX:
			// script hash is expected for multisig txs
			DENY();
			break;

		default:
			// in POOL_REGISTRATION signing modes, this certificate should have already been
			// reported as invalid (only pool registration certificate is allowed)
			ASSERT(false);
			break;
		}
		break;

	case STAKE_CREDENTIAL_KEY_HASH:
		switch (txSigningMode) {
		case SIGN_TX_SIGNINGMODE_PLUTUS_TX:
			SHOW_IF(app_mode_expert());
			ALLOW();
			break;

		case SIGN_TX_SIGNINGMODE_ORDINARY_TX:
			// key path is expected for ordinary txs
			// no known usecase for using 3rd party withdrawals in an ordinary tx
			// the hash might come from a key used in a witness
			// we are protecting users from accidentally signing such withdrawals
			DENY();
			break;

		case SIGN_TX_SIGNINGMODE_MULTISIG_TX:
			// script hash is expected for multisig txs
			DENY();
			break;

		default:
			// in POOL_REGISTRATION signing modes, this certificate should have already been
			// reported as invalid (only pool registration certificate is allowed)
			ASSERT(false);
			break;
		}

	case STAKE_CREDENTIAL_SCRIPT_HASH:
		switch (txSigningMode) {
		case SIGN_TX_SIGNINGMODE_MULTISIG_TX:
		case SIGN_TX_SIGNINGMODE_PLUTUS_TX:
			SHOW_IF(app_mode_expert());
			ALLOW();
			break;

		case SIGN_TX_SIGNINGMODE_ORDINARY_TX:
			// key path is expected for ordinary txs
			DENY();
			break;

		default:
			// in POOL_REGISTRATION signing modes, this certificate should have already been
			// reported as invalid (only pool registration certificate is allowed)
			ASSERT(false);
			break;
		}
		break;

	default:
		// in POOL_REGISTRATION signing modes, non-zero number of withdrawals
		// should have already been reported as invalid
		ASSERT(false);
		break;
	}

	DENY(); // should not be reached
}

// TODO move witness policies in the proper place, at the end of tx
static inline security_policy_t _ordinaryWitnessPolicy(const bip44_path_t* path, bool mintPresent)
{
	switch (bip44_classifyPath(path)) {
	case PATH_ORDINARY_SPENDING_KEY:
	case PATH_ORDINARY_STAKING_KEY:
		DENY_IF(violatesSingleAccountOrStoreIt(path));
		WARN_UNLESS(bip44_isPathReasonable(path));
		SHOW_IF(app_mode_expert());
		ALLOW();
		break;

	case PATH_POOL_COLD_KEY:
		// ordinary key paths and pool cold key paths can be hidden if they are not unusual
		// (the user saw all outputs, withdrawals and pool certificates and they all belong to him)
		WARN_UNLESS(bip44_isPathReasonable(path));
		SHOW();
		break;

	case PATH_MINT_KEY:
		DENY_UNLESS(mintPresent);
		// maybe not necessary, but let the user know which mint key is he using (eg. in case
		// the minting policy contains multiple of his keys but with different rules)
		SHOW();
		break;

	default:
		// multisig keys forbidden
		DENY();
		break;
	}
}

static inline security_policy_t _multisigWitnessPolicy(const bip44_path_t* path, bool mintPresent)
{
	switch (bip44_classifyPath(path)) {
	case PATH_MULTISIG_SPENDING_KEY:
	case PATH_MULTISIG_STAKING_KEY:
		// multisig key paths are allowed, but hiding them would make impossible for the user to
		// distinguish what funds are being spent (multisig UTXOs sharing a signer are not
		// necessarily interchangeable, because they may be governed by a different script)
		WARN_UNLESS(bip44_isPathReasonable(path));
		SHOW();
		break;

	case PATH_MINT_KEY:
		DENY_UNLESS(mintPresent);
		// maybe not necessary, but let the user know which mint key is he using (eg. in case
		// the minting policy contains multiple of his keys but with different rules)
		SHOW();
		break;

	default:
		// ordinary and pool cold keys forbidden
		DENY();
		break;
	}
}

static inline security_policy_t _plutusWitnessPolicy(const bip44_path_t* path, bool mintPresent)
{
	switch (bip44_classifyPath(path)) {
	// in PLUTUS_TX, we allow signing with any path, but it must be shown
	case PATH_ORDINARY_SPENDING_KEY:
	case PATH_ORDINARY_STAKING_KEY:
	case PATH_MULTISIG_SPENDING_KEY:
	case PATH_MULTISIG_STAKING_KEY:
		WARN_UNLESS(bip44_isPathReasonable(path));
		SHOW();
		break;

	case PATH_MINT_KEY:
		// mint witness without mint in the tx: somewhat suspicious,
		// no known usecase, but a mint path could be e.g. in required signers
		SHOW_UNLESS(mintPresent);
		// maybe not necessary, but let the user know which mint key is he using (e.g. in case
		// the minting policy contains multiple of his keys but with different rules)
		SHOW();
		break;

	case PATH_POOL_COLD_KEY:
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
		// only ordinary spending key paths (because of inputs) and pool cold key path are allowed
		WARN_UNLESS(bip44_isPathReasonable(path));
		// TODO is there a reason to show the witnesses?
		SHOW();
		break;

	default:
		DENY();
		break;
	}
}

// For each transaction witness
// Note: witnesses reveal public key of an address and Ledger *does not* check
// whether they correspond to previously declared inputs and certificates
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

// For transaction auxiliary data
security_policy_t policyForSignTxAuxData(aux_data_type_t auxDataType)
{
	switch (auxDataType) {

	case AUX_DATA_TYPE_ARBITRARY_HASH:
		SHOW_IF(app_mode_expert());
		ALLOW();

	case AUX_DATA_TYPE_CIP36_REGISTRATION:
		// this is the policy for the initial prompt
		// details of the registration are governed by separate policies
		// (see policyForGovernanceVotingRegistration...)
		SHOW();
		break;

	default:
		ASSERT(false);
	}

	DENY(); // should not be reached
}

// For transaction validity interval start
security_policy_t policyForSignTxValidityIntervalStart()
{
	SHOW_IF(app_mode_expert());
	ALLOW();
}

// For transaction mint field
security_policy_t policyForSignTxMintInit(const sign_tx_signingmode_t txSigningMode)
{
	switch (txSigningMode) {
	case SIGN_TX_SIGNINGMODE_ORDINARY_TX:
	case SIGN_TX_SIGNINGMODE_MULTISIG_TX:
	case SIGN_TX_SIGNINGMODE_PLUTUS_TX:
		SHOW();
		break;

	default:
		// in POOL_REGISTRATION signing modes, non-empty mint field
		// should have already been reported as invalid
		ASSERT(false);
	}

	DENY(); // should not be reached
}

// For final mint confirmation
security_policy_t policyForSignTxMintConfirm(security_policy_t mintInitPolicy)
{
	switch (mintInitPolicy) {
	case POLICY_ALLOW_WITHOUT_PROMPT:
		ALLOW();
		break;

	case POLICY_SHOW_BEFORE_RESPONSE:
		// all minted coins were shown, show a final cofirmation prompt as well
		PROMPT();
		break;

	default:
		ASSERT(false);
	}

	DENY(); // should not be reached
}

// For transaction script data hash
security_policy_t policyForSignTxScriptDataHash(const sign_tx_signingmode_t txSigningMode)
{
	switch (txSigningMode) {
	case SIGN_TX_SIGNINGMODE_ORDINARY_TX:
	case SIGN_TX_SIGNINGMODE_MULTISIG_TX:
	case SIGN_TX_SIGNINGMODE_PLUTUS_TX:
		SHOW_IF(app_mode_expert());
		ALLOW();
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

// For each transaction collateral input
security_policy_t policyForSignTxCollateralInput(
        const sign_tx_signingmode_t txSigningMode,
        bool isTotalCollateralPresent
)
{
	// WARNING: policies for collateral inputs, collateral return output and total collateral are interdependent

	// we do not impose restrictions on individual collateral inputs
	// because a HW wallet cannot verify anything about the input

	switch (txSigningMode) {
	case SIGN_TX_SIGNINGMODE_PLUTUS_TX:
		// safe to hide if total collateral is given
		// (if tokens are present, they go to collateral output, and collateral ADA is
		// shown explicitly, so we don't need to see individual collateral inputs)
		SHOW_IF(!isTotalCollateralPresent && app_mode_expert());
		ALLOW();
		break;

	case SIGN_TX_SIGNINGMODE_ORDINARY_TX:
	case SIGN_TX_SIGNINGMODE_MULTISIG_TX:
	case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OWNER:
	case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OPERATOR:
		// collateral inputs allowed only if Plutus script is to be executed
		DENY();
		break;

	default:
		ASSERT(false);
	}

	DENY();
}

static bool required_signers_allowed(const sign_tx_signingmode_t txSigningMode)
{
	switch (txSigningMode) {
	case SIGN_TX_SIGNINGMODE_PLUTUS_TX:
	case SIGN_TX_SIGNINGMODE_ORDINARY_TX:
	case SIGN_TX_SIGNINGMODE_MULTISIG_TX:
		return true;

	default:
		return false;
	}
}

static bool is_required_signer_allowed(bip44_path_t* path)
{
	switch (bip44_classifyPath(path)) {
	case PATH_ORDINARY_ACCOUNT:
	case PATH_ORDINARY_SPENDING_KEY:
	case PATH_ORDINARY_STAKING_KEY:
		return bip44_hasShelleyPrefix(path);

	case PATH_MULTISIG_ACCOUNT:
	case PATH_MULTISIG_SPENDING_KEY:
	case PATH_MULTISIG_STAKING_KEY:
		return true;

	case PATH_MINT_KEY:
		return true;

	default:
		return false;
	}
}

security_policy_t policyForSignTxRequiredSigner(
        const sign_tx_signingmode_t txSigningMode,
        sign_tx_required_signer_t* requiredSigner
)
{
	DENY_UNLESS(required_signers_allowed(txSigningMode));

	switch(requiredSigner->type) {

	case REQUIRED_SIGNER_WITH_HASH:
		SHOW_IF(app_mode_expert());
		ALLOW();
		break;

	case REQUIRED_SIGNER_WITH_PATH:
		DENY_UNLESS(is_required_signer_allowed(&requiredSigner->keyPath));
		SHOW_IF(app_mode_expert());
		ALLOW();
		break;

	default:
		ASSERT(false);
	}

	DENY(); // should not be reached
}

security_policy_t policyForSignTxTotalCollateral()
{
	// WARNING: policies for collateral inputs, collateral return output and total collateral are interdependent

	// showing protects against unlimited collateral loss
	// if not present, we display a warning about unknown collateral
	SHOW();
}

security_policy_t policyForSignTxReferenceInput(const sign_tx_signingmode_t txSigningMode)
{
	switch (txSigningMode) {
	case SIGN_TX_SIGNINGMODE_PLUTUS_TX:
		// should be shown because the user loses all collateral if Plutus execution fails
		SHOW_IF(app_mode_expert());
		ALLOW();
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

security_policy_t policyForGovernanceVotingRegistrationVotingKey()
{
	SHOW();
}

security_policy_t policyForGovernanceVotingRegistrationVotingKeyPath(
        bip44_path_t* path,
        governance_voting_registration_format_t format
)
{
	// encourages people to use the new format,
	// so that we can drop support for CIP15 sooner
	DENY_UNLESS(format == CIP36);

	DENY_UNLESS(bip44_classifyPath(path) == PATH_GOVERNANCE_VOTING_KEY);
	WARN_UNLESS(bip44_isPathReasonable(path));
	SHOW();
}

security_policy_t policyForGovernanceVotingRegistrationStakingKey(
        const bip44_path_t* stakingKeyPath
)
{
	DENY_UNLESS(bip44_isOrdinaryStakingKeyPath(stakingKeyPath));
	WARN_UNLESS(bip44_isPathReasonable(stakingKeyPath));

	SHOW();
}

// based on https://input-output-rnd.slack.com/archives/C036XSMFXE3/p1668185230182239
// TODO make sure this is what we want
security_policy_t policyForGovernanceVotingRegistrationVotingRewardsDestination(
        const tx_output_destination_storage_t* destination,
        const uint8_t networkId
)
{
	switch (destination->type) {

	case DESTINATION_DEVICE_OWNED: {
		DENY_UNLESS(isValidAddressParams(&destination->params));
		DENY_UNLESS(isShelleyAddressType(destination->params.type));
		DENY_IF(destination->params.networkId != networkId);

		// in a typical case, the rewards go to an address controlled by this device
		// and the address is sent in a way allowing a verification of that fact
		WARN_UNLESS(
		        is_standard_base_address(&destination->params)
		);

		// we are sure the address belongs to the device
		SHOW();
		break;
	}

	case DESTINATION_THIRD_PARTY: {
		const uint8_t header = getAddressHeader(
		                               destination->address.buffer, destination->address.size
		                       );
		DENY_UNLESS(isShelleyAddressType(getAddressType(header)));
		DENY_IF(getNetworkId(header) != networkId);

		// we don't know who owns the address
		// to possibly avoid this warning, send the address as parameters (see above)
		WARN();
		break;
	}

	default:
		ASSERT(false);
		break;
	}

	DENY(); // should not be reached

}

security_policy_t policyForGovernanceVotingRegistrationNonce()
{
	SHOW();
}

security_policy_t policyForGovernanceVotingRegistrationVotingPurpose()
{
	// since it will only be used for Catalyst, we don't show this value to non-experts
	SHOW_IF(app_mode_expert());
	ALLOW();
}

security_policy_t policyForGovernanceVotingRegistrationConfirm()
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

security_policy_t policyForSignGovernanceVoteInit()
{
	PROMPT();
}

security_policy_t policyForSignGovernanceVoteConfirm()
{
	PROMPT();
}

security_policy_t policyForSignGovernanceVoteWitness(bip44_path_t* path)
{
	switch (bip44_classifyPath(path)) {
	case PATH_GOVERNANCE_VOTING_KEY:
		WARN_UNLESS(bip44_isPathReasonable(path));
		SHOW();
		break;


	default:
		DENY();
		break;
	}
}
