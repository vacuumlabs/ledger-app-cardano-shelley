#include "addressUtilsShelley.h"
#include "securityPolicy.h"
#include "bip44.h"

// Warning: following helper macros assume "pathSpec" in the context

// Helper macros

static inline bool path_is_inconsistent_with_header(uint8_t header, const bip44_path_t* pathSpec) {
	const uint8_t addressType = getAddressType(header);

	// Byron derivation path is only valid for a Byron address
	if (addressType == BYRON && !bip44_isByron(pathSpec)) return false;
	if (addressType != BYRON && !bip44_isShelley(pathSpec)) return false;

	if (addressType == REWARD) {
		if (!bip44_isValidStakingKeyPath(pathSpec)) return false;
	} else {
		// for all non-reward addresses, we check chain type and length
		if (!bip44_hasValidChainTypeForAddress(pathSpec)) return false;
		if (!bip44_containsAddress(pathSpec)) return false;
	}

	return true;
}

static inline bool has_cardano_prefix_and_any_account(const bip44_path_t* pathSpec)
{
	return bip44_hasValidCardanoPrefix(pathSpec) &&
	       bip44_containsAccount(pathSpec);
}

static inline bool has_valid_change_and_any_address(const bip44_path_t* pathSpec)
{
	return bip44_hasValidChainTypeForAddress(pathSpec) &&
	       bip44_containsAddress(pathSpec);
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

#define DENY_IF(expr)   if (expr) return POLICY_DENY;
#define WARN_IF(expr)   if (expr) return POLICY_PROMPT_WARN_UNUSUAL;
#define PROMPT_IF(expr) if (expr) return POLICY_PROMPT_BEFORE_RESPONSE;
#define ALLOW_IF(expr)  if (expr) return POLICY_ALLOW_WITHOUT_PROMPT;
#define SHOW_IF(expr)   if (expr) return POLICY_SHOW_BEFORE_RESPONSE;

// Get extended public key and return it to the host
security_policy_t policyForGetExtendedPublicKey(const bip44_path_t* pathSpec)
{
	DENY_IF(!has_cardano_prefix_and_any_account(pathSpec));

	WARN_IF(!bip44_hasReasonableAccount(pathSpec));
	// Normally extPubKey is asked only for an account or a staking key
	WARN_IF(bip44_containsChainType(pathSpec) && !bip44_isValidStakingKeyPath(pathSpec));

	PROMPT_IF(true);
}

// Derive address and return it to the host
security_policy_t policyForReturnDeriveAddress(uint8_t header, const bip44_path_t* pathSpec)
{
	DENY_IF(!has_cardano_prefix_and_any_account(pathSpec));
	DENY_IF(path_is_inconsistent_with_header(header, pathSpec));
	DENY_IF(!has_valid_change_and_any_address(pathSpec));

	WARN_IF(!has_reasonable_account_and_address(pathSpec))
	WARN_IF(is_too_deep(pathSpec)); // TODO change to DENY?

	PROMPT_IF(true);
}

// Derive address and show it to the user
security_policy_t policyForShowDeriveAddress(uint8_t header, const bip44_path_t* pathSpec)
{
	DENY_IF(!has_cardano_prefix_and_any_account(pathSpec));
	DENY_IF(path_is_inconsistent_with_header(header, pathSpec));
	DENY_IF(!has_valid_change_and_any_address(pathSpec));

	WARN_IF(!has_reasonable_account_and_address(pathSpec))
	WARN_IF(is_too_deep(pathSpec));

	SHOW_IF(true);
}

// Attest UTxO and return it to the host
security_policy_t policyForAttestUtxo()
{
	// We always allow attesting UTxO without user interaction (there is no security implication for doing this)
	ALLOW_IF(true);
}


// Initiate transaction signing
security_policy_t policyForSignTxInit()
{
	// Could be switched to POLICY_ALLOW_WITHOUT_PROMPT to skip initial "new transaction" question
	PROMPT_IF(true);
}

// For each transaction UTxO input
security_policy_t policyForSignTxInput()
{
	// No need to check (attested) tx inputs
	ALLOW_IF(true);
}

// For each transaction (third-party) address output
security_policy_t policyForSignTxOutputAddress(
        const uint8_t* rawAddressBuffer MARK_UNUSED, size_t rawAddressSize MARK_UNUSED
)
{
	// We always show third-party output addresses
	SHOW_IF(true);
}

// For each transaction change (Ledger's) output
security_policy_t policyForSignTxOutputPath(const bip44_path_t* pathSpec)
{
	DENY_IF(!has_cardano_prefix_and_any_account(pathSpec));
	DENY_IF(!has_valid_change_and_any_address(pathSpec));

	// Note: we use SHOW_IF to display these unusual requests
	// as 3-rd party addresses
	SHOW_IF(!has_reasonable_account_and_address(pathSpec))
	SHOW_IF(is_too_deep(pathSpec));

	ALLOW_IF(true);
}

// For transaction fee
security_policy_t policyForSignTxFee(uint64_t fee MARK_UNUSED)
{
	SHOW_IF(true);
}

// For each transaction witness
// Note: witnesses reveal public key of an address
// and Ledger *does not* check whether they correspond to previously declared UTxOs
security_policy_t policyForSignTxWitness(const bip44_path_t* pathSpec)
{
	DENY_IF(!has_cardano_prefix_and_any_account(pathSpec));
	DENY_IF(!has_valid_change_and_any_address(pathSpec));

	// Perhaps we can relax these?
	WARN_IF(!has_reasonable_account_and_address(pathSpec))
	WARN_IF(is_too_deep(pathSpec));

	ALLOW_IF(true);
}
