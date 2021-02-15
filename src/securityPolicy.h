#ifndef H_CARDANO_APP_SECURITY_POLICY
#define H_CARDANO_APP_SECURITY_POLICY

#include "addressUtilsShelley.h"
#include "bip44.h"
#include "cardanoOutputs.h"
#include "signTxPoolRegistration.h"

typedef enum {
	POLICY_DENY = 1,
	POLICY_ALLOW_WITHOUT_PROMPT = 2,
	POLICY_PROMPT_BEFORE_RESPONSE = 3,
	POLICY_PROMPT_WARN_UNUSUAL = 4,
	POLICY_SHOW_BEFORE_RESPONSE = 5, // Show on display but do not ask for explicit confirmation
} security_policy_t;

security_policy_t policyForGetPublicKeysInit(size_t numPaths);
security_policy_t policyForGetExtendedPublicKey(const bip44_path_t* pathSpec);
security_policy_t policyForGetExtendedPublicKeyBulkExport(const bip44_path_t* pathSpec);


security_policy_t policyForShowDeriveAddress(const addressParams_t* addressParams);
security_policy_t policyForReturnDeriveAddress(const addressParams_t* addressParams);


security_policy_t policyForSignTxInit(
        uint8_t networkId,
        uint32_t protocolMagic,
        uint16_t numOutputs,
        uint16_t numWithdrawals,
        bool isSigningPoolRegistrationAsOwner
);

security_policy_t policyForSignTxInput();

security_policy_t policyForSignTxOutputAddressBytes(
        bool isSigningPoolRegistrationAsOwner,
        const uint8_t* rawAddressBuffer, size_t rawAddressSize,
        const uint8_t networkId, const uint32_t protocolMagic
);
security_policy_t policyForSignTxOutputAddressParams(
        bool isSigningPoolRegistrationAsOwner,
        const addressParams_t* params,
        const uint8_t networkId, const uint32_t protocolMagic
);
security_policy_t policyForSignTxOutputConfirm(
        security_policy_t addressPolicy,
        uint64_t numAssetGroups
);

security_policy_t policyForSignTxFee(bool isSigningPoolRegistrationAsOwner, uint64_t fee);

security_policy_t policyForSignTxTtl(uint32_t ttl);

security_policy_t policyForSignTxCertificate(
        const bool includeStakePoolRegistrationCertificate,
        const uint8_t certificateType
);
security_policy_t policyForSignTxCertificateStaking(
        const uint8_t certificateType,
        const bip44_path_t* stakingKeyPath
);
security_policy_t policyForSignTxCertificateStakePoolRegistration(
);
security_policy_t policyForSignTxStakePoolRegistrationOwner(pool_owner_t* owner);
security_policy_t policyForSignTxStakePoolRegistrationMetadata();
security_policy_t policyForSignTxStakePoolRegistrationNoMetadata();
security_policy_t policyForSignTxStakePoolRegistrationConfirm();

security_policy_t policyForSignTxWithdrawal();

security_policy_t policyForSignTxMetadata();

security_policy_t policyForSignTxValidityIntervalStart();

security_policy_t policyForSignTxWitness(
        bool isSigningPoolRegistrationAsOwner,
        const bip44_path_t* pathSpec
);

security_policy_t policyForSignTxConfirm();

bool is_tx_network_verifiable(
        uint16_t numOutputs,
        uint16_t numWithdrawals,
        bool isSigningPoolRegistrationAsOwner
);


static inline void ENSURE_NOT_DENIED(security_policy_t policy)
{
	if (policy == POLICY_DENY) {
		THROW(ERR_REJECTED_BY_POLICY);
	}
}

#endif
