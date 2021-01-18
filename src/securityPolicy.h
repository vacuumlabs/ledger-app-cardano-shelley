#ifndef H_CARDANO_APP_SECURITY_POLICY
#define H_CARDANO_APP_SECURITY_POLICY

#include "addressUtilsShelley.h"
#include "bip44.h"
#include "cardanoOutputs.h"
#include "signTxPoolRegistration.h"
#include "signTx.h"

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
        sign_tx_usecase_t signTxUsecase,
        uint8_t networkId,
        uint32_t protocolMagic,
        uint16_t numOutputs,
        uint16_t numWithdrawals
);

security_policy_t policyForSignTxInput();

security_policy_t policyForSignTxOutputAddressBytes(
        sign_tx_usecase_t signTxUsecase,
        const uint8_t* rawAddressBuffer, size_t rawAddressSize,
        const uint8_t networkId, const uint32_t protocolMagic
);
security_policy_t policyForSignTxOutputAddressParams(
        sign_tx_usecase_t signTxUsecase,
        const addressParams_t* params,
        const uint8_t networkId, const uint32_t protocolMagic
);
security_policy_t policyForSignTxOutputConfirm(
        security_policy_t addressPolicy,
        uint64_t numAssetGroups
);

security_policy_t policyForSignTxFee(sign_tx_usecase_t signTxUsecase, uint64_t fee);

security_policy_t policyForSignTxTtl(uint32_t ttl);

security_policy_t policyForSignTxCertificate(
        sign_tx_usecase_t signTxUsecase,
        const certificate_type_t certificateType
);
security_policy_t policyForSignTxCertificateStaking(
        const certificate_type_t certificateType,
        const bip44_path_t* stakingKeyPath
);
#ifdef POOL_OPERATOR_APP
security_policy_t policyForSignTxCertificateStakePoolRetirement(
        sign_tx_usecase_t signTxUsecase,
        const bip44_path_t* poolIdPath,
        uint64_t epoch
);
#endif
security_policy_t policyForSignTxStakePoolRegistrationPoolId(
        sign_tx_usecase_t signTxUsecase,
        const pool_id_t* poolId
);
security_policy_t policyForSignTxStakePoolRegistrationVrfKey(
        sign_tx_usecase_t signTxUsecase
);
security_policy_t policyForSignTxStakePoolRegistrationRewardAccount(
        sign_tx_usecase_t signTxUsecase,
        const pool_reward_account_t* poolRewardAccount
);
security_policy_t policyForSignTxStakePoolRegistrationOwner(
        const sign_tx_usecase_t signTxUsecase,
        const pool_owner_t* owner
);
security_policy_t policyForSignTxStakePoolRegistrationRelay(
        const sign_tx_usecase_t signTxUsecase,
        const pool_relay_t* relay
);
security_policy_t policyForSignTxStakePoolRegistrationMetadata();
security_policy_t policyForSignTxStakePoolRegistrationNoMetadata();
security_policy_t policyForSignTxStakePoolRegistrationConfirm();

security_policy_t policyForSignTxWithdrawal();

security_policy_t policyForSignTxMetadata();

security_policy_t policyForSignTxValidityIntervalStart();

security_policy_t policyForSignTxWitness(
        sign_tx_usecase_t signTxUsecase,
        const bip44_path_t* pathSpec
);

security_policy_t policyForSignTxConfirm();

bool is_tx_network_verifiable(
        sign_tx_usecase_t signTxUsecase,
        uint16_t numOutputs,
        uint16_t numWithdrawals
);


static inline void ENSURE_NOT_DENIED(security_policy_t policy)
{
	if (policy == POLICY_DENY) {
		THROW(ERR_REJECTED_BY_POLICY);
	}
}

#endif // H_CARDANO_APP_SECURITY_POLICY
