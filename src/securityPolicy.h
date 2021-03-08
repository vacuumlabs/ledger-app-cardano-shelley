#ifndef H_CARDANO_APP_SECURITY_POLICY
#define H_CARDANO_APP_SECURITY_POLICY

#include "addressUtilsShelley.h"
#include "bip44.h"
#include "cardano.h"
#include "securityPolicyType.h"
#include "signTxPoolRegistration.h"
#include "signTx.h"

bool is_tx_network_verifiable(
        sign_tx_usecase_t signTxUsecase,
        uint16_t numOutputs,
        uint16_t numWithdrawals
);

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
security_policy_t policyForSignTxCertificateStakePoolRetirement(
        sign_tx_usecase_t signTxUsecase,
        const bip44_path_t* poolIdPath,
        uint64_t epoch
);
security_policy_t policyForSignTxStakePoolRegistrationPoolId(
        sign_tx_usecase_t signTxUsecase,
        const pool_id_t* poolId
);
security_policy_t policyForSignTxStakePoolRegistrationVrfKey(
        sign_tx_usecase_t signTxUsecase
);
security_policy_t policyForSignTxStakePoolRegistrationRewardAccount(
        sign_tx_usecase_t signTxUsecase,
        const reward_account_t* poolRewardAccount
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
security_policy_t policyForSignTxStakePoolRegistrationConfirm(
        uint32_t numOwners, uint32_t numRelays
);

security_policy_t policyForSignTxWithdrawal();

security_policy_t policyForSignTxMetadata();

security_policy_t policyForSignTxValidityIntervalStart();

security_policy_t policyForSignTxWitness(
        sign_tx_usecase_t signTxUsecase,
        const bip44_path_t* pathSpec
);

security_policy_t policyForSignTxConfirm();

security_policy_t policyForSignOpCert(const bip44_path_t* poolColdKeyPathSpec);

#endif // H_CARDANO_APP_SECURITY_POLICY
