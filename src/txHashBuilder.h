#ifndef H_CARDANO_APP_TX_HASH_BUILDER
#define H_CARDANO_APP_TX_HASH_BUILDER

#include "cardano.h"
#include "hash.h"

enum {
	TX_BODY_KEY_INPUTS = 0,
	TX_BODY_KEY_OUTPUTS = 1,
	TX_BODY_KEY_FEE = 2,
	TX_BODY_KEY_TTL = 3,
	TX_BODY_KEY_CERTIFICATES = 4,
	TX_BODY_KEY_WITHDRAWALS = 5,
	// TX_BODY_KEY_UPDATE = 6, // not used
	TX_BODY_KEY_AUX_DATA = 7,
	TX_BODY_KEY_VALIDITY_INTERVAL_START = 8,
	TX_BODY_KEY_MINT = 9,
};

/* The state machine of the tx hash builder is driven by user calls.
 * E.g., when the user calls txHashBuilder_addInput(), the input is only
 * added and the state is not advanced to outputs even if all inputs have been added
 * --- only after calling txHashBuilder_enterOutputs()
 * is the state advanced to TX_HASH_BUILDER_IN_OUTPUTS.
 *
 * Pool registration certificates have an inner state loop which is implemented
 * in a similar fashion with the exception that when all pool certificate data
 * have been entered, the state is changed to TX_HASH_BUILDER_IN_CERTIFICATES.
 */
typedef enum {
	TX_HASH_BUILDER_INIT = 100,
	TX_HASH_BUILDER_IN_INPUTS = 200,
	TX_HASH_BUILDER_IN_OUTPUTS = 300,
	TX_HASH_BUILDER_IN_OUTPUTS_TOP_LEVEL_DATA = 310,
	TX_HASH_BUILDER_IN_OUTPUTS_ASSET_GROUP = 311,
	TX_HASH_BUILDER_IN_OUTPUTS_TOKEN = 312,
	TX_HASH_BUILDER_IN_FEE = 400,
	TX_HASH_BUILDER_IN_TTL = 500,
	TX_HASH_BUILDER_IN_CERTIFICATES = 600,
	TX_HASH_BUILDER_IN_CERTIFICATES_POOL_INIT = 610,
	TX_HASH_BUILDER_IN_CERTIFICATES_POOL_KEY_HASH = 611,
	TX_HASH_BUILDER_IN_CERTIFICATES_POOL_VRF = 612,
	TX_HASH_BUILDER_IN_CERTIFICATES_POOL_FINANCIALS = 613,
	TX_HASH_BUILDER_IN_CERTIFICATES_POOL_REWARD_ACCOUNT = 614,
	TX_HASH_BUILDER_IN_CERTIFICATES_POOL_OWNERS = 615,
	TX_HASH_BUILDER_IN_CERTIFICATES_POOL_RELAYS = 616,
	TX_HASH_BUILDER_IN_CERTIFICATES_POOL_METADATA = 617,
	TX_HASH_BUILDER_IN_WITHDRAWALS = 700,
	TX_HASH_BUILDER_IN_AUX_DATA = 800,
	TX_HASH_BUILDER_IN_VALIDITY_INTERVAL_START = 900,
	TX_HASH_BUILDER_IN_MINT = 1000,
	TX_HASH_BUILDER_IN_MINT_TOP_LEVEL_DATA = 1010,
	TX_HASH_BUILDER_IN_MINT_ASSET_GROUP = 1011,
	TX_HASH_BUILDER_IN_MINT_TOKEN = 1012,
	TX_HASH_BUILDER_FINISHED = 1100,
} tx_hash_builder_state_t;

typedef struct {
	uint16_t remainingInputs;
	uint16_t remainingOutputs;
	uint16_t remainingWithdrawals;
	uint16_t remainingCertificates;
	bool includeTtl;
	bool includeAuxData;
	bool includeValidityIntervalStart;
	bool includeMint;

	union {
		struct {
			uint16_t remainingOwners;
			uint16_t remainingRelays;
		} poolCertificateData;

		struct {
			uint16_t remainingAssetGroups;
			uint16_t remainingTokens;
		} multiassetData;
	};

	tx_hash_builder_state_t state;
	blake2b_256_context_t txHash;
} tx_hash_builder_t;


void txHashBuilder_init(
        tx_hash_builder_t* builder,
        uint16_t numInputs,
        uint16_t numOutputs,
        bool includeTtl,
        uint16_t numCertificates,
        uint16_t numWithdrawals,
        bool includeAuxData,
        bool includeValidityIntervalStart,
        bool includeMint
);

void txHashBuilder_enterInputs(tx_hash_builder_t* builder);
void txHashBuilder_addInput(
        tx_hash_builder_t* builder,
        const uint8_t* utxoHashBuffer, size_t utxoHashSize,
        uint32_t utxoIndex
);

void txHashBuilder_enterOutputs(tx_hash_builder_t* builder);
void txHashBuilder_addOutput_topLevelData(
        tx_hash_builder_t* builder,
        const uint8_t* addressBuffer, size_t addressSize,
        uint64_t amount,
        uint16_t numAssetGroups
);
void txHashBuilder_addOutput_tokenGroup(
        tx_hash_builder_t* builder,
        const uint8_t* policyIdBuffer, size_t policyIdSize,
        uint16_t numTokens
);
void txHashBuilder_addOutput_token(
        tx_hash_builder_t* builder,
        const uint8_t* assetNameBuffer, size_t assetNameSize,
        uint64_t amount
);

void txHashBuilder_addFee(tx_hash_builder_t* builder, uint64_t fee);

void txHashBuilder_addTtl(tx_hash_builder_t* builder, uint64_t ttl);

void txHashBuilder_enterCertificates(tx_hash_builder_t* builder);
void txHashBuilder_addCertificate_stakingKey(
        tx_hash_builder_t* builder,
        const certificate_type_t certificateType,
        const uint8_t* stakingKeyHash, size_t stakingKeyHashSize
);
void txHashBuilder_addCertificate_delegation(
        tx_hash_builder_t* builder,
        const uint8_t* stakingKeyHash, size_t stakingKeyHashSize,
        const uint8_t* poolKeyHash, size_t poolKeyHashSize
);
void txHashBuilder_addCertificate_poolRetirement(
        tx_hash_builder_t* builder,
        uint8_t* poolKeyHash, size_t poolKeyHashSize,
        uint64_t epoch
);

void txHashBuilder_poolRegistrationCertificate_enter(
        tx_hash_builder_t* builder,
        uint16_t numOwners, uint16_t numRelays
);
void txHashBuilder_poolRegistrationCertificate_poolKeyHash(
        tx_hash_builder_t* builder,
        uint8_t* poolKeyHash, size_t poolKeyHashSize
);
void txHashBuilder_poolRegistrationCertificate_vrfKeyHash(
        tx_hash_builder_t* builder,
        uint8_t* vrfKeyHash, size_t vrfKeyHashSize
);
void txHashBuilder_poolRegistrationCertificate_financials(
        tx_hash_builder_t* builder,
        uint64_t pledge, uint64_t cost,
        uint64_t marginNumerator, uint64_t marginDenominator
);
void txHashBuilder_poolRegistrationCertificate_rewardAccount(
        tx_hash_builder_t* builder,
        uint8_t* rewardAccount, size_t rewardAccountSize
);
void txHashBuilder_addPoolRegistrationCertificate_enterOwners(tx_hash_builder_t* builder);
void txHashBuilder_addPoolRegistrationCertificate_addOwner(
        tx_hash_builder_t* builder,
        const uint8_t* stakingKeyHash, size_t stakingKeyHashSize
);
void txHashBuilder_addPoolRegistrationCertificate_enterRelays(tx_hash_builder_t* builder);
void txHashBuilder_addPoolRegistrationCertificate_addRelay(
        tx_hash_builder_t* builder,
        pool_relay_t* relay
);
void txHashBuilder_addPoolRegistrationCertificate_addPoolMetadata(
        tx_hash_builder_t* builder,
        const uint8_t* url, size_t urlSize,
        const uint8_t* metadataHash, size_t metadataHashSize
);
void txHashBuilder_addPoolRegistrationCertificate_addPoolMetadata_null(
        tx_hash_builder_t* builder
);

void txHashBuilder_enterWithdrawals(tx_hash_builder_t* builder);
void txHashBuilder_addWithdrawal(
        tx_hash_builder_t* builder,
        const uint8_t* rewardAddressBuffer, size_t rewardAddressSize,
        uint64_t amount
);

void txHashBuilder_addAuxData(
        tx_hash_builder_t* builder,
        const uint8_t* auxDataHashBuffer, size_t auxDataHashSize
);

void txHashBuilder_addValidityIntervalStart(
        tx_hash_builder_t* builder,
        uint64_t validityIntervalStart
);

void txHashBuilder_enterMint(tx_hash_builder_t* builder);
void txHashBuilder_addMint_topLevelData(
        tx_hash_builder_t* builder, uint16_t numAssetGroups
);
void txHashBuilder_addMint_tokenGroup(
        tx_hash_builder_t* builder,
        const uint8_t* policyIdBuffer, size_t policyIdSize,
        uint16_t numTokens
);
void txHashBuilder_addMint_token(
        tx_hash_builder_t* builder,
        const uint8_t* assetNameBuffer, size_t assetNameSize,
        int64_t amount
);

void txHashBuilder_finalize(
        tx_hash_builder_t* builder,
        uint8_t* outBuffer, size_t outSize
);


#ifdef DEVEL
void run_txHashBuilder_test();
#endif // DEVEL

#endif // H_CARDANO_APP_TX_HASH_BUILDER
