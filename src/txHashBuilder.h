#ifndef H_CARDANO_APP_TX_HASH_BUILDER
#define H_CARDANO_APP_TX_HASH_BUILDER

#include "hash.h"

enum {
	TX_BODY_KEY_INPUTS = 0,
	TX_BODY_KEY_OUTPUTS = 1,
	TX_BODY_KEY_FEE = 2,
	TX_BODY_KEY_TTL = 3,
	TX_BODY_KEY_CERTIFICATES = 4,
	TX_BODY_KEY_WITHDRAWALS = 5,
	// TX_BODY_KEY_UPDATE = 6, // not used
	TX_BODY_KEY_METADATA = 7
};

// there are other types we do not support
enum {
	CERTIFICATE_TYPE_STAKE_REGISTRATION = 0,
	CERTIFICATE_TYPE_STAKE_DEREGISTRATION = 1,
	CERTIFICATE_TYPE_STAKE_DELEGATION = 2,
	CERTIFICATE_TYPE_STAKE_POOL_REGISTRATION = 3
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
 *
 * WARNING: the state machine relies on inequality comparisons between states in certain places.
 */
typedef enum {
	TX_HASH_BUILDER_INIT = 100,
	TX_HASH_BUILDER_IN_INPUTS = 200,
	TX_HASH_BUILDER_IN_OUTPUTS = 300,
	TX_HASH_BUILDER_IN_FEE = 400,
	TX_HASH_BUILDER_IN_TTL = 500,
	TX_HASH_BUILDER_IN_CERTIFICATES = 600,
	TX_HASH_BUILDER_IN_CERTIFICATES_POOL = 610,
	TX_HASH_BUILDER_IN_CERTIFICATES_POOL_OWNERS = 611,
	TX_HASH_BUILDER_IN_CERTIFICATES_POOL_RELAYS = 612,
	TX_HASH_BUILDER_IN_CERTIFICATES_POOL_METADATA = 613,
	TX_HASH_BUILDER_IN_WITHDRAWALS = 700,
	TX_HASH_BUILDER_IN_METADATA = 800,
	TX_HASH_BUILDER_FINISHED = 900,
} tx_hash_builder_state_t;

typedef struct {
	uint16_t remainingInputs;
	uint16_t remainingOutputs;
	uint16_t remainingWithdrawals;
	uint16_t remainingCertificates;
	bool includeMetadata;

	struct {
		uint16_t remainingOwners;
		uint16_t remainingRelays;
	} poolCertificateData;

	tx_hash_builder_state_t state;
	blake2b_256_context_t txHash;
} tx_hash_builder_t;


void txHashBuilder_init(
        tx_hash_builder_t* builder,
        uint16_t numInputs,
        uint16_t numOutputs,
        uint16_t numCertificates,
        uint16_t numWithdrawals,
        bool includeMetadata
);

void txHashBuilder_enterInputs(tx_hash_builder_t* builder);
void txHashBuilder_addInput(
        tx_hash_builder_t* builder,
        const uint8_t* utxoHashBuffer, size_t utxoHashSize,
        uint32_t utxoIndex
);

void txHashBuilder_enterOutputs(tx_hash_builder_t* builder);
void txHashBuilder_addOutput(
        tx_hash_builder_t* builder,
        const uint8_t* addressBuffer, size_t addressSize,
        uint64_t amount
);

void txHashBuilder_addFee(tx_hash_builder_t* builder, uint64_t fee);

void txHashBuilder_addTtl(tx_hash_builder_t* builder, uint64_t ttl);

void txHashBuilder_enterCertificates(tx_hash_builder_t* builder);
void txHashBuilder_addCertificate_stakingKey(
        tx_hash_builder_t* builder,
        const int certificateType,
        const uint8_t* stakingKeyHash, size_t stakingKeyHashSize
);
void txHashBuilder_addCertificate_delegation(
        tx_hash_builder_t* builder,
        const uint8_t* stakingKeyHash, size_t stakingKeyHashSize,
        const uint8_t* poolKeyHash, size_t poolKeyHashSize
);
void txHashBuilder_addPoolRegistrationCertificate(
        tx_hash_builder_t* builder,
        const uint8_t* poolKeyHash, size_t poolKeyHashSize,
        const uint8_t* vrfKeyHash, size_t vrfKeyHashSize,
        uint64_t pledge, uint64_t cost,
        uint64_t marginNumerator, uint64_t marginDenominator,
        const uint8_t* rewardAccount, size_t rewardAccountSize,
        uint16_t numOwners, uint16_t numRelays
);
void txHashBuilder_addPoolRegistrationCertificate_enterOwners(tx_hash_builder_t* builder);
void txHashBuilder_addPoolRegistrationCertificate_addOwner(
        tx_hash_builder_t* builder,
        const uint8_t* stakingKeyHash, size_t stakingKeyHashSize
);
void txHashBuilder_addPoolRegistrationCertificate_enterRelays(tx_hash_builder_t* builder);
void txHashBuilder_addPoolRegistrationCertificate_addRelay0(
        tx_hash_builder_t* builder,
        const uint16_t* port,
        const uint8_t* ipv4, size_t ipv4Size,
        const uint8_t* ipv6, size_t ipv6Size
);
void txHashBuilder_addPoolRegistrationCertificate_addRelay1(
        tx_hash_builder_t* builder,
        const uint16_t* port,
        const uint8_t* dnsName, size_t dnsNameSize
);
void txHashBuilder_addPoolRegistrationCertificate_addRelay2(
        tx_hash_builder_t* builder,
        const uint8_t* dnsName, size_t dnsNameSize
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

void txHashBuilder_addMetadata(
        tx_hash_builder_t* builder,
        const uint8_t* metadataHashBuffer, size_t metadataHashSize
);

void txHashBuilder_finalize(
        tx_hash_builder_t* builder,
        uint8_t* outBuffer, size_t outSize
);

void run_txHashBuilder_test();

#endif // H_CARDANO_APP_TX_HASH_BUILDER
