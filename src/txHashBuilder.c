#include "common.h"
#include "txHashBuilder.h"
#include "hash.h"
#include "cbor.h"
#include "cardano.h"
#include "crc32.h"
#include "bufView.h"

// Syntactic sugar
#define BUILDER_APPEND_CBOR(type, value) \
	blake2b_256_append_cbor(&builder->txHash, type, value)

#define BUILDER_APPEND_DATA(buffer, bufferSize) \
	blake2b_256_append_and_trace(&builder->txHash, buffer, bufferSize)


void blake2b_256_append_and_trace(
        blake2b_256_context_t* hashCtx,
        const uint8_t* buffer,
        size_t bufferSize
)
{
	TRACE_BUFFER(buffer, bufferSize);
	blake2b_256_append(hashCtx, buffer, bufferSize);
}

void blake2b_256_append_cbor(
        blake2b_256_context_t* hashCtx,
        uint8_t type, uint64_t value
)
{
	uint8_t buffer[10];
	size_t size = cbor_writeToken(type, value, buffer, SIZEOF(buffer));
	TRACE_BUFFER(buffer, size);
	blake2b_256_append(hashCtx, buffer, size);
}

void txHashBuilder_init(
        tx_hash_builder_t* builder,
        uint16_t numInputs,
        uint16_t numOutputs,
        uint16_t numCertificates,
        uint16_t numWithdrawals,
        bool includeMetadata
)
{
	TRACE("numInputs = %u", numInputs);
	TRACE("numOutputs = %u", numOutputs);
	TRACE("numCertificates = %u", numCertificates);
	TRACE("numWithdrawals  = %u", numWithdrawals);
	TRACE("includeMetadata = %u", includeMetadata);

	blake2b_256_init(&builder->txHash);

	{
		size_t numItems = 4;

		builder->remainingInputs = numInputs;
		builder->remainingOutputs = numOutputs;

		builder->remainingCertificates = numCertificates;
		if (numCertificates > 0) numItems++;

		builder->remainingWithdrawals = numWithdrawals;
		if (numWithdrawals > 0) numItems++;

		builder->includeMetadata = includeMetadata;
		if (includeMetadata) numItems++;

		TRACE("Serializing tx body with %u items", numItems);
		BUILDER_APPEND_CBOR(CBOR_TYPE_MAP, numItems);
	}
	builder->state = TX_HASH_BUILDER_INIT;
}

static void txHashBuilder_assertCanLeaveInit(tx_hash_builder_t* builder)
{
	ASSERT(builder->state == TX_HASH_BUILDER_INIT);
}

void txHashBuilder_enterInputs(tx_hash_builder_t* builder)
{
	txHashBuilder_assertCanLeaveInit(builder);
	{
		// Enter inputs
		BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, TX_BODY_KEY_INPUTS);
		BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, builder->remainingInputs);
	}
	builder->state = TX_HASH_BUILDER_IN_INPUTS;
}

void txHashBuilder_addInput(
        tx_hash_builder_t* builder,
        const uint8_t* utxoHashBuffer, size_t utxoHashSize,
        uint32_t utxoIndex
)
{
	ASSERT(builder->state == TX_HASH_BUILDER_IN_INPUTS);
	ASSERT(builder->remainingInputs > 0);
	builder->remainingInputs--;
	// Array(2)[
	//    Bytes[hash],
	//    Unsigned[index]
	// ]
	{
		BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 2);
		{
			ASSERT(utxoHashSize == 32);
			BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, utxoHashSize);
			BUILDER_APPEND_DATA(utxoHashBuffer, utxoHashSize);
		}
		{
			BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, utxoIndex);
		}
	}
}

static void txHashBuilder_assertCanLeaveInputs(tx_hash_builder_t* builder)
{
	ASSERT(builder->state == TX_HASH_BUILDER_IN_INPUTS);
	ASSERT(builder->remainingInputs == 0);
}

void txHashBuilder_enterOutputs(tx_hash_builder_t* builder)
{
	txHashBuilder_assertCanLeaveInputs(builder);
	{
		// Enter outputs
		BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, TX_BODY_KEY_OUTPUTS);
		BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, builder->remainingOutputs);
	}
	builder->state = TX_HASH_BUILDER_IN_OUTPUTS;
}

void txHashBuilder_addOutput(
        tx_hash_builder_t* builder,
        const uint8_t* addressBuffer, size_t addressSize,
        uint64_t amount
)
{
	ASSERT(builder->state == TX_HASH_BUILDER_IN_OUTPUTS);
	ASSERT(builder->remainingOutputs > 0);
	builder->remainingOutputs--;

	// Array(2)[
	//   Bytes[address]
	//   Unsigned[amount]
	// ]
	{
		BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 2);
		{
			BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, addressSize);
			BUILDER_APPEND_DATA(addressBuffer, addressSize);
		}
		{
			BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, amount);
		}
	}
}

static void txHashBuilder_assertCanLeaveOutputs(tx_hash_builder_t* builder)
{
	ASSERT(builder->state == TX_HASH_BUILDER_IN_OUTPUTS);
	ASSERT(builder->remainingOutputs == 0);
}

void txHashBuilder_addFee(tx_hash_builder_t* builder, uint64_t fee)
{
	txHashBuilder_assertCanLeaveOutputs(builder);

	// add fee item into the main tx body map
	BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, TX_BODY_KEY_FEE);
	BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, fee);

	builder->state = TX_HASH_BUILDER_IN_FEE;
}

static void txHashBuilder_assertCanLeaveFee(tx_hash_builder_t* builder)
{
	ASSERT(builder->state == TX_HASH_BUILDER_IN_FEE);
}

void txHashBuilder_addTtl(tx_hash_builder_t* builder, uint64_t ttl)
{
	txHashBuilder_assertCanLeaveFee(builder);

	BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, TX_BODY_KEY_TTL);
	BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, ttl);

	builder->state = TX_HASH_BUILDER_IN_TTL;
}

static void txHashBuilder_assertCanLeaveTtl(tx_hash_builder_t* builder)
{
	ASSERT(builder->state == TX_HASH_BUILDER_IN_TTL);
}


void txHashBuilder_enterCertificates(tx_hash_builder_t* builder)
{
	txHashBuilder_assertCanLeaveTtl(builder);
	ASSERT(builder->remainingCertificates > 0);

	{
		// Enter certificates
		BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, TX_BODY_KEY_CERTIFICATES);
		BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, builder->remainingCertificates);
	}

	builder->poolCertificateData.remainingOwners = 0;
	builder->poolCertificateData.remainingRelays = 0;

	builder->state = TX_HASH_BUILDER_IN_CERTIFICATES;
}

// staking key certificate registration or deregistration
void txHashBuilder_addCertificate_stakingKey(
        tx_hash_builder_t* builder,
        const int certificateType,
        const uint8_t* stakingKeyHash, size_t stakingKeyHashSize
)
{
	ASSERT(builder->state == TX_HASH_BUILDER_IN_CERTIFICATES);
	ASSERT(builder->remainingCertificates > 0);
	builder->remainingCertificates--;
	ASSERT((certificateType == CERTIFICATE_TYPE_STAKE_REGISTRATION)
	       || (certificateType == CERTIFICATE_TYPE_STAKE_DEREGISTRATION));

	// Array(2)[
	//   Unsigned[certificateType]
	//   Array(2)[
	//     Unsigned[0]
	//     Bytes[stakingKeyHash]
	//   ]
	// ]
	{
		BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 2);
		{
			BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, certificateType);
		}
		{
			BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 2);
			{
				BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, 0);
			}
			{
				BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, stakingKeyHashSize);
				BUILDER_APPEND_DATA(stakingKeyHash, stakingKeyHashSize);
			}
		}
	}
}

void txHashBuilder_addCertificate_delegation(
        tx_hash_builder_t* builder,
        const uint8_t* stakingKeyHash, size_t stakingKeyHashSize,
        const uint8_t* poolKeyHash, size_t poolKeyHashSize
)
{
	ASSERT(builder->state == TX_HASH_BUILDER_IN_CERTIFICATES);
	ASSERT(builder->remainingCertificates > 0);
	builder->remainingCertificates--;

	// Array(2)[
	//   Unsigned[2]
	//   Array(2)[
	//     Unsigned[0]
	//     Bytes[stakingKeyHash]
	//   ]
	//   Bytes[poolKeyHash]
	// ]
	{
		BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 3);
		{
			BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, 2);
		}
		{
			BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 2);
			{
				BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, 0);
			}
			{
				BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, stakingKeyHashSize);
				BUILDER_APPEND_DATA(stakingKeyHash, stakingKeyHashSize);
			}
		}
		{
			BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, poolKeyHashSize);
			BUILDER_APPEND_DATA(poolKeyHash, poolKeyHashSize);
		}
	}
}

void txHashBuilder_addPoolRegistrationCertificate(
        tx_hash_builder_t* builder,
        const uint8_t* poolKeyHash, size_t poolKeyHashSize,
        const uint8_t* vrfKeyHash, size_t vrfKeyHashSize,
        uint64_t pledge, uint64_t cost,
        uint64_t marginNumerator, uint64_t marginDenominator,
        const uint8_t* rewardAccount, size_t rewardAccountSize,
        uint16_t numOwners, uint16_t numRelays
)
{
	TRACE("txHashBuilder_addPoolRegistrationCertificate: %d", builder->state);

	ASSERT(builder->state == TX_HASH_BUILDER_IN_CERTIFICATES);
	ASSERT(builder->remainingCertificates > 0);
	builder->remainingCertificates--;

	ASSERT(builder->poolCertificateData.remainingOwners == 0);
	builder->poolCertificateData.remainingOwners = numOwners;
	ASSERT(builder->poolCertificateData.remainingRelays == 0);
	builder->poolCertificateData.remainingRelays = numRelays;

	// Array(10)[
	//   Unsigned[3]
	//   Bytes[pool_keyhash]
	//   Bytes[vrf_keyhash]
	//   Unsigned[pledge]
	//   Unsigned[cost]
	//   Tag(30) Array(2)[
	//     Unsigned[marginDenominator]
	//     Unsigned[marginNumerator]
	//   ]
	//   Bytes[rewardAccount]

	// the array is not closed yet, we need to add owners, relays, pool metadata
	{
		BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 10);
		{
			BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, 3);
		}
		{
			BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, poolKeyHashSize);
			BUILDER_APPEND_DATA(poolKeyHash, poolKeyHashSize);
		}
		{
			BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, vrfKeyHashSize);
			BUILDER_APPEND_DATA(vrfKeyHash, vrfKeyHashSize);
		}
		{
			BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, pledge);
		}
		{
			BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, cost);
		}
		{
			BUILDER_APPEND_CBOR(CBOR_TYPE_TAG, 30);
			BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 2);
			{
				BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, marginNumerator);
			}
			{
				BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, marginDenominator);
			}
		}
		{
			BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, rewardAccountSize);
			BUILDER_APPEND_DATA(rewardAccount, rewardAccountSize);
		}
	}

	builder->state = TX_HASH_BUILDER_IN_CERTIFICATES_POOL;
}

void txHashBuilder_addPoolRegistrationCertificate_enterOwners(tx_hash_builder_t* builder)
{
	TRACE("txHashBuilder_addPoolRegistrationCertificate_enterOwners: %d", builder->state);

	ASSERT(builder->state == TX_HASH_BUILDER_IN_CERTIFICATES_POOL);

	{
		BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, builder->poolCertificateData.remainingOwners);
	}

	builder->state = TX_HASH_BUILDER_IN_CERTIFICATES_POOL_OWNERS;
}

void txHashBuilder_addPoolRegistrationCertificate_addOwner(
        tx_hash_builder_t* builder,
        const uint8_t* stakingKeyHash, size_t stakingKeyHashSize
)
{
	TRACE("txHashBuilder_addPoolRegistrationCertificate_addOwner: %d", builder->state);

	ASSERT(builder->state == TX_HASH_BUILDER_IN_CERTIFICATES_POOL_OWNERS);
	ASSERT(builder->poolCertificateData.remainingOwners > 0);
	builder->poolCertificateData.remainingOwners--;

	// Bytes[poolKeyHash]
	{
		BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, stakingKeyHashSize);
		BUILDER_APPEND_DATA(stakingKeyHash, stakingKeyHashSize);
	}
}

void txHashBuilder_addPoolRegistrationCertificate_enterRelays(tx_hash_builder_t* builder)
{
	TRACE("txHashBuilder_addPoolRegistrationCertificate_addOwner: %d", builder->state);

	// enter empty owners if none were received
	if (builder->state == TX_HASH_BUILDER_IN_CERTIFICATES_POOL)
		txHashBuilder_addPoolRegistrationCertificate_enterOwners(builder);

	ASSERT(builder->state == TX_HASH_BUILDER_IN_CERTIFICATES_POOL_OWNERS);
	ASSERT(builder->poolCertificateData.remainingOwners == 0);

	{
		BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, builder->poolCertificateData.remainingRelays);
	}

	builder->state = TX_HASH_BUILDER_IN_CERTIFICATES_POOL_RELAYS;
}

static void addRelay_updateState(tx_hash_builder_t* builder)
{
	switch (builder->state) {
	case TX_HASH_BUILDER_IN_CERTIFICATES_POOL:
	case TX_HASH_BUILDER_IN_CERTIFICATES_POOL_OWNERS:
		txHashBuilder_addPoolRegistrationCertificate_enterRelays(builder);
		break;

	case TX_HASH_BUILDER_IN_CERTIFICATES_POOL_RELAYS:
		break; // we want to be here

	default:
		ASSERT(false);
	}
	ASSERT(builder->state == TX_HASH_BUILDER_IN_CERTIFICATES_POOL_RELAYS);
}

void txHashBuilder_addPoolRegistrationCertificate_addRelay0(
        tx_hash_builder_t* builder,
        const uint16_t* port,
        const uint8_t* ipv4, size_t ipv4Size,
        const uint8_t* ipv6, size_t ipv6Size
)
{
	TRACE("txHashBuilder_addPoolRegistrationCertificate_addRelay0: %d", builder->state);

	addRelay_updateState(builder);
	ASSERT(builder->state == TX_HASH_BUILDER_IN_CERTIFICATES_POOL_RELAYS);
	ASSERT(builder->poolCertificateData.remainingRelays > 0);
	builder->poolCertificateData.remainingRelays--;

	ASSERT(ipv4Size < BUFFER_SIZE_PARANOIA);
	ASSERT(ipv6Size < BUFFER_SIZE_PARANOIA);

	// Array(4)[
	//   Unsigned[0]
	//   Unsigned[port] / Null
	//   Bytes[ipv4] / Null
	//   Bytes[ipv6] / Null
	// ]
	{
		BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 4);
		{
			BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, 0);
		}
		{
			if (port != NULL) {
				BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, *port);
			} else {
				BUILDER_APPEND_CBOR(CBOR_TYPE_NULL, 0);
			}
		}
		{
			if (ipv4 != NULL) {
				ASSERT(ipv4Size > 0);
				BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, ipv4Size);
				BUILDER_APPEND_DATA(ipv4, ipv4Size);
			} else {
				BUILDER_APPEND_CBOR(CBOR_TYPE_NULL, 0);
			}
		}
		{
			if (ipv6 != NULL) {
				ASSERT(ipv6Size > 0);
				BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, ipv6Size);
				BUILDER_APPEND_DATA(ipv6, ipv6Size);
			} else {
				BUILDER_APPEND_CBOR(CBOR_TYPE_NULL, 0);
			}
		}
	}
}

void txHashBuilder_addPoolRegistrationCertificate_addRelay1(
        tx_hash_builder_t* builder,
        const uint16_t* port,
        const uint8_t* dnsName, size_t dnsNameSize
)
{
	TRACE("txHashBuilder_addPoolRegistrationCertificate_addRelay1: %d", builder->state);

	addRelay_updateState(builder);
	ASSERT(builder->state == TX_HASH_BUILDER_IN_CERTIFICATES_POOL_RELAYS);
	ASSERT(builder->poolCertificateData.remainingRelays > 0);
	builder->poolCertificateData.remainingRelays--;

	ASSERT(dnsName != NULL);
	ASSERT(dnsNameSize > 0);
	ASSERT(dnsNameSize < BUFFER_SIZE_PARANOIA);

	// Array(3)[
	//   Unsigned[1]
	//   Unsigned[port] / Null
	//   Text[dnsName]
	// ]
	{
		BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 3);
		{
			BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, 1);
		}
		{
			if (port != NULL) {
				BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, *port);
			} else {
				BUILDER_APPEND_CBOR(CBOR_TYPE_NULL, 0);
			}
		}
		{
			BUILDER_APPEND_CBOR(CBOR_TYPE_TEXT, dnsNameSize);
			BUILDER_APPEND_DATA(dnsName, dnsNameSize);
		}
	}
}

void txHashBuilder_addPoolRegistrationCertificate_addRelay2(
        tx_hash_builder_t* builder,
        const uint8_t* dnsName, size_t dnsNameSize
)
{
	TRACE("txHashBuilder_addPoolRegistrationCertificate_addRelay2: %d", builder->state);

	addRelay_updateState(builder);
	ASSERT(builder->state == TX_HASH_BUILDER_IN_CERTIFICATES_POOL_RELAYS);
	ASSERT(builder->poolCertificateData.remainingRelays > 0);
	builder->poolCertificateData.remainingRelays--;

	ASSERT(dnsName != NULL);
	ASSERT(dnsNameSize > 0);
	ASSERT(dnsNameSize < BUFFER_SIZE_PARANOIA);

	// Array(2)[
	//   Unsigned[2]
	//   Text[dnsName]
	// ]
	{
		BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 3);
		{
			BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, 1);
		}
		{
			BUILDER_APPEND_CBOR(CBOR_TYPE_TEXT, dnsNameSize);
			BUILDER_APPEND_DATA(dnsName, dnsNameSize);
		}
	}
}

// enter empty owners or relays if none were received
static void addPoolMetadata_updateState(tx_hash_builder_t* builder)
{
	switch (builder->state) {
	case TX_HASH_BUILDER_IN_CERTIFICATES_POOL:
	case TX_HASH_BUILDER_IN_CERTIFICATES_POOL_OWNERS:
		txHashBuilder_addPoolRegistrationCertificate_enterRelays(builder);
	// intentional fallthrough

	case TX_HASH_BUILDER_IN_CERTIFICATES_POOL_RELAYS:
		ASSERT(builder->poolCertificateData.remainingRelays == 0);
		break; // we want to be here

	default:
		ASSERT(false);
	}

	builder->state = TX_HASH_BUILDER_IN_CERTIFICATES_POOL_METADATA;
}

void txHashBuilder_addPoolRegistrationCertificate_addPoolMetadata(
        tx_hash_builder_t* builder,
        const uint8_t* url, size_t urlSize,
        const uint8_t* metadataHash, size_t metadataHashSize
)
{
	TRACE("txHashBuilder_addPoolRegistrationCertificate_addPoolMetadata: %d", builder->state);

	addPoolMetadata_updateState(builder);
	ASSERT(builder->state == TX_HASH_BUILDER_IN_CERTIFICATES_POOL_METADATA);

	// Array(2)[
	//   Tstr[url]
	//   Bytes[metadataHash]
	// ]
	{
		BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 2);
		{
			BUILDER_APPEND_CBOR(CBOR_TYPE_TEXT, urlSize);
			BUILDER_APPEND_DATA(url, urlSize);
		}
		{
			BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, metadataHashSize);
			BUILDER_APPEND_DATA(metadataHash, metadataHashSize);
		}
	}
	builder->state = TX_HASH_BUILDER_IN_CERTIFICATES;
}

void txHashBuilder_addPoolRegistrationCertificate_addPoolMetadata_null(
        tx_hash_builder_t* builder
)
{
	TRACE("txHashBuilder_addPoolRegistrationCertificate_addPoolMetadata_null: %d", builder->state);

	addPoolMetadata_updateState(builder);
	ASSERT(builder->state == TX_HASH_BUILDER_IN_CERTIFICATES_POOL_METADATA);
	{
		BUILDER_APPEND_CBOR(CBOR_TYPE_NULL, 0);
	}
	builder->state = TX_HASH_BUILDER_IN_CERTIFICATES;
}

static void txHashBuilder_assertCanLeaveCertificates(tx_hash_builder_t* builder)
{
	if (builder->state == TX_HASH_BUILDER_IN_CERTIFICATES) {
		ASSERT(builder->remainingCertificates == 0);
	} else if (builder->state == TX_HASH_BUILDER_IN_TTL) {
		txHashBuilder_assertCanLeaveTtl(builder);
		ASSERT(builder->remainingCertificates == 0);
	} else {
		ASSERT(false);
	}
}

void txHashBuilder_enterWithdrawals(tx_hash_builder_t* builder)
{
	TRACE("txHashBuilder_enterWithdrawals: %d", builder->state);

	txHashBuilder_assertCanLeaveCertificates(builder);
	ASSERT(builder->remainingWithdrawals > 0);

	{
		// enter withdrawals
		BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, TX_BODY_KEY_WITHDRAWALS);
		BUILDER_APPEND_CBOR(CBOR_TYPE_MAP, builder->remainingWithdrawals);
	}

	builder->state = TX_HASH_BUILDER_IN_WITHDRAWALS;
}

void txHashBuilder_addWithdrawal(
        tx_hash_builder_t* builder,
        const uint8_t* rewardAddressBuffer, size_t rewardAddressSize,
        uint64_t amount
)
{
	ASSERT(builder->state == TX_HASH_BUILDER_IN_WITHDRAWALS);
	ASSERT(builder->remainingWithdrawals > 0);
	ASSERT(rewardAddressSize == 1 + ADDRESS_KEY_HASH_LENGTH);
	builder->remainingWithdrawals--;

	// map entry
	//   Bytes[address]
	//   Unsigned[amount]
	{
		BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, rewardAddressSize);
		BUILDER_APPEND_DATA(rewardAddressBuffer, rewardAddressSize);
	}
	{
		BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, amount);
	}
}

static void txHashBuilder_assertCanLeaveWithdrawals(tx_hash_builder_t* builder)
{
	ASSERT(builder->state <= TX_HASH_BUILDER_IN_WITHDRAWALS);

	if (builder->state == TX_HASH_BUILDER_IN_WITHDRAWALS) {
		ASSERT(builder->remainingWithdrawals == 0);
	} else {
		txHashBuilder_assertCanLeaveCertificates(builder);
		ASSERT(builder->remainingWithdrawals == 0);
	}
}

void txHashBuilder_addMetadata(tx_hash_builder_t* builder, const uint8_t* metadataHashBuffer, size_t metadataHashBufferSize)
{
	txHashBuilder_assertCanLeaveWithdrawals(builder);
	ASSERT(builder->includeMetadata);

	{
		BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, 7);
		BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, metadataHashBufferSize);
		BUILDER_APPEND_DATA(metadataHashBuffer, metadataHashBufferSize);
	}
	builder->state = TX_HASH_BUILDER_IN_METADATA;
}

static void txHashBuilder_assertCanLeaveMetadata(tx_hash_builder_t* builder)
{
	ASSERT(builder->state <= TX_HASH_BUILDER_IN_METADATA);

	if (builder->state == TX_HASH_BUILDER_IN_METADATA) {
		// nothing to do
	} else {
		txHashBuilder_assertCanLeaveWithdrawals(builder);
		ASSERT(!builder->includeMetadata);
	}
}

void txHashBuilder_finalize(tx_hash_builder_t* builder, uint8_t* outBuffer, size_t outSize)
{
	txHashBuilder_assertCanLeaveMetadata(builder);

	ASSERT(outSize == 32);
	{
		blake2b_256_finalize(&builder->txHash, outBuffer, outSize);
	}

	builder->state = TX_HASH_BUILDER_FINISHED;
}
