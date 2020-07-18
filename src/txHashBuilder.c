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
	TRACE("numWithdrawals  = %u", numCertificates);
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

bool txHashBuilder_assertCanLeaveInit(tx_hash_builder_t* builder)
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

bool txHashBuilder_assertCanLeaveInputs(tx_hash_builder_t* builder)
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

void txHashBuilder_assertCanLeaveOutputs(tx_hash_builder_t* builder)
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

void txHashBuilder_assertCanLeaveFee(tx_hash_builder_t* builder)
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

void txHashBuilder_assertCanLeaveTtl(tx_hash_builder_t* builder)
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

void txHashBuilder_assertCanLeaveCertificates(tx_hash_builder_t* builder)
{
	ASSERT(builder->state <= TX_HASH_BUILDER_IN_CERTIFICATES);

	if (builder->state == TX_HASH_BUILDER_IN_CERTIFICATES) {
		ASSERT(builder->remainingCertificates == 0);
	} else {
		txHashBuilder_assertCanLeaveTtl(builder);
		ASSERT(builder->remainingCertificates == 0);
	}
}

void txHashBuilder_enterWithdrawals(tx_hash_builder_t* builder)
{
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
        const uint8_t* rewardAccountBuffer, size_t rewardAccountSize,
        uint64_t amount
)
{
	ASSERT(builder->state == TX_HASH_BUILDER_IN_WITHDRAWALS);
	ASSERT(builder->remainingWithdrawals > 0);
	builder->remainingWithdrawals--;

	// map entry
	//   Bytes[address]
	//   Unsigned[amount]
	{
		BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, rewardAccountSize);
		BUILDER_APPEND_DATA(rewardAccountBuffer, rewardAccountSize);
	}
	{
		BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, amount);
	}
}

void txHashBuilder_assertCanLeaveWithdrawals(tx_hash_builder_t* builder)
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

void txHashBuilder_assertCanLeaveMetadata(tx_hash_builder_t* builder)
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
