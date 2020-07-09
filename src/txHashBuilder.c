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
	blake2b_256_append(&builder->txHash, buffer, bufferSize)


void blake2b_256_append_cbor(
        blake2b_256_context_t* hashCtx,
        uint8_t type, uint64_t value
)
{
	uint8_t buffer[10];
	TRACE();
	size_t size = cbor_writeToken(type, value, buffer, SIZEOF(buffer));
	TRACE();
	blake2b_256_append(hashCtx, buffer, size);
}

void txHashBuilder_init(tx_hash_builder_t* builder)
{
	TRACE();
	blake2b_256_init(&builder->txHash);
	{
		TRACE();
		// main preamble
		BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 3);
		BUILDER_APPEND_CBOR(CBOR_TYPE_MAP, 4);
	}
	TRACE();
	builder->state = TX_HASH_BUILDER_INIT;
}

void txHashBuilder_enterInputs(tx_hash_builder_t* builder, const uint16_t numInputs)
{
	ASSERT(builder->state == TX_HASH_BUILDER_INIT);
	{
		// Enter inputs
		BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, TX_BODY_KEY_INPUTS);
		BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, numInputs);
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

void txHashBuilder_enterOutputs(tx_hash_builder_t* builder, const uint16_t numOutputs)
{
	ASSERT(builder->state == TX_HASH_BUILDER_IN_INPUTS);
	{
		// End inputs
		BUILDER_APPEND_CBOR(CBOR_TYPE_INDEF_END, 0);
		// Enter outputs
		BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, TX_BODY_KEY_OUTPUTS);
		BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, numOutputs);
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

void txHashBuilder_addFee(tx_hash_builder_t* builder, uint64_t fee)
{
	ASSERT(builder->state == TX_HASH_BUILDER_IN_OUTPUTS);

	// end outputs
	BUILDER_APPEND_CBOR(CBOR_TYPE_INDEF_END, 0);

	// add fee item into the map
	BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, TX_BODY_KEY_FEE);
	BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, fee);

	builder->state = TX_HASH_BUILDER_IN_FEE;
}

void txHashBuilder_addTtl(tx_hash_builder_t* builder, uint64_t ttl)
{
	ASSERT(builder->state == TX_HASH_BUILDER_IN_FEE);

	BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, TX_BODY_KEY_TTL);
	BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, ttl);

	builder->state = TX_HASH_BUILDER_IN_TTL;
}

void txHashBuilder_enterCertificates(tx_hash_builder_t* builder)
{
	ASSERT(builder->state == TX_HASH_BUILDER_IN_TTL);
	{
		// Enter certificates
		BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, TX_BODY_KEY_CERTIFICATES);
		BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY_INDEF, 0);
	}
	builder->state = TX_HASH_BUILDER_IN_CERTIFICATES;
}

// TODO
void txHashBuilder_addCertificate(
        tx_hash_builder_t* builder,
        const uint8_t* addressBuffer, size_t addressSize,
        uint64_t amount
)
{
	ASSERT(builder->state == TX_HASH_BUILDER_IN_CERTIFICATES);

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

void txHashBuilder_enterWithdrawals(tx_hash_builder_t* builder)
{
	switch (builder->state) {
	case TX_HASH_BUILDER_IN_TTL:
		break;

	case TX_HASH_BUILDER_IN_CERTIFICATES:
		// end certificates
		BUILDER_APPEND_CBOR(CBOR_TYPE_INDEF_END, 0);

	default:
		ASSERT(false);
	}
	{
		// Enter withdrawals
		BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, TX_BODY_KEY_WITHDRAWALS);
		BUILDER_APPEND_CBOR(CBOR_TYPE_MAP_INDEF, 0);
	}
	builder->state = TX_HASH_BUILDER_IN_WITHDRAWALS;
}

// TODO
void txHashBuilder_addWithdrawal(
        tx_hash_builder_t* builder,
        const uint8_t* rewardAccountBuffer, size_t rewardAccountSize,
        uint64_t amount
)
{
	ASSERT(builder->state == TX_HASH_BUILDER_IN_CERTIFICATES);

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

void txHashBuilder_addMetadata(tx_hash_builder_t* builder, const uint8_t* metadataHashBuffer, size_t metadataHashBufferSize)
{
	switch (builder->state) {
	case TX_HASH_BUILDER_IN_TTL:
		break;

	case TX_HASH_BUILDER_IN_CERTIFICATES:
		// end certificates
		BUILDER_APPEND_CBOR(CBOR_TYPE_INDEF_END, 0);

	case TX_HASH_BUILDER_IN_WITHDRAWALS:
		// end withdrawals
		BUILDER_APPEND_CBOR(CBOR_TYPE_INDEF_END, 0);
		break;

	default:
		ASSERT(false);
	}
	{
		BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, 7);
		BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, metadataHashBufferSize);
		BUILDER_APPEND_DATA(metadataHashBuffer, metadataHashBufferSize);
	}
	builder->state = TX_HASH_BUILDER_IN_METADATA;
}

void txHashBuilder_addNullMetadata(tx_hash_builder_t* builder)
{
	TRACE();
	switch (builder->state) {
		case TX_HASH_BUILDER_IN_TTL:
			break;

		case TX_HASH_BUILDER_IN_CERTIFICATES:
			// end certificates
			BUILDER_APPEND_CBOR(CBOR_TYPE_INDEF_END, 0);

		case TX_HASH_BUILDER_IN_WITHDRAWALS:
			// end withdrawals
			BUILDER_APPEND_CBOR(CBOR_TYPE_INDEF_END, 0);
			break;

		default:
			ASSERT(false);
	}
	{
		TRACE();
		BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, 7);
		TRACE();
		BUILDER_APPEND_CBOR(CBOR_TYPE_PRIMITIVES, CBOR_PRIMITIVE_NULL);
		TRACE();
	}
	builder->state = TX_HASH_BUILDER_IN_METADATA;
}

void txHashBuilder_finalize(tx_hash_builder_t* builder, uint8_t* outBuffer, size_t outSize)
{
	ASSERT(builder->state == TX_HASH_BUILDER_IN_METADATA);
	ASSERT(outSize == 32);
	{
		blake2b_256_finalize(&builder->txHash, outBuffer, outSize);
	}
	builder->state = TX_HASH_BUILDER_FINISHED;
}
