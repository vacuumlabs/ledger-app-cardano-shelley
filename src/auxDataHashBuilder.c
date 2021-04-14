#include "common.h"
#include "auxDataHashBuilder.h"
#include "hash.h"
#include "cbor.h"
#include "cardano.h"
#include "crc32.h"
#include "bufView.h"

// this tracing is rarely needed
// so we want to keep it turned off to avoid polluting the trace log

//#define TRACE_AUX_DATA_HASH_BUILDER

#ifdef TRACE_AUX_DATA_HASH_BUILDER
#define _TRACE(...) TRACE(__VA_ARGS__)
#else
#define _TRACE(...)
#endif // DEVEL

static enum {
	HASH_CTX_AUX_DATA = (1u << 0),
	HASH_CTX_CATALYST_PAYLOAD = (1u << 1)
};

// Syntactic sugar
#define APPEND_CBOR(hashContexts, type, value) \
	if (hashContexts & HASH_CTX_AUX_DATA) blake2b_256_append_cbor(&builder->auxDataHash, type, value, true); \
	if (hashContexts & HASH_CTX_CATALYST_PAYLOAD) blake2b_256_append_cbor(&builder->catalystRegistrationData.payloadHash, type, value, false);

#define APPEND_DATA(hashContexts, buffer, bufferSize) \
	if (hashContexts & HASH_CTX_AUX_DATA) blake2b_256_append_and_trace(&builder->auxDataHash, buffer, bufferSize); \
	if (hashContexts & HASH_CTX_CATALYST_PAYLOAD) blake2b_256_append(&builder->catalystRegistrationData.payloadHash, buffer, bufferSize);


__noinline_due_to_stack__
static void blake2b_256_append_cbor(
        blake2b_256_context_t* hashCtx,
        uint8_t type, uint64_t value, bool trace
)
{
	uint8_t buffer[10];
	size_t size = cbor_writeToken(type, value, buffer, SIZEOF(buffer));
	if (trace) {
		TRACE_BUFFER(buffer, size);
	}
	blake2b_256_append(hashCtx, buffer, size);
}

static void blake2b_256_append_and_trace(
        blake2b_256_context_t* hashCtx,
        const uint8_t* buffer,
        size_t bufferSize
)
{
	// keeping tracing within a function to be able to extract the serialized data
	// by matching the function name where the tracing is invoked
	TRACE_BUFFER(buffer, bufferSize);
	blake2b_256_append(hashCtx, buffer, bufferSize);
}

void auxDataHashBuilder_init(
        aux_data_hash_builder_t* builder
)
{
	TRACE("Serializing tx auxiliary data");
	blake2b_256_init(&builder->auxDataHash);
	blake2b_256_init(&builder->catalystRegistrationData.payloadHash);

	{
		APPEND_CBOR(HASH_CTX_AUX_DATA, CBOR_TYPE_ARRAY, 2);
	}
	builder->state = AUX_DATA_HASH_BUILDER_INIT;
}

void auxDataHashBuilder_catalystRegistration_enter(aux_data_hash_builder_t* builder)
{
	_TRACE("state = %d", builder->state);

	ASSERT(builder->state == AUX_DATA_HASH_BUILDER_INIT);
	{
		APPEND_CBOR(HASH_CTX_AUX_DATA, CBOR_TYPE_MAP, 2);
	}
	builder->state = AUX_DATA_HASH_BUILDER_IN_CATALYST_REGISTRATION_INIT;
}

void auxDataHashBuilder_catalystRegistration_enterPayload(aux_data_hash_builder_t* builder)
{
	_TRACE("state = %d", builder->state);

	ASSERT(builder->state == AUX_DATA_HASH_BUILDER_IN_CATALYST_REGISTRATION_INIT);
	{
		// map {61284: <payload>} is being hashed and signed in the catalyst voting registration
		// this instruction introduces the beginning of this single-key dictionary
		// the remainder of the payload serialization shares the tokens with the overall auxiliary data CBOR
		APPEND_CBOR(HASH_CTX_CATALYST_PAYLOAD, CBOR_TYPE_MAP, 1)

		// Enter the Catalyst voting key registration payload inner map
		APPEND_CBOR(HASH_CTX_AUX_DATA | HASH_CTX_CATALYST_PAYLOAD, CBOR_TYPE_UNSIGNED, METADATA_KEY_CATALYST_REGISTRATION_PAYLOAD);
		APPEND_CBOR(HASH_CTX_AUX_DATA | HASH_CTX_CATALYST_PAYLOAD, CBOR_TYPE_MAP, 4);
	}
	builder->state = AUX_DATA_HASH_BUILDER_IN_CATALYST_REGISTRATION_PAYLOAD_INIT;
}

void auxDataHashBuilder_catalystRegistration_addVotingKey(
        aux_data_hash_builder_t* builder,
        const uint8_t* votingPubKeyBuffer, size_t votingPubKeySize
)
{
	_TRACE("state = %d", builder->state);

	ASSERT(builder->state == AUX_DATA_HASH_BUILDER_IN_CATALYST_REGISTRATION_PAYLOAD_INIT);
	{
		APPEND_CBOR(HASH_CTX_AUX_DATA | HASH_CTX_CATALYST_PAYLOAD, CBOR_TYPE_UNSIGNED, CATALYST_REGISTRATION_PAYLOAD_KEY_VOTING_KEY);
		{
			ASSERT(votingPubKeySize == 32);
			APPEND_CBOR(HASH_CTX_AUX_DATA | HASH_CTX_CATALYST_PAYLOAD, CBOR_TYPE_BYTES, votingPubKeySize);
			APPEND_DATA(HASH_CTX_AUX_DATA | HASH_CTX_CATALYST_PAYLOAD, votingPubKeyBuffer, votingPubKeySize);
		}
	}
	builder->state = AUX_DATA_HASH_BUILDER_IN_CATALYST_REGISTRATION_PAYLOAD_VOTING_KEY;
}

void auxDataHashBuilder_catalystRegistration_addStakingKey(
        aux_data_hash_builder_t* builder,
        const uint8_t* stakingPubKeyBuffer, size_t stakingPubKeySize
)
{
	_TRACE("state = %d", builder->state);

	ASSERT(builder->state == AUX_DATA_HASH_BUILDER_IN_CATALYST_REGISTRATION_PAYLOAD_VOTING_KEY);
	{
		APPEND_CBOR(HASH_CTX_AUX_DATA | HASH_CTX_CATALYST_PAYLOAD, CBOR_TYPE_UNSIGNED, CATALYST_REGISTRATION_PAYLOAD_KEY_STAKING_KEY);
		{
			ASSERT(stakingPubKeySize == PUBLIC_KEY_SIZE);
			APPEND_CBOR(HASH_CTX_AUX_DATA | HASH_CTX_CATALYST_PAYLOAD, CBOR_TYPE_BYTES, stakingPubKeySize);
			APPEND_DATA(HASH_CTX_AUX_DATA | HASH_CTX_CATALYST_PAYLOAD, stakingPubKeyBuffer, stakingPubKeySize);
		}
	}
	builder->state = AUX_DATA_HASH_BUILDER_IN_CATALYST_REGISTRATION_PAYLOAD_STAKING_KEY;
}

void auxDataHashBuilder_catalystRegistration_addVotingRewardsAddress(
        aux_data_hash_builder_t* builder,
        const uint8_t* addressBuffer, size_t addressSize
)
{
	_TRACE("state = %d", builder->state);

	ASSERT(builder->state == AUX_DATA_HASH_BUILDER_IN_CATALYST_REGISTRATION_PAYLOAD_STAKING_KEY);
	{
		APPEND_CBOR(HASH_CTX_AUX_DATA | HASH_CTX_CATALYST_PAYLOAD, CBOR_TYPE_UNSIGNED, CATALYST_REGISTRATION_PAYLOAD_KEY_VOTING_REWARDS_ADDRESS);
		{
			APPEND_CBOR(HASH_CTX_AUX_DATA | HASH_CTX_CATALYST_PAYLOAD, CBOR_TYPE_BYTES, addressSize);
			APPEND_DATA(HASH_CTX_AUX_DATA | HASH_CTX_CATALYST_PAYLOAD, addressBuffer, addressSize);
		}
	}
	builder->state = AUX_DATA_HASH_BUILDER_IN_CATALYST_REGISTRATION_PAYLOAD_VOTING_REWARDS_ADDRESS;
}

void auxDataHashBuilder_catalystRegistration_addNonce(
        aux_data_hash_builder_t* builder,
        const uint64_t nonce
)
{
	_TRACE("state = %d", builder->state);

	ASSERT(builder->state == AUX_DATA_HASH_BUILDER_IN_CATALYST_REGISTRATION_PAYLOAD_VOTING_REWARDS_ADDRESS);
	{
		APPEND_CBOR(HASH_CTX_AUX_DATA | HASH_CTX_CATALYST_PAYLOAD, CBOR_TYPE_UNSIGNED, CATALYST_REGISTRATION_PAYLOAD_KEY_NONCE);
		APPEND_CBOR(HASH_CTX_AUX_DATA | HASH_CTX_CATALYST_PAYLOAD, CBOR_TYPE_UNSIGNED, nonce);
	}
	builder->state = AUX_DATA_HASH_BUILDER_IN_CATALYST_REGISTRATION_PAYLOAD_NONCE;
}

void auxDataHashBuilder_catalystRegistration_finalizePayload(aux_data_hash_builder_t* builder, uint8_t* outBuffer, size_t outSize)
{
	_TRACE("state = %d", builder->state);

	ASSERT(builder->state == AUX_DATA_HASH_BUILDER_IN_CATALYST_REGISTRATION_PAYLOAD_NONCE);

	ASSERT(outSize == 32);
	{
		blake2b_256_finalize(&builder->catalystRegistrationData.payloadHash, outBuffer, outSize);
	}
}

void auxDataHashBuilder_catalystRegistration_addSignature(
        aux_data_hash_builder_t* builder,
        const uint8_t* signatureBuffer, size_t signatureSize
)
{
	_TRACE("state = %d", builder->state);

	ASSERT(builder->state == AUX_DATA_HASH_BUILDER_IN_CATALYST_REGISTRATION_PAYLOAD_NONCE);
	{
		APPEND_CBOR(HASH_CTX_AUX_DATA, CBOR_TYPE_UNSIGNED, METADATA_KEY_CATALYST_REGISTRATION_SIGNATURE);
		{
			ASSERT(signatureSize == 64);
			APPEND_CBOR(HASH_CTX_AUX_DATA, CBOR_TYPE_MAP, 1);
			APPEND_CBOR(HASH_CTX_AUX_DATA, CBOR_TYPE_UNSIGNED, CATALYST_REGISTRATION_SIGNATURE_KEY);
			APPEND_CBOR(HASH_CTX_AUX_DATA, CBOR_TYPE_BYTES, signatureSize);
			APPEND_DATA(HASH_CTX_AUX_DATA, signatureBuffer, signatureSize);
		}
	}
	builder->state = AUX_DATA_HASH_BUILDER_IN_CATALYST_REGISTRATION_SIGNATURE;
}

void auxDataHashBuilder_catalystRegistration_addAuxiliaryScripts(
        aux_data_hash_builder_t* builder
)
{
	_TRACE("state = %d", builder->state);

	ASSERT(builder->state == AUX_DATA_HASH_BUILDER_IN_CATALYST_REGISTRATION_SIGNATURE);
	{
		// auxiliary scripts currently hard-coded to an empty list
		APPEND_CBOR(HASH_CTX_AUX_DATA, CBOR_TYPE_ARRAY, 0);
	}

	builder->state = AUX_DATA_HASH_BUILDER_IN_AUXILIARY_SCRIPTS;
}

void auxDataHashBuilder_finalize(aux_data_hash_builder_t* builder, uint8_t* outBuffer, size_t outSize)
{
	_TRACE("state = %d", builder->state);

	ASSERT(builder->state == AUX_DATA_HASH_BUILDER_IN_AUXILIARY_SCRIPTS);

	ASSERT(outSize == 32);
	{
		blake2b_256_finalize(&builder->auxDataHash, outBuffer, outSize);
	}

	builder->state = AUX_DATA_HASH_BUILDER_FINISHED;
}
