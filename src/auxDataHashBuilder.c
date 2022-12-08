#include "common.h"
#include "auxDataHashBuilder.h"
#include "hash.h"
#include "cbor.h"
#include "cardano.h"
#include "bufView.h"

// this tracing is rarely needed
// so we want to keep it turned off to avoid polluting the trace log

//#define TRACE_AUX_DATA_HASH_BUILDER

#ifdef TRACE_AUX_DATA_HASH_BUILDER
#define _TRACE(...) TRACE(__VA_ARGS__)
#else
#define _TRACE(...)
#endif // DEVEL

enum {
	HC_AUX_DATA =         (1u << 0), // aux data hash context
	HC_GOVERNANCE_VOTING_PAYLOAD = (1u << 1)  // governance voting registration payload hash context
};

/*
The following macros and functions have dual purpose:
1. syntactic sugar for neat recording of hash computations;
2. tracing of hash computations (allows to reconstruct bytestrings we are hashing via usbtool).
*/

#define APPEND_CBOR(hashContexts, type, value) \
	if (hashContexts & HC_AUX_DATA) { \
		blake2b_256_append_cbor_aux_data(&builder->auxDataHash, type, value, true); \
	} \
	if (hashContexts & HC_GOVERNANCE_VOTING_PAYLOAD) { \
		blake2b_256_append_cbor_aux_data(&builder->governanceVotingRegistrationData.payloadHash, type, value, false); \
	}

#define APPEND_DATA(hashContexts, buffer, bufferSize) \
	if (hashContexts & HC_AUX_DATA) { \
		blake2b_256_append_buffer_aux_data(&builder->auxDataHash, buffer, bufferSize, true); \
	} \
	if (hashContexts & HC_GOVERNANCE_VOTING_PAYLOAD) { \
		blake2b_256_append_buffer_aux_data(&builder->governanceVotingRegistrationData.payloadHash, buffer, bufferSize, false); \
	}


__noinline_due_to_stack__
static void blake2b_256_append_cbor_aux_data(
        blake2b_256_context_t* hashCtx,
        uint8_t type, uint64_t value,
        bool trace
)
{
	uint8_t buffer[10] = {0};
	size_t size = cbor_writeToken(type, value, buffer, SIZEOF(buffer));
	if (trace) {
		TRACE_BUFFER(buffer, size);
	}
	blake2b_256_append(hashCtx, buffer, size);
}

static void blake2b_256_append_buffer_aux_data(
        blake2b_256_context_t* hashCtx,
        const uint8_t* buffer, size_t bufferSize,
        bool trace
)
{
	ASSERT(bufferSize < BUFFER_SIZE_PARANOIA);

	// keeping tracing within a function to be able to extract the serialized data
	// by matching the function name where the tracing is invoked
	if (trace) {
		TRACE_BUFFER(buffer, bufferSize);
	}
	blake2b_256_append(hashCtx, buffer, bufferSize);
}

/* End of hash computation utilities. */

void auxDataHashBuilder_init(
        aux_data_hash_builder_t* builder
)
{
	TRACE("Serializing tx auxiliary data");
	blake2b_256_init(&builder->auxDataHash);
	blake2b_256_init(&builder->governanceVotingRegistrationData.payloadHash);

	{
		APPEND_CBOR(HC_AUX_DATA, CBOR_TYPE_ARRAY, 2);
	}
	builder->state = AUX_DATA_HASH_BUILDER_INIT;
}

void auxDataHashBuilder_governanceVotingRegistration_enter(
        aux_data_hash_builder_t* builder,
        governance_voting_registration_format_t format
)
{
	_TRACE("state = %d", builder->state);

	ASSERT(format == CIP15 || format == CIP36);
	builder->governanceVotingRegistrationData.format = format;

	ASSERT(builder->state == AUX_DATA_HASH_BUILDER_INIT);
	{
		// for governance voting, in the completed auxiliary data
		// there is a map with two entries 61284 and 61285
		APPEND_CBOR(HC_AUX_DATA, CBOR_TYPE_MAP, 2);
		// however, the data being signed is a map with a single entry 61284
		APPEND_CBOR(HC_GOVERNANCE_VOTING_PAYLOAD, CBOR_TYPE_MAP, 1);
		// the remainder of the payload serialization shares the cbor tokens
		// with the overall auxiliary data CBOR
	}

	builder->state = AUX_DATA_HASH_BUILDER_IN_GOVERNANCE_VOTING_REGISTRATION_INIT;
}

void auxDataHashBuilder_governanceVotingRegistration_enterPayload(aux_data_hash_builder_t* builder)
{
	_TRACE("state = %d", builder->state);

	ASSERT(builder->state == AUX_DATA_HASH_BUILDER_IN_GOVERNANCE_VOTING_REGISTRATION_INIT);
	{
		// Enter the governance voting key registration payload inner map
		size_t mapSize = (builder->governanceVotingRegistrationData.format == CIP36) ? 5 : 4;
		APPEND_CBOR(HC_AUX_DATA | HC_GOVERNANCE_VOTING_PAYLOAD, CBOR_TYPE_UNSIGNED, METADATA_KEY_GOVERNANCE_VOTING_REGISTRATION_PAYLOAD);
		APPEND_CBOR(HC_AUX_DATA | HC_GOVERNANCE_VOTING_PAYLOAD, CBOR_TYPE_MAP, mapSize);
	}
	builder->state = AUX_DATA_HASH_BUILDER_IN_GOVERNANCE_VOTING_PAYLOAD_INIT;
}

void auxDataHashBuilder_governanceVotingRegistration_addVotingKey(
        aux_data_hash_builder_t* builder,
        const uint8_t* votingPubKeyBuffer, size_t votingPubKeySize
)
{
	_TRACE("state = %d", builder->state);

	ASSERT(votingPubKeySize < BUFFER_SIZE_PARANOIA);

	ASSERT(builder->state == AUX_DATA_HASH_BUILDER_IN_GOVERNANCE_VOTING_PAYLOAD_INIT);
	{
		APPEND_CBOR(HC_AUX_DATA | HC_GOVERNANCE_VOTING_PAYLOAD, CBOR_TYPE_UNSIGNED, GOVERNANCE_VOTING_REGISTRATION_PAYLOAD_KEY_VOTING_KEY);
		{
			ASSERT(votingPubKeySize == PUBLIC_KEY_SIZE);
			APPEND_CBOR(HC_AUX_DATA | HC_GOVERNANCE_VOTING_PAYLOAD, CBOR_TYPE_BYTES, votingPubKeySize);
			APPEND_DATA(HC_AUX_DATA | HC_GOVERNANCE_VOTING_PAYLOAD, votingPubKeyBuffer, votingPubKeySize);
		}
	}
	builder->state = AUX_DATA_HASH_BUILDER_IN_GOVERNANCE_VOTING_PAYLOAD_VOTING_KEY;
}

void auxDataHashBuilder_governanceVotingRegistration_enterDelegations(
        aux_data_hash_builder_t* builder,
        size_t numDelegations
)
{
	_TRACE("state = %d", builder->state);

	builder->governanceVotingRegistrationData.remainingDelegations = numDelegations;

	ASSERT(builder->state == AUX_DATA_HASH_BUILDER_IN_GOVERNANCE_VOTING_PAYLOAD_INIT);
	{
		APPEND_CBOR(HC_AUX_DATA | HC_GOVERNANCE_VOTING_PAYLOAD, CBOR_TYPE_UNSIGNED, GOVERNANCE_VOTING_REGISTRATION_PAYLOAD_KEY_VOTING_KEY);
		APPEND_CBOR(HC_AUX_DATA | HC_GOVERNANCE_VOTING_PAYLOAD, CBOR_TYPE_ARRAY, numDelegations);
	}
	builder->state = AUX_DATA_HASH_BUILDER_IN_GOVERNANCE_VOTING_PAYLOAD_DELEGATIONS;
}

void auxDataHashBuilder_governanceVotingRegistration_addDelegation(
        aux_data_hash_builder_t* builder,
        const uint8_t* votingPubKeyBuffer, size_t votingPubKeySize,
        uint32_t weight
)
{
	_TRACE("state = %d", builder->state);

	ASSERT(votingPubKeySize < BUFFER_SIZE_PARANOIA);

	ASSERT(builder->state == AUX_DATA_HASH_BUILDER_IN_GOVERNANCE_VOTING_PAYLOAD_DELEGATIONS);
	ASSERT(builder->governanceVotingRegistrationData.remainingDelegations > 0);

	builder->governanceVotingRegistrationData.remainingDelegations--;

	{
		APPEND_CBOR(HC_AUX_DATA | HC_GOVERNANCE_VOTING_PAYLOAD, CBOR_TYPE_ARRAY, 2);
		{
			ASSERT(votingPubKeySize == PUBLIC_KEY_SIZE);
			APPEND_CBOR(HC_AUX_DATA | HC_GOVERNANCE_VOTING_PAYLOAD, CBOR_TYPE_BYTES, votingPubKeySize);
			APPEND_DATA(HC_AUX_DATA | HC_GOVERNANCE_VOTING_PAYLOAD, votingPubKeyBuffer, votingPubKeySize);
		}
		APPEND_CBOR(HC_AUX_DATA | HC_GOVERNANCE_VOTING_PAYLOAD, CBOR_TYPE_UNSIGNED, weight);
	}
}

void auxDataHashBuilder_governanceVotingRegistration_addStakingKey(
        aux_data_hash_builder_t* builder,
        const uint8_t* stakingPubKeyBuffer, size_t stakingPubKeySize
)
{
	_TRACE("state = %d", builder->state);

	ASSERT(stakingPubKeySize < BUFFER_SIZE_PARANOIA);

	switch(builder->state) {

	case AUX_DATA_HASH_BUILDER_IN_GOVERNANCE_VOTING_PAYLOAD_VOTING_KEY:
		// ok
		break;

	case AUX_DATA_HASH_BUILDER_IN_GOVERNANCE_VOTING_PAYLOAD_DELEGATIONS:
		ASSERT(builder->governanceVotingRegistrationData.remainingDelegations == 0);
		break;

	default:
		// should not happen
		ASSERT(false);
	}

	{
		APPEND_CBOR(HC_AUX_DATA | HC_GOVERNANCE_VOTING_PAYLOAD, CBOR_TYPE_UNSIGNED, GOVERNANCE_VOTING_REGISTRATION_PAYLOAD_KEY_STAKING_KEY);
		{
			ASSERT(stakingPubKeySize == PUBLIC_KEY_SIZE);
			APPEND_CBOR(HC_AUX_DATA | HC_GOVERNANCE_VOTING_PAYLOAD, CBOR_TYPE_BYTES, stakingPubKeySize);
			APPEND_DATA(HC_AUX_DATA | HC_GOVERNANCE_VOTING_PAYLOAD, stakingPubKeyBuffer, stakingPubKeySize);
		}
	}
	builder->state = AUX_DATA_HASH_BUILDER_IN_GOVERNANCE_VOTING_PAYLOAD_STAKING_KEY;
}

void auxDataHashBuilder_governanceVotingRegistration_addVotingRewardsAddress(
        aux_data_hash_builder_t* builder,
        const uint8_t* addressBuffer, size_t addressSize
)
{
	_TRACE("state = %d", builder->state);

	ASSERT(addressSize > 0);
	ASSERT(addressSize < BUFFER_SIZE_PARANOIA);

	ASSERT(builder->state == AUX_DATA_HASH_BUILDER_IN_GOVERNANCE_VOTING_PAYLOAD_STAKING_KEY);
	{
		APPEND_CBOR(HC_AUX_DATA | HC_GOVERNANCE_VOTING_PAYLOAD, CBOR_TYPE_UNSIGNED, GOVERNANCE_VOTING_REGISTRATION_PAYLOAD_KEY_VOTING_REWARDS_ADDRESS);
		{
			APPEND_CBOR(HC_AUX_DATA | HC_GOVERNANCE_VOTING_PAYLOAD, CBOR_TYPE_BYTES, addressSize);
			APPEND_DATA(HC_AUX_DATA | HC_GOVERNANCE_VOTING_PAYLOAD, addressBuffer, addressSize);
		}
	}
	builder->state = AUX_DATA_HASH_BUILDER_IN_GOVERNANCE_VOTING_PAYLOAD_VOTING_REWARDS_ADDRESS;
}

void auxDataHashBuilder_governanceVotingRegistration_addNonce(
        aux_data_hash_builder_t* builder,
        uint64_t nonce
)
{
	_TRACE("state = %d", builder->state);

	ASSERT(builder->state == AUX_DATA_HASH_BUILDER_IN_GOVERNANCE_VOTING_PAYLOAD_VOTING_REWARDS_ADDRESS);
	{
		APPEND_CBOR(HC_AUX_DATA | HC_GOVERNANCE_VOTING_PAYLOAD, CBOR_TYPE_UNSIGNED, GOVERNANCE_VOTING_REGISTRATION_PAYLOAD_KEY_NONCE);
		APPEND_CBOR(HC_AUX_DATA | HC_GOVERNANCE_VOTING_PAYLOAD, CBOR_TYPE_UNSIGNED, nonce);
	}
	builder->state = AUX_DATA_HASH_BUILDER_IN_GOVERNANCE_VOTING_PAYLOAD_NONCE;
}

void auxDataHashBuilder_governanceVotingRegistration_addVotingPurpose(
        aux_data_hash_builder_t* builder,
        uint64_t votingPurpose
)
{
	_TRACE("state = %d", builder->state);

	ASSERT(builder->state == AUX_DATA_HASH_BUILDER_IN_GOVERNANCE_VOTING_PAYLOAD_NONCE);
	{
		APPEND_CBOR(HC_AUX_DATA | HC_GOVERNANCE_VOTING_PAYLOAD, CBOR_TYPE_UNSIGNED, GOVERNANCE_VOTING_REGISTRATION_PAYLOAD_KEY_VOTING_PURPOSE);
		APPEND_CBOR(HC_AUX_DATA | HC_GOVERNANCE_VOTING_PAYLOAD, CBOR_TYPE_UNSIGNED, votingPurpose);
	}
	builder->state = AUX_DATA_HASH_BUILDER_IN_GOVERNANCE_VOTING_PAYLOAD_VOTING_PURPOSE;
}

void auxDataHashBuilder_governanceVotingRegistration_finalizePayload(aux_data_hash_builder_t* builder, uint8_t* outBuffer, size_t outSize)
{
	_TRACE("state = %d", builder->state);

	ASSERT(outSize < BUFFER_SIZE_PARANOIA);

	ASSERT(
	        builder->state == AUX_DATA_HASH_BUILDER_IN_GOVERNANCE_VOTING_PAYLOAD_NONCE ||
	        builder->state == AUX_DATA_HASH_BUILDER_IN_GOVERNANCE_VOTING_PAYLOAD_VOTING_PURPOSE
	);

	ASSERT(outSize == GOVERNANCE_VOTING_REGISTRATION_PAYLOAD_HASH_LENGTH);
	{
		blake2b_256_finalize(&builder->governanceVotingRegistrationData.payloadHash, outBuffer, outSize);
	}
}

void auxDataHashBuilder_governanceVotingRegistration_addSignature(
        aux_data_hash_builder_t* builder,
        const uint8_t* signatureBuffer, size_t signatureSize
)
{
	_TRACE("state = %d", builder->state);

	ASSERT(signatureSize < BUFFER_SIZE_PARANOIA);

	ASSERT(
	        builder->state == AUX_DATA_HASH_BUILDER_IN_GOVERNANCE_VOTING_PAYLOAD_NONCE ||
	        builder->state == AUX_DATA_HASH_BUILDER_IN_GOVERNANCE_VOTING_PAYLOAD_VOTING_PURPOSE
	);
	{
		APPEND_CBOR(HC_AUX_DATA, CBOR_TYPE_UNSIGNED, METADATA_KEY_GOVERNANCE_VOTING_SIGNATURE);
		{
			ASSERT(signatureSize == ED25519_SIGNATURE_LENGTH);
			APPEND_CBOR(HC_AUX_DATA, CBOR_TYPE_MAP, 1);
			APPEND_CBOR(HC_AUX_DATA, CBOR_TYPE_UNSIGNED, GOVERNANCE_VOTING_REGISTRATION_SIGNATURE_KEY);
			APPEND_CBOR(HC_AUX_DATA, CBOR_TYPE_BYTES, signatureSize);
			APPEND_DATA(HC_AUX_DATA, signatureBuffer, signatureSize);
		}
	}
	builder->state = AUX_DATA_HASH_BUILDER_IN_GOVERNANCE_VOTING_SIGNATURE;
}

void auxDataHashBuilder_governanceVotingRegistration_addAuxiliaryScripts(
        aux_data_hash_builder_t* builder
)
{
	_TRACE("state = %d", builder->state);

	ASSERT(builder->state == AUX_DATA_HASH_BUILDER_IN_GOVERNANCE_VOTING_SIGNATURE);
	{
		// auxiliary scripts currently hard-coded to an empty list
		APPEND_CBOR(HC_AUX_DATA, CBOR_TYPE_ARRAY, 0);
	}

	builder->state = AUX_DATA_HASH_BUILDER_IN_AUXILIARY_SCRIPTS;
}

void auxDataHashBuilder_finalize(aux_data_hash_builder_t* builder, uint8_t* outBuffer, size_t outSize)
{
	_TRACE("state = %d", builder->state);

	ASSERT(builder->state == AUX_DATA_HASH_BUILDER_IN_AUXILIARY_SCRIPTS);

	ASSERT(outSize == AUX_DATA_HASH_LENGTH);
	{
		blake2b_256_finalize(&builder->auxDataHash, outBuffer, outSize);
	}

	builder->state = AUX_DATA_HASH_BUILDER_FINISHED;
}
