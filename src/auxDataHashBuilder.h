#ifndef H_CARDANO_APP_AUX_DATA_HASH_BUILDER
#define H_CARDANO_APP_AUX_DATA_HASH_BUILDER

#include "cardano.h"
#include "hash.h"
#include "keyDerivation.h"

enum {
	METADATA_KEY_GOVERNANCE_VOTING_REGISTRATION_PAYLOAD = 61284,
	METADATA_KEY_GOVERNANCE_VOTING_SIGNATURE = 61285,
};

enum {
	GOVERNANCE_VOTING_REGISTRATION_PAYLOAD_KEY_VOTING_KEY = 1,
	GOVERNANCE_VOTING_REGISTRATION_PAYLOAD_KEY_STAKING_KEY = 2,
	GOVERNANCE_VOTING_REGISTRATION_PAYLOAD_KEY_VOTING_REWARDS_ADDRESS = 3,
	GOVERNANCE_VOTING_REGISTRATION_PAYLOAD_KEY_NONCE = 4,
	GOVERNANCE_VOTING_REGISTRATION_PAYLOAD_KEY_VOTING_PURPOSE = 5,
};

enum {
	GOVERNANCE_VOTING_REGISTRATION_SIGNATURE_KEY = 1,
};

typedef enum {
	AUX_DATA_HASH_BUILDER_INIT = 100,
	AUX_DATA_HASH_BUILDER_IN_GOVERNANCE_VOTING_REGISTRATION_INIT = 200,
	AUX_DATA_HASH_BUILDER_IN_GOVERNANCE_VOTING_PAYLOAD_INIT = 210,
	AUX_DATA_HASH_BUILDER_IN_GOVERNANCE_VOTING_PAYLOAD_VOTING_KEY = 211,
	AUX_DATA_HASH_BUILDER_IN_GOVERNANCE_VOTING_PAYLOAD_DELEGATIONS = 212,
	AUX_DATA_HASH_BUILDER_IN_GOVERNANCE_VOTING_PAYLOAD_STAKING_KEY = 213,
	AUX_DATA_HASH_BUILDER_IN_GOVERNANCE_VOTING_PAYLOAD_VOTING_REWARDS_ADDRESS = 214,
	AUX_DATA_HASH_BUILDER_IN_GOVERNANCE_VOTING_PAYLOAD_NONCE = 215,
	AUX_DATA_HASH_BUILDER_IN_GOVERNANCE_VOTING_PAYLOAD_VOTING_PURPOSE = 216,
	AUX_DATA_HASH_BUILDER_IN_GOVERNANCE_VOTING_SIGNATURE = 220,
	AUX_DATA_HASH_BUILDER_IN_AUXILIARY_SCRIPTS = 300,
	AUX_DATA_HASH_BUILDER_FINISHED = 400,
} aux_data_hash_builder_state_t;

typedef enum {
	CIP15 = 1,
	CIP36 = 2
} governance_voting_registration_format_t;

typedef struct {
	struct {
		blake2b_256_context_t payloadHash;
		governance_voting_registration_format_t format;
		uint16_t remainingDelegations;
	} governanceVotingRegistrationData;

	aux_data_hash_builder_state_t state;
	blake2b_256_context_t auxDataHash;
} aux_data_hash_builder_t;


void auxDataHashBuilder_init(
        aux_data_hash_builder_t* builder
);

void auxDataHashBuilder_governanceVotingRegistration_enter(
        aux_data_hash_builder_t* builder,
        governance_voting_registration_format_t format
);
void auxDataHashBuilder_governanceVotingRegistration_enterPayload(aux_data_hash_builder_t* builder);
void auxDataHashBuilder_governanceVotingRegistration_addVotingKey(
        aux_data_hash_builder_t* builder,
        const uint8_t* votingPubKeyBuffer, size_t votingPubKeySize
);
void auxDataHashBuilder_governanceVotingRegistration_enterDelegations(
        aux_data_hash_builder_t* builder,
        size_t numDelegations
);
void auxDataHashBuilder_governanceVotingRegistration_addDelegation(
        aux_data_hash_builder_t* builder,
        const uint8_t* votingPubKeyBuffer, size_t votingPubKeySize,
        uint32_t weight
);
void auxDataHashBuilder_governanceVotingRegistration_addStakingKey(
        aux_data_hash_builder_t* builder,
        const uint8_t* stakingPubKeyBuffer, size_t stakingPubKeySize
);
void auxDataHashBuilder_governanceVotingRegistration_addVotingRewardsAddress(
        aux_data_hash_builder_t* builder,
        const uint8_t* addressBuffer, size_t addressSize
);
void auxDataHashBuilder_governanceVotingRegistration_addNonce(aux_data_hash_builder_t* builder, uint64_t nonce);
void auxDataHashBuilder_governanceVotingRegistration_addVotingPurpose(
        aux_data_hash_builder_t* builder,
        uint64_t votingPurpose
);
void auxDataHashBuilder_governanceVotingRegistration_finalizePayload(
        aux_data_hash_builder_t* builder,
        uint8_t* outBuffer, size_t outSize
);

void auxDataHashBuilder_governanceVotingRegistration_addSignature(
        aux_data_hash_builder_t* builder,
        const uint8_t* signatureBuffer, size_t signatureSize
);

void auxDataHashBuilder_governanceVotingRegistration_addAuxiliaryScripts(aux_data_hash_builder_t* builder);

void auxDataHashBuilder_finalize(
        aux_data_hash_builder_t* builder,
        uint8_t* outBuffer, size_t outSize
);

#ifdef DEVEL
void run_auxDataHashBuilder_test();
#endif // DEVEL

#endif // H_CARDANO_APP_AUX_DATA_HASH_BUILDER
