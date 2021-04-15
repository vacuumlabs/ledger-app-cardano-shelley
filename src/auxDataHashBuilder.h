#ifndef H_CARDANO_APP_AUX_DATA_HASH_BUILDER
#define H_CARDANO_APP_AUX_DATA_HASH_BUILDER

#include "cardano.h"
#include "hash.h"
#include "keyDerivation.h"

enum {
	METADATA_KEY_CATALYST_REGISTRATION_PAYLOAD = 61284,
	METADATA_KEY_CATALYST_SIGNATURE = 61285,
};

enum {
	CATALYST_REGISTRATION_PAYLOAD_KEY_VOTING_KEY = 1,
	CATALYST_REGISTRATION_PAYLOAD_KEY_STAKING_KEY = 2,
	CATALYST_REGISTRATION_PAYLOAD_KEY_VOTING_REWARDS_ADDRESS = 3,
	CATALYST_REGISTRATION_PAYLOAD_KEY_NONCE = 4,
};

enum {
	CATALYST_SIGNATURE_KEY = 1,
};

typedef enum {
	AUX_DATA_HASH_BUILDER_INIT = 100,
	AUX_DATA_HASH_BUILDER_IN_CATALYST_REGISTRATION_INIT = 200,
	AUX_DATA_HASH_BUILDER_IN_CATALYST_PAYLOAD_INIT = 210,
	AUX_DATA_HASH_BUILDER_IN_CATALYST_PAYLOAD_VOTING_KEY = 211,
	AUX_DATA_HASH_BUILDER_IN_CATALYST_PAYLOAD_STAKING_KEY = 212,
	AUX_DATA_HASH_BUILDER_IN_CATALYST_PAYLOAD_VOTING_REWARDS_ADDRESS = 213,
	AUX_DATA_HASH_BUILDER_IN_CATALYST_PAYLOAD_NONCE = 214,
	AUX_DATA_HASH_BUILDER_IN_CATALYST_SIGNATURE = 220,
	AUX_DATA_HASH_BUILDER_IN_AUXILIARY_SCRIPTS = 300,
	AUX_DATA_HASH_BUILDER_FINISHED = 400,
} aux_data_hash_builder_state_t;

typedef struct {
	struct {
		blake2b_256_context_t payloadHash;
	} catalystRegistrationData;

	aux_data_hash_builder_state_t state;
	blake2b_256_context_t auxDataHash;
} aux_data_hash_builder_t;


void auxDataHashBuilder_init(
        aux_data_hash_builder_t* builder
);

void auxDataHashBuilder_catalystRegistration_enter(aux_data_hash_builder_t* builder);
void auxDataHashBuilder_catalystRegistration_enterPayload(aux_data_hash_builder_t* builder);
void auxDataHashBuilder_catalystRegistration_addVotingKey(
        aux_data_hash_builder_t* builder,
        const uint8_t* votingPubKeyBuffer, size_t votingPubKeySize
);
void auxDataHashBuilder_catalystRegistration_addStakingKey(
        aux_data_hash_builder_t* builder,
        const uint8_t* stakingPubKeyBuffer, size_t stakingPubKeySize
);
void auxDataHashBuilder_catalystRegistration_addVotingRewardsAddress(
        aux_data_hash_builder_t* builder,
        const uint8_t* addressBuffer, size_t addressSize
);
void auxDataHashBuilder_catalystRegistration_addNonce(aux_data_hash_builder_t* builder, uint64_t nonce);
void auxDataHashBuilder_catalystRegistration_finalizePayload(
        aux_data_hash_builder_t* builder,
        uint8_t* outBuffer, size_t outSize
);

void auxDataHashBuilder_catalystRegistration_addSignature(
        aux_data_hash_builder_t* builder,
        const uint8_t* signatureBuffer, size_t signatureSize
);

void auxDataHashBuilder_catalystRegistration_addAuxiliaryScripts(aux_data_hash_builder_t* builder);

void auxDataHashBuilder_finalize(
        aux_data_hash_builder_t* builder,
        uint8_t* outBuffer, size_t outSize
);

#ifdef DEVEL
void run_auxDataHashBuilder_test();
#endif // DEVEL

#endif // H_CARDANO_APP_AUX_DATA_HASH_BUILDER
