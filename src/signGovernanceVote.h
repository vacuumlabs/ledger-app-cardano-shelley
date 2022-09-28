#ifndef H_CARDANO_APP_SIGN_GOVERNANCE_VOTE
#define H_CARDANO_APP_SIGN_GOVERNANCE_VOTE

#include "cardano.h"
#include "common.h"
#include "handlers.h"
#include "bip44.h"
#include "votecastHashBuilder.h"

#define MAX_VOTECAST_CHUNK_SIZE 240
#define VOTE_PLAN_ID_SIZE 32

typedef enum {
	VOTECAST_STAGE_NONE = 0,
	VOTECAST_STAGE_INIT = 20,
	VOTECAST_STAGE_CHUNK = 40,
	VOTECAST_STAGE_CONFIRM = 60,
	VOTECAST_STAGE_WITNESS = 80,
} sign_governance_vote_stage_t;

typedef struct {
	sign_governance_vote_stage_t stage;
	int ui_step;
	size_t remainingVotecastBytes;

	votecast_hash_builder_t votecastHashBuilder;
	uint8_t votecastHash[VOTECAST_HASH_LENGTH];

	union {
		struct {
			uint8_t votePlanId[VOTE_PLAN_ID_SIZE];
			uint8_t proposalIndex;
			uint8_t payloadTypeTag;
		};
		uint8_t votecastChunk[MAX_VOTECAST_CHUNK_SIZE];
		struct {
			bip44_path_t path;
			uint8_t signature[ED25519_SIGNATURE_LENGTH];
		} witnessData;
	};
} ins_sign_governance_vote_context_t;

handler_fn_t signGovernanceVote_handleAPDU;

#endif // H_CARDANO_APP_SIGN_GOVERNANCE_VOTE
