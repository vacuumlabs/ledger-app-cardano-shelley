#ifndef H_CARDANO_APP_SIGN_CVOTE
#define H_CARDANO_APP_SIGN_CVOTE

#include "cardano.h"
#include "common.h"
#include "handlers.h"
#include "bip44.h"
#include "votecastHashBuilder.h"

#define MAX_VOTECAST_CHUNK_SIZE 240
#define VOTE_PLAN_ID_SIZE       32

typedef enum {
    VOTECAST_STAGE_NONE = 0,
    VOTECAST_STAGE_INIT = 20,
    VOTECAST_STAGE_CHUNK = 40,
    VOTECAST_STAGE_CONFIRM = 60,
    VOTECAST_STAGE_WITNESS = 80,
} sign_cvote_stage_t;

typedef struct {
    sign_cvote_stage_t stage;
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
} ins_sign_cvote_context_t;

uint16_t signCVote_handleAPDU(uint8_t p1,
                              uint8_t p2,
                              const uint8_t* wireDataBuffer,
                              size_t wireDataSize,
                              bool isNewCall);

void vote_advanceStage();
#endif  // H_CARDANO_APP_SIGN_CVOTE
