#ifndef H_CARDANO_APP_VOTECAST_HASH_BUILDER
#define H_CARDANO_APP_VOTECAST_HASH_BUILDER

#include "hash.h"

#define VOTECAST_HASH_LENGTH 32

typedef enum {
    VOTECAST_HASH_BUILDER_INIT = 100,
    VOTECAST_HASH_BUILDER_CHUNK = 200,
    VOTECAST_HASH_BUILDER_FINISHED = 1800,
} votecast_hash_builder_state_t;

typedef struct {
    votecast_hash_builder_state_t state;

    size_t remainingBytes;

    blake2b_256_context_t hash;
} votecast_hash_builder_t;

void votecastHashBuilder_init(votecast_hash_builder_t* builder, size_t remainingBytes);

void votecastHashBuilder_chunk(votecast_hash_builder_t* builder,
                               const uint8_t* chunk,
                               size_t chunkSize);

void votecastHashBuilder_finalize(votecast_hash_builder_t* builder,
                                  uint8_t* outBuffer,
                                  size_t outSize);

#endif  // H_CARDANO_APP_VOTECAST_HASH_BUILDER
