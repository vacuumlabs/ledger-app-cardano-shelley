#ifndef H_CARDANO_APP_NATIVE_SCRIPT_HASH_BUILDER
#define H_CARDANO_APP_NATIVE_SCRIPT_HASH_BUILDER

#ifdef APP_FEATURE_NATIVE_SCRIPT_HASH

#include "cardano.h"
#include "hash.h"

typedef enum {
    NATIVE_SCRIPT_HASH_BUILDER_SCRIPT = 100,
    NATIVE_SCRIPT_HASH_BUILDER_FINISHED = 200,
} native_script_hash_builder_state_t;

typedef struct {
    uint8_t level;
    uint32_t remainingScripts[MAX_SCRIPT_DEPTH];
    native_script_hash_builder_state_t state;
    blake2b_224_context_t nativeScriptHash;
} native_script_hash_builder_t;

void nativeScriptHashBuilder_init(native_script_hash_builder_t* builder);

void nativeScriptHashBuilder_startComplexScript_all(native_script_hash_builder_t* builder,
                                                    uint32_t remainingScripts);

void nativeScriptHashBuilder_startComplexScript_any(native_script_hash_builder_t* builder,
                                                    uint32_t remainingScripts);

void nativeScriptHashBuilder_startComplexScript_n_of_k(native_script_hash_builder_t* builder,
                                                       uint32_t remainingScripts,
                                                       uint32_t requiredScripts);

void nativeScriptHashBuilder_addScript_pubkey(native_script_hash_builder_t* builder,
                                              const uint8_t* pubKeyHashBuffer,
                                              size_t pubKeyHashSize);

void nativeScriptHashBuilder_addScript_invalidBefore(native_script_hash_builder_t* builder,
                                                     uint64_t timelock);

void nativeScriptHashBuilder_addScript_invalidHereafter(native_script_hash_builder_t* builder,
                                                        uint64_t timelock);

void nativeScriptHashBuilder_finalize(native_script_hash_builder_t* builder,
                                      uint8_t* outBuffer,
                                      size_t outSize);

#endif  // APP_FEATURE_NATIVE_SCRIPT_HASH

#endif  // H_CARDANO_APP_NATIVE_SCRIPT_HASH_BUILDER
