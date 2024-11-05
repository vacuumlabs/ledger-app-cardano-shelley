#ifndef H_CARDANO_APP_DERIVE_NATIVE_SCRIPT_HASH
#define H_CARDANO_APP_DERIVE_NATIVE_SCRIPT_HASH

#ifdef APP_FEATURE_NATIVE_SCRIPT_HASH

#include "bip44.h"
#include "cardano.h"
#include "common.h"
#include "handlers.h"
#include "nativeScriptHashBuilder.h"

handler_fn_t deriveNativeScriptHash_handleAPDU;

// a special type for distinguishing what to show in the UI, makes it easier
// to handle PUBKEY DEVICE_OWNED vs THIRD_PARTY
typedef enum {
    UI_SCRIPT_PUBKEY_PATH = 0,  // aka DEVICE_OWNED
    UI_SCRIPT_PUBKEY_HASH,      // aka THIRD_PARTY
    UI_SCRIPT_ALL,
    UI_SCRIPT_ANY,
    UI_SCRIPT_N_OF_K,
    UI_SCRIPT_INVALID_BEFORE,
    UI_SCRIPT_INVALID_HEREAFTER,
} ui_native_script_type;

typedef struct {
    uint32_t totalScripts;
    uint32_t remainingScripts;
} complex_native_script_t;

typedef union {
    uint32_t requiredScripts;
    bip44_path_t pubkeyPath;
    uint8_t pubkeyHash[ADDRESS_KEY_HASH_LENGTH];
    uint64_t timelock;
} native_script_content_t;

typedef struct {
    uint8_t level;
    // stores information about a complex script at the index level
    complex_native_script_t complexScripts[MAX_SCRIPT_DEPTH];

    uint8_t scriptHashBuffer[SCRIPT_HASH_LENGTH];
    native_script_hash_builder_t hashBuilder;

    native_script_content_t scriptContent;

    // UI information
    int ui_step;
    ui_native_script_type ui_scriptType;
} ins_derive_native_script_hash_context_t;

#endif  // APP_FEATURE_NATIVE_SCRIPT_HASH

#endif  // H_CARDANO_APP_DERIVE_NATIVE_SCRIPT_HASH
