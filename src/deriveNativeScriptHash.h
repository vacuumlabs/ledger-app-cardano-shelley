#ifndef H_CARDANO_APP_DERIVE_NATIVE_SCRIPT_HASH
#define H_CARDANO_APP_DERIVE_NATIVE_SCRIPT_HASH

#include "bip44.h"
#include "cardano.h"
#include "common.h"
#include "handlers.h"
#include "nativeScriptHashBuilder.h"

handler_fn_t deriveNativeScriptHash_handleAPDU;

typedef struct {
	uint32_t remainingScripts;
} complex_native_script_t;

typedef struct {
	uint8_t level;
	// stores information about a complex script at the index level
	complex_native_script_t complexScripts[MAX_SCRIPT_DEPTH];

	uint8_t scriptHashBuffer[SCRIPT_HASH_LENGTH];
	native_script_hash_builder_t hashBuilder;
} ins_derive_native_script_hash_context_t;

#endif // H_CARDANO_APP_DERIVE_NATIVE_SCRIPT_HASH
