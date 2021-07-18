#ifndef H_CARDANO_APP_DERIVE_NATIVE_SCRIPT_HASH
#define H_CARDANO_APP_DERIVE_NATIVE_SCRIPT_HASH

#include "cardano.h"
#include "common.h"
#include "handlers.h"

handler_fn_t deriveNativeScriptHash_handleAPDU;

typedef struct {
	uint32_t remainingScripts;
} complex_native_script_t;

typedef struct {
	uint8_t level;
	// stores information about a complex script at the index level
	complex_native_script_t complexScripts[MAX_SCRIPT_DEPTH];
} ins_derive_native_script_hash_context_t;

#endif // H_CARDANO_APP_DERIVE_NATIVE_SCRIPT_HASH
