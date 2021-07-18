#ifndef H_CARDANO_APP_DERIVE_NATIVE_SCRIPT_HASH
#define H_CARDANO_APP_DERIVE_NATIVE_SCRIPT_HASH

#include "common.h"
#include "handlers.h"

handler_fn_t deriveNativeScriptHash_handleAPDU;

// depth of n means it can handle up to n-1 nesting of native scripts
static const size_t MAX_SCRIPT_DEPTH = 11;

typedef struct {
	uint8_t level;
	uint32_t remainingScripts[MAX_SCRIPT_DEPTH];
} ins_derive_native_script_hash_context_t;

#endif // H_CARDANO_APP_DERIVE_NATIVE_SCRIPT_HASH
