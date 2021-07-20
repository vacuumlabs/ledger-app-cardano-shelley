#ifndef H_CARDANO_APP_DERIVE_NATIVE_SCRIPT_HASH
#define H_CARDANO_APP_DERIVE_NATIVE_SCRIPT_HASH

#include "bip44.h"
#include "cardano.h"
#include "common.h"
#include "handlers.h"

handler_fn_t deriveNativeScriptHash_handleAPDU;

// depth of n means it can handle up to n-1 nesting of native scripts
static const size_t MAX_SCRIPT_DEPTH = 11;

typedef struct {
	bip44_path_t path;
} native_script_pubkey_device_owned_t;

typedef struct {
	uint8_t hash[ADDRESS_KEY_HASH_LENGTH];
} native_script_pubkey_third_party_t;

typedef struct {
	uint32_t n;
} native_script_n_of_k_t;

typedef struct {
	uint64_t timelock;
} native_script_invalid_before_t;

typedef struct {
	uint64_t timelock;
} native_script_invalid_hereafter_t;

typedef union {
	native_script_pubkey_device_owned_t pubkeyDeviceOwned;
	native_script_pubkey_third_party_t pubkeyThirdParty;
	native_script_n_of_k_t nOfK;
	native_script_invalid_before_t invalidBefore;
	native_script_invalid_hereafter_t invalidHereafter;
} native_script_t;

typedef enum {
	NATIVE_COMPLEX_SCRIPT_ALL,
	NATIVE_COMPLEX_SCRIPT_ANY,
	NATIVE_COMPLEX_SCRIPT_N_OF_K,
} native_complex_script_type;

typedef struct {
	uint8_t level;
	uint32_t remainingScripts[MAX_SCRIPT_DEPTH];
	native_complex_script_type type[MAX_SCRIPT_DEPTH];
	native_script_t nativeScript;
} ins_derive_native_script_hash_context_t;

#endif // H_CARDANO_APP_DERIVE_NATIVE_SCRIPT_HASH
