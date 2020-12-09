#ifndef H_CARDANO_APP_STATE
#define H_CARDANO_APP_STATE

#include "getVersion.h"
#include "getPublicKeys.h"
#include "deriveAddress.h"
#include "getPoolColdPublicKey.h"
#include "signTx.h"


typedef union {
	// Here should go states of all instructions
	ins_get_keys_context_t getKeysContext;
	ins_get_pool_cold_pubkey_context_t getPoolColdPublicKeyContext;
	ins_derive_address_context_t deriveAddressContext;
	ins_sign_tx_context_t signTxContext;
} instructionState_t;

// Note(instructions are uint8_t but we have a special INS_NONE value
extern int currentInstruction;

extern instructionState_t instructionState;

#endif
