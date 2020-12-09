#ifdef POOL_OPERATOR_APP

#ifndef H_CARDANO_APP_GET_COLD_PUBLIC_KEY
#define H_CARDANO_APP_GET_COLD_PUBLIC_KEY

#include "common.h"
#include "handlers.h"
#include "bip44.h"
#include "keyDerivation.h"

handler_fn_t getPoolColdPublicKey_handleAPDU;

typedef struct {
	int16_t responseReadyMagic;
	bip44_path_t pathSpec;
	extendedPublicKey_t extPoolColdPubKey;
	int ui_step;
} ins_get_pool_cold_pubkey_context_t;

#endif // H_CARDANO_APP_GET_COLD_PUBLIC_KEY

#endif // POOL_OPERATOR_APP
