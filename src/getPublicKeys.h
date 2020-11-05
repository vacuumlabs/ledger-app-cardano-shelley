#ifndef H_CARDANO_APP_GET_PUB_KEYS
#define H_CARDANO_APP_GET_PUB_KEYS

#include "common.h"
#include "handlers.h"
#include "bip44.h"
#include "keyDerivation.h"

#define MAX_PUBLIC_KEYS 1000

typedef enum {
	GET_KEYS_STAGE_NONE = 0,
	GET_KEYS_STAGE_INIT = 20,
	GET_KEYS_STAGE_GET_KEYS = 40
} get_keys_stage_t;

typedef struct {
	get_keys_stage_t stage;

	uint16_t remainingKeys;

	bip44_path_t pathSpec;
	extendedPublicKey_t extPubKey;

	uint16_t responseReadyMagic;

	int ui_step;
} ins_get_keys_context_t;

handler_fn_t getPublicKeys_handleAPDU;

#endif
