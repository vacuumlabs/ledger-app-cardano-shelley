#ifndef H_CARDANO_APP_DERIVE_ADDRESS
#define H_CARDANO_APP_DERIVE_ADDRESS

#include "common.h"
#include "bip44.h"
#include "handlers.h"
#include "addressUtilsShelley.h"

handler_fn_t deriveAddress_handleAPDU;

typedef struct {
	uint16_t responseReadyMagic;
	bip44_path_t pathSpec;
	uint8_t addressHeader;
	union {
		struct {
			bool useAccountStakingKey;
			uint8_t hash[PUBLIC_KEY_HASH_LENGTH];
		} stakingKeyHash;
		certificatePointer_t stakingKeyPointer;
	};
	struct {
		uint8_t buffer[128]; // TODO is this enough?
		size_t size;
	} address;
	int ui_step;
} ins_derive_address_context_t;

#endif
