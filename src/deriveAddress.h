#ifndef H_CARDANO_APP_DERIVE_ADDRESS
#define H_CARDANO_APP_DERIVE_ADDRESS

#include <os.h>
#include "keyDerivation.h"

void handleDeriveAddress(
        uint8_t p1,
        uint8_t p2,
        uint8_t *dataBuffer,
        size_t dataLength
);

typedef struct {
	uint16_t responseReadyMagic;
	bip44_path_t pathSpec;
	uint8_t addressBuffer[128];
	size_t addressSize;
} ins_derive_address_context_t;

#endif
