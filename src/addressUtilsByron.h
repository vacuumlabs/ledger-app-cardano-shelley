#ifndef H_CARDANO_APP_ADDRESS_UTILS_BYRON
#define H_CARDANO_APP_ADDRESS_UTILS_BYRON

#include "common.h"
#include "bip44.h"

size_t deriveAddress_byron(
        const bip44_path_t* pathSpec,
        uint32_t protocolMagic,
        uint8_t* outBuffer, size_t outSize
);

// Note: validates the overall address structure at the same time
uint32_t extractProtocolMagic(
        const uint8_t* addressBuffer, size_t addressSize
);


#ifdef DEVEL
void run_addressUtilsByron_test();
#endif // DEVEL

#endif // H_CARDANO_APP_ADDRESS_UTILS_BYRON
