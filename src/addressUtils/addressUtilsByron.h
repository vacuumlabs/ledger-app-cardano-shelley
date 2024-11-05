#ifndef H_CARDANO_APP_ADDRESS_UTILS_BYRON
#define H_CARDANO_APP_ADDRESS_UTILS_BYRON

#include "common.h"
#include "bip44.h"

#ifdef APP_FEATURE_BYRON_ADDRESS_DERIVATION

size_t deriveAddress_byron(const bip44_path_t* pathSpec,
                           uint32_t protocolMagic,
                           uint8_t* outBuffer,
                           size_t outSize);

#endif  // APP_FEATURE_BYRON_ADDRESS_DERIVATION

#ifdef APP_FEATURE_BYRON_PROTOCOL_MAGIC_CHECK

// Note: validates the overall address structure at the same time
uint32_t extractProtocolMagic(const uint8_t* addressBuffer, size_t addressSize);

#endif  // APP_FEATURE_BYRON_PROTOCOL_MAGIC_CHECK

#endif  // H_CARDANO_APP_ADDRESS_UTILS_BYRON
