#ifndef H_CARDANO_APP_MESSAGE_SIGNING
#define H_CARDANO_APP_MESSAGE_SIGNING

#include "bip44.h"

void getTxWitness(bip44_path_t* pathSpec,
                  const uint8_t* txHashBuffer, size_t txHashSize,
                  uint8_t* outBuffer, size_t outSize);

#ifdef POOL_OPERATOR_APP
void getOpCertSignature(bip44_path_t* pathSpec,
                        const uint8_t* opCertBodyBuffer, size_t opCertBodySize,
                        uint8_t* outBuffer, size_t outSize);
#endif // POOL_OPERATOR_APP

#endif // H_CARDANO_APP_MESSAGE_SIGNING
