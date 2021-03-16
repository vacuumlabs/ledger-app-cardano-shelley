#ifndef H_CARDANO_APP_MESSAGE_SIGNING
#define H_CARDANO_APP_MESSAGE_SIGNING

#include "bip44.h"

void getTxWitness(bip44_path_t* pathSpec,
                  const uint8_t* txHashBuffer, size_t txHashSize,
                  uint8_t* outBuffer, size_t outSize);

void getCatalystVotingRegistrationSignature(bip44_path_t* pathSpec,
        const uint8_t* payloadHashBuffer, size_t payloadHashSize,
        uint8_t* outBuffer, size_t outSize);

#endif // H_CARDANO_APP_MESSAGE_SIGNING
