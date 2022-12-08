#ifndef H_CARDANO_APP_MESSAGE_SIGNING
#define H_CARDANO_APP_MESSAGE_SIGNING

#include "bip44.h"

void getWitness(bip44_path_t* pathSpec,
                const uint8_t* txHashBuffer, size_t txHashSize,
                uint8_t* outBuffer, size_t outSize);

void getGovernanceVotingRegistrationSignature(bip44_path_t* pathSpec,
        const uint8_t* payloadHashBuffer, size_t payloadHashSize,
        uint8_t* outBuffer, size_t outSize);

void getOpCertSignature(bip44_path_t* pathSpec,
                        const uint8_t* opCertBodyBuffer, size_t opCertBodySize,
                        uint8_t* outBuffer, size_t outSize);

#endif // H_CARDANO_APP_MESSAGE_SIGNING
