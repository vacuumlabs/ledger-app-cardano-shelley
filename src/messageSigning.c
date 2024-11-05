#include "cx.h"

#include "messageSigning.h"
#include "cardano.h"
#include "bip44.h"
#include "securityPolicy.h"
#include "crypto.h"

void signRawMessageWithPath(bip44_path_t* pathSpec,
                            const uint8_t* messageBuffer,
                            size_t messageSize,
                            uint8_t* outBuffer,
                            size_t outSize) {
    size_t sigLen = outSize;

    ASSERT(messageSize < BUFFER_SIZE_PARANOIA);
    ASSERT(sigLen == ED25519_SIGNATURE_LENGTH);

    // Sanity check
    ASSERT(pathSpec->length <= ARRAY_LEN(pathSpec->path));

    // if the path is invalid, it's a bug in previous validation
    ASSERT(policyForDerivePrivateKey(pathSpec) != POLICY_DENY);

#ifndef FUZZING
    {
        TRACE("signing with path:");
        BIP44_PRINTF(pathSpec);
        PRINTF("\n");

        cx_err_t error = crypto_eddsa_sign(pathSpec->path,
                                           pathSpec->length,
                                           messageBuffer,
                                           messageSize,
                                           outBuffer,
                                           &sigLen);
        if (error != CX_OK) {
            PRINTF("error: %d", error);
            ASSERT(false);
        }
    }
#endif

    ASSERT(sigLen == ED25519_SIGNATURE_LENGTH);
}

// sign the given hash by the private key derived according to the given path
void getWitness(bip44_path_t* pathSpec,
                const uint8_t* hashBuffer,
                size_t hashSize,
                uint8_t* outBuffer,
                size_t outSize) {
    ASSERT(outSize < BUFFER_SIZE_PARANOIA);

#ifndef FUZZING
    signRawMessageWithPath(pathSpec, hashBuffer, hashSize, outBuffer, outSize);
#endif
}

void getCVoteRegistrationSignature(bip44_path_t* pathSpec,
                                   const uint8_t* payloadHashBuffer,
                                   size_t payloadHashSize,
                                   uint8_t* outBuffer,
                                   size_t outSize) {
    ASSERT(payloadHashSize == CVOTE_REGISTRATION_PAYLOAD_HASH_LENGTH);
    ASSERT(outSize < BUFFER_SIZE_PARANOIA);

#ifndef FUZZING
    signRawMessageWithPath(pathSpec, payloadHashBuffer, payloadHashSize, outBuffer, outSize);
#endif
}

#ifdef APP_FEATURE_OPCERT
void getOpCertSignature(bip44_path_t* pathSpec,
                        const uint8_t* opCertBodyBuffer,
                        size_t opCertBodySize,
                        uint8_t* outBuffer,
                        size_t outSize) {
    ASSERT(bip44_isPoolColdKeyPath(pathSpec));
    ASSERT(opCertBodySize == OP_CERT_BODY_LENGTH);
    ASSERT(outSize < BUFFER_SIZE_PARANOIA);

    signRawMessageWithPath(pathSpec, opCertBodyBuffer, opCertBodySize, outBuffer, outSize);
}
#endif  // APP_FEATURE_OPCERT
