#include <cx.h>

#include "messageSigning.h"
#include "cardano.h"
#include "keyDerivation.h"
#include "bip44.h"

static void signRawMessage(privateKey_t* privateKey,
                           const uint8_t* messageBuffer, size_t messageSize,
                           uint8_t* outBuffer, size_t outSize)
{
	uint8_t signature[64] = {0};
	ASSERT(messageSize < BUFFER_SIZE_PARANOIA);
	ASSERT(outSize == SIZEOF(signature));

	#ifndef FUZZING
	// Note(ppershing): this could be done without
	// temporary copy
	STATIC_ASSERT(sizeof(int) == sizeof(size_t), "bad sizing");
	io_seproxyhal_io_heartbeat();
	size_t signatureSize =
	        (size_t) cx_eddsa_sign(
	                (const struct cx_ecfp_256_private_key_s*) privateKey,
	                0 /* mode */,
	                CX_SHA512,
	                messageBuffer, messageSize,
	                NULL /* ctx */, 0 /* ctx len */,
	                signature, SIZEOF(signature),
	                0 /* info */
	        );
	io_seproxyhal_io_heartbeat();

	ASSERT(signatureSize == ED25519_SIGNATURE_LENGTH);
	memmove(outBuffer, signature, signatureSize);
	#endif
}

static void signRawMessageWithPath(bip44_path_t* pathSpec,
                                   const uint8_t* messageBuffer, size_t messageSize,
                                   uint8_t* outBuffer, size_t outSize)
{
	ASSERT(messageSize < BUFFER_SIZE_PARANOIA);
	ASSERT(outSize < BUFFER_SIZE_PARANOIA);

	chain_code_t chainCode;
	privateKey_t privateKey;

	TRACE("derive private key");

	BEGIN_TRY {
		TRY {
			derivePrivateKey(pathSpec, &chainCode, &privateKey);

			signRawMessage(
			        &privateKey,
			        messageBuffer, messageSize,
			        outBuffer, outSize
			);
		}
		FINALLY {
			explicit_bzero(&privateKey, SIZEOF(privateKey));
			explicit_bzero(&chainCode, SIZEOF(chainCode));
		}
	} END_TRY;
}

// sign the given hash by the private key derived according to the given path
void getWitness(bip44_path_t* pathSpec,
                const uint8_t* hashBuffer, size_t hashSize,
                uint8_t* outBuffer, size_t outSize)
{
	ASSERT(outSize < BUFFER_SIZE_PARANOIA);

	#ifndef FUZZING
	signRawMessageWithPath(pathSpec, hashBuffer, hashSize, outBuffer, outSize);
	#endif
}

void getCVoteRegistrationSignature(bip44_path_t* pathSpec,
                                   const uint8_t* payloadHashBuffer, size_t payloadHashSize,
                                   uint8_t* outBuffer, size_t outSize)
{
	ASSERT(payloadHashSize == CVOTE_REGISTRATION_PAYLOAD_HASH_LENGTH);
	ASSERT(outSize < BUFFER_SIZE_PARANOIA);

	#ifndef FUZZING
	signRawMessageWithPath(pathSpec, payloadHashBuffer, payloadHashSize, outBuffer, outSize);
	#endif
}

void getOpCertSignature(bip44_path_t* pathSpec,
                        const uint8_t* opCertBodyBuffer, size_t opCertBodySize,
                        uint8_t* outBuffer, size_t outSize)
{
	ASSERT(bip44_isPoolColdKeyPath(pathSpec));
	ASSERT(opCertBodySize == OP_CERT_BODY_LENGTH);
	ASSERT(outSize < BUFFER_SIZE_PARANOIA);

	signRawMessageWithPath(pathSpec, opCertBodyBuffer, opCertBodySize, outBuffer, outSize);
}
