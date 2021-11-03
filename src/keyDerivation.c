#include <os_io_seproxyhal.h>
#include <stdint.h>

#include "assert.h"
#include "errors.h"
#include "keyDerivation.h"
#include "cbor.h"
#include "hash.h"
#include "base58.h"
#include "utils.h"
#include "endian.h"
#include "cardano.h"
#include "securityPolicy.h"

void derivePrivateKey(
        const bip44_path_t* pathSpec,
        chain_code_t* chainCode,
        privateKey_t* privateKey
)
{
	// Sanity check
	ASSERT(pathSpec->length <= ARRAY_LEN(pathSpec->path));

	// if the path is invalid, it's a bug in previous validation
	ASSERT(policyForDerivePrivateKey(pathSpec) != POLICY_DENY);

	uint8_t privateKeyRawBuffer[64];

	STATIC_ASSERT(SIZEOF(chainCode->code) == 32, "bad chain code length");
	explicit_bzero(chainCode->code, SIZEOF(chainCode->code));

	BEGIN_TRY {
		TRY {
			STATIC_ASSERT(CX_APILEVEL >= 5, "unsupported api level");
			STATIC_ASSERT(SIZEOF(privateKey->d) == 64, "bad private key length");
			#ifndef FUZZING
			io_seproxyhal_io_heartbeat();
			os_perso_derive_node_bip32(
			        CX_CURVE_Ed25519,
			        pathSpec->path,
			        pathSpec->length,
			        privateKeyRawBuffer,
			        chainCode->code);
			io_seproxyhal_io_heartbeat();
			#endif
			// We should do cx_ecfp_init_private_key here, but it does not work in SDK < 1.5.4,
			// should work with the new SDK
			privateKey->curve = CX_CURVE_Ed25519;
			privateKey->d_len = 64;
			memmove(privateKey->d, privateKeyRawBuffer, 64);
		}
		FINALLY {
			explicit_bzero(privateKeyRawBuffer, SIZEOF(privateKeyRawBuffer));
		}
	} END_TRY;
}


void deriveRawPublicKey(
        const privateKey_t* privateKey,
        cx_ecfp_public_key_t* publicKey
)
{
	#ifndef FUZZING
	// We should do cx_ecfp_generate_pair here, but it does not work in SDK < 1.5.4,
	// should work with the new SDK
	io_seproxyhal_io_heartbeat();
	cx_eddsa_get_public_key(
	        // cx_eddsa has a special case struct for Cardano's private keys
	        // but signature is standard
	        (const struct cx_ecfp_256_private_key_s *) privateKey,
	        CX_SHA512,
	        publicKey,
	        NULL, 0, NULL, 0);
	io_seproxyhal_io_heartbeat();
	#endif
}

void extractRawPublicKey(
        const cx_ecfp_public_key_t* publicKey,
        uint8_t* outBuffer, size_t outSize
)
{
	// copy public key little endian to big endian
	ASSERT(outSize == 32);
	STATIC_ASSERT(SIZEOF(publicKey->W) == 65, "bad public key length");

	uint8_t i;
	for (i = 0; i < 32; i++) {
		outBuffer[i] = publicKey->W[64 - i];
	}

	if ((publicKey->W[32] & 1) != 0) {
		outBuffer[31] |= 0x80;
	}
}


// pub_key + chain_code
void deriveExtendedPublicKey(
        const bip44_path_t* pathSpec,
        extendedPublicKey_t* out
)
{
	privateKey_t privateKey;
	chain_code_t chainCode;

	STATIC_ASSERT(SIZEOF(*out) == CHAIN_CODE_SIZE + PUBLIC_KEY_SIZE, "bad ext pub key size");

	BEGIN_TRY {
		TRY {
			derivePrivateKey(
			        pathSpec,
			        &chainCode,
			        &privateKey
			);

			// Pubkey part
			cx_ecfp_public_key_t publicKey;

			deriveRawPublicKey(&privateKey, &publicKey);

			STATIC_ASSERT(SIZEOF(out->pubKey) == PUBLIC_KEY_SIZE, "bad pub key size");

			extractRawPublicKey(&publicKey, out->pubKey, SIZEOF(out->pubKey));

			// Chain code (we copy it second to avoid mid-updates extractRawPublicKey throws
			STATIC_ASSERT(CHAIN_CODE_SIZE == SIZEOF(out->chainCode), "bad chain code size");
			STATIC_ASSERT(CHAIN_CODE_SIZE == SIZEOF(chainCode.code), "bad chain code size");
			memmove(out->chainCode, chainCode.code, CHAIN_CODE_SIZE);
		}
		FINALLY {
			explicit_bzero(&privateKey, SIZEOF(privateKey));
		}
	} END_TRY;
}
