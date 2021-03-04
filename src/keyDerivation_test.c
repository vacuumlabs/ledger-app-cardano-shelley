#ifdef DEVEL

#include "keyDerivation.h"
#include "hexUtils.h"
#include "test_utils.h"

static void pathSpec_init(bip44_path_t* pathSpec, const uint32_t* pathArray, uint32_t pathLength)
{
	pathSpec->length = pathLength;
	os_memmove(pathSpec->path, pathArray, pathLength * 4);
}

void testcase_derivePrivateKey(uint32_t* path, uint32_t pathLen, const char* expectedHex)
{
	PRINTF("testcase_derivePrivateKey ");

	bip44_path_t pathSpec;
	ASSERT(pathLen <= BIP44_MAX_PATH_ELEMENTS);
	pathSpec_init(&pathSpec, path, pathLen);
	bip44_PRINTF(&pathSpec);
	PRINTF("\n");

	uint8_t expected[64];
	size_t expectedSize = decode_hex(expectedHex, expected, SIZEOF(expected));

	chain_code_t chainCode;
	privateKey_t privateKey;
	derivePrivateKey(&pathSpec, &chainCode, &privateKey);
	EXPECT_EQ_BYTES(expected, privateKey.d, expectedSize);
}

void testPrivateKeyDerivation()
{

#define HD HARDENED_BIP32

#define TESTCASE(path_, expectedHex_) \
	{ \
		uint32_t path[] = { UNWRAP path_ }; \
		testcase_derivePrivateKey(path, ARRAY_LEN(path), expectedHex_); \
	}


	// Note: Failing tests here? Did you load testing mnemonic
	// "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"?

	TESTCASE(
	        (HD + 44, HD + 1815, HD + 1),

	        "5878bdf06af259f1419324680c4d4ce05b4343895b697144d874749925e69d41"
	        "648e7e50061809207f81dac36b73cd8fab2325d49d26bc65ebbb696ea59c45b8"
	);

	TESTCASE(
	        (HD + 1852, HD + 1815, HD + 1, 0, HD + 55),

	        "08671b6f39031f2fc7bcebff7b85aec4c27787fc6a12f7f8bbfb28902ae69d41"
			"85751aae1484fb26c53f8e4c35b943d11449b52e5863779821fcc49cddf60792"
	);
#undef TESTCASE

#define TESTCASE(path_, error_) \
	{ \
		uint32_t path[] = { UNWRAP path_ }; \
		EXPECT_THROWS(testcase_derivePrivateKey(path, ARRAY_LEN(path), ""), error_ ); \
	}

	TESTCASE( (HD + 43, HD + 1815), ERR_INVALID_BIP44_PATH);
	TESTCASE( (HD + 44, 1815, HD + 1), ERR_INVALID_BIP44_PATH);
	TESTCASE( (HD + 44, HD + 33, HD + 1), ERR_INVALID_BIP44_PATH);
#undef TESTCASE
}

void testcase_derivePublicKey(uint32_t* path, uint32_t pathLen, const char* expected)
{
	PRINTF("testcase_derivePublicKey ");

	bip44_path_t pathSpec;
	pathSpec_init(&pathSpec, path, pathLen);

	bip44_PRINTF(&pathSpec);
	PRINTF("\n");

	chain_code_t chainCode;
	privateKey_t privateKey;
	derivePrivateKey(&pathSpec, &chainCode, &privateKey);
	cx_ecfp_public_key_t publicKey;
	deriveRawPublicKey(&privateKey, &publicKey);
	uint8_t publicKeyRaw[32];
	extractRawPublicKey(&publicKey, publicKeyRaw, SIZEOF(publicKeyRaw));

	uint8_t expectedBuffer[32];
	decode_hex(expected, expectedBuffer, SIZEOF(expectedBuffer));
	EXPECT_EQ_BYTES(expectedBuffer, publicKeyRaw, SIZEOF(expectedBuffer));
}

void testPublicKeyDerivation()
{
#define TESTCASE(path_, expectedHex_) \
	{ \
		uint32_t path[] = { UNWRAP path_ }; \
		testcase_derivePublicKey(path, ARRAY_LEN(path), expectedHex_); \
	}

	// byron

	TESTCASE(
	        (HD + 44, HD + 1815, HD + 1),
	        "eb6e933ce45516ac7b0e023de700efae5e212ccc6bf0fcb33ba9243b9d832827"
	)

	TESTCASE(
	        (HD + 44, HD + 1815, HD + 1, HD + 1, 189),
	        "383d4ee1ca5a6d0a88fcbc345dc0c1b1bdb6d63d6f0fc57a65c395aa9b9712c1"
	);

	// shelley

	TESTCASE(
	        (HD + 1852, HD + 1815, HD + 1),
	        "c9d624c493e269271980bc5e89bcd913719137f3b20c11339f28875951124c82"
	);

	TESTCASE(
	        (HD + 1852, HD + 1815, HD + 1, HD + 1, 189),
	        "20bce7877e7ba4536f8fe555198e4cb3340e655af44f68c4b9dd087e932ab864"
	);

	// pool cold key

	TESTCASE(
	        (HD + 1853, HD + 1815, HD + 0, HD + 2),
	        "0f38ab7679e756ca11924f12e745d154ffbac01bc0f7bf05ba7f658c3a28b0cb"
	);

#undef TESTCASE
}


void testcase_deriveChainCode(uint32_t* path, uint32_t pathLen, const char* expectedHex)
{
	PRINTF("testcase_deriveChainCode ");

	chain_code_t chainCode;
	privateKey_t privateKey;

	bip44_path_t pathSpec;
	pathSpec_init(&pathSpec, path, pathLen);

	bip44_PRINTF(&pathSpec);
	PRINTF("\n");

	derivePrivateKey(&pathSpec, &chainCode, &privateKey);

	uint8_t expectedBuffer[32];
	decode_hex(expectedHex, expectedBuffer, 32);
	EXPECT_EQ_BYTES(expectedBuffer, chainCode.code, 32);
}

// not tested
void testChainCodeDerivation()
{
#define TESTCASE(path_, expectedHex_) \
	{ \
		uint32_t path[] = { UNWRAP path_ }; \
		testcase_deriveChainCode(path, ARRAY_LEN(path), expectedHex_); \
	}

	TESTCASE(
	        (HD + 44, HD + 1815, HD + 1),
	        "0b161cb11babe1f56c3f9f1cbbb7b6d2d13eeb3efa67205198a69b8d81885354"
	);

	TESTCASE(
	        (HD + 1852, HD + 1815, HD + 1, HD + 1, HD + 44),
	        "a92fb06ab6a4321d4b55878ec062988f315d9fe701009946cd95617dde8ba2a1"
	);

#undef TESTCASE
}


void run_key_derivation_test()
{
	PRINTF("Running key derivation tests\n");
	PRINTF("If they fail, make sure you seeded your device with\n");
	PRINTF("12-word mnemonic: 11*abandon about\n");
	testPrivateKeyDerivation();
	testPublicKeyDerivation();
	testChainCodeDerivation();
}

#endif // DEVEL
