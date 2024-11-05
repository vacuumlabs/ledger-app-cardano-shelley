#ifdef DEVEL

#include "keyDerivation.h"
#include "hexUtils.h"
#include "testUtils.h"

static void pathSpec_init(bip44_path_t* pathSpec, const uint32_t* pathArray, uint32_t pathLength) {
    pathSpec->length = pathLength;
    memmove(pathSpec->path, pathArray, pathLength * 4);
}

void testcase_derivePublicKey(uint32_t* path, uint32_t pathLen, const char* expected) {
    PRINTF("testcase_derivePublicKey ");

    bip44_path_t pathSpec;
    pathSpec_init(&pathSpec, path, pathLen);

    BIP44_PRINTF(&pathSpec);
    PRINTF("\n");

    extendedPublicKey_t extPubKey;
    deriveExtendedPublicKey(&pathSpec, &extPubKey);

    uint8_t expectedBuffer[32] = {0};
    decode_hex(expected, expectedBuffer, SIZEOF(expectedBuffer));
    EXPECT_EQ_BYTES(expectedBuffer, extPubKey.pubKey, SIZEOF(expectedBuffer));
}

#define HD HARDENED_BIP32

void testPublicKeyDerivation() {
#define TESTCASE(path_, expectedHex_)                                  \
    {                                                                  \
        uint32_t path[] = {UNWRAP path_};                              \
        testcase_derivePublicKey(path, ARRAY_LEN(path), expectedHex_); \
    }

    // byron

    TESTCASE((HD + 44, HD + 1815, HD + 1),
             "eb6e933ce45516ac7b0e023de700efae5e212ccc6bf0fcb33ba9243b9d832827")

    TESTCASE((HD + 44, HD + 1815, HD + 1, HD + 1, 189),
             "383d4ee1ca5a6d0a88fcbc345dc0c1b1bdb6d63d6f0fc57a65c395aa9b9712c1");

    // shelley

    TESTCASE((HD + 1852, HD + 1815, HD + 1),
             "c9d624c493e269271980bc5e89bcd913719137f3b20c11339f28875951124c82");

    TESTCASE((HD + 1852, HD + 1815, HD + 1, HD + 1, 189),
             "20bce7877e7ba4536f8fe555198e4cb3340e655af44f68c4b9dd087e932ab864");

    // pool cold key

    TESTCASE((HD + 1853, HD + 1815, HD + 0, HD + 2),
             "0f38ab7679e756ca11924f12e745d154ffbac01bc0f7bf05ba7f658c3a28b0cb");

#undef TESTCASE
}

void run_key_derivation_test() {
    PRINTF("Running key derivation tests\n");
    PRINTF("If they fail, make sure you seeded your device with\n");
    PRINTF("12-word mnemonic: 11*abandon about\n");
    testPublicKeyDerivation();
}

#endif  // DEVEL
