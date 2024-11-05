#if defined(DEVEL) && defined(APP_FEATURE_NATIVE_SCRIPT_HASH)

#include "hexUtils.h"
#include "nativeScriptHashBuilder.h"
#include "testUtils.h"

#define BUF_FROM_STR(name, size) \
    uint8_t name[size] = {0};    \
    decode_hex(name##Str, name, size);

#define BEFORE_EACH                       \
    native_script_hash_builder_t builder; \
    nativeScriptHashBuilder_init(&builder);

#define FINALIZE                                                                 \
    uint8_t result[SCRIPT_HASH_LENGTH] = {0};                                    \
    nativeScriptHashBuilder_finalize(&builder, result, ADDRESS_KEY_HASH_LENGTH); \
    PRINTF("Native script hash hex\n");                                          \
    PRINTF("%.*h\n", 32, result);

#define EQUALS(name)                        \
    BUF_FROM_STR(name, SCRIPT_HASH_LENGTH); \
    EXPECT_EQ_BYTES(result, name, SCRIPT_HASH_LENGTH);

static const char* pubkeyHashStr = "3a55d9f68255dfbefa1efd711f82d005fae1be2e145d616c90cf0fa9";
static const char* expectedPubkeyScriptHashStr =
    "855228f5ecececf9c85618007cc3c2e5bdf5e6d41ef8d6fa793fe0eb";

static const uint64_t invalidBefore = 42;
static const char* expectedInvalidBeforeScriptHashStr =
    "2a25e608a683057e32ea38b50ce8875d5b34496b393da8d25d314c4e";

static const uint64_t invalidHereafter = 42;
static const char* expectedInvalidHereafterScriptHashStr =
    "1620dc65993296335183f23ff2f7747268168fabbeecbf24c8a20194";

static const char* expectedEmptyAllScriptHashStr =
    "d441227553a0f1a965fee7d60a0f724b368dd1bddbc208730fccebcf";
static const char* expectedEmptyAnyScriptHashStr =
    "52dc3d43b6d2465e96109ce75ab61abe5e9c1d8a3c9ce6ff8a3af528";
static const char* expectedEmptyNofKScriptHashStr =
    "3530cc9ae7f2895111a99b7a02184dd7c0cea7424f1632d73951b1d7";

static const char* expectedNestedComplexScriptsStr =
    "1f292766b9b0db263f8ecc087478f6aeea3c9fe091674153084e5668";

void run_nativeScriptHashBuilder_test() {
    PRINTF("nativeScriptHashBuilder test\n");
    {
        BEFORE_EACH;

        BUF_FROM_STR(pubkeyHash, ADDRESS_KEY_HASH_LENGTH);
        nativeScriptHashBuilder_addScript_pubkey(&builder, pubkeyHash, SIZEOF(pubkeyHash));

        FINALIZE;
        EQUALS(expectedPubkeyScriptHash);
    }
    {
        BEFORE_EACH;

        nativeScriptHashBuilder_addScript_invalidBefore(&builder, invalidBefore);

        FINALIZE;
        EQUALS(expectedInvalidBeforeScriptHash);
    }
    {
        BEFORE_EACH;

        nativeScriptHashBuilder_addScript_invalidHereafter(&builder, invalidHereafter);

        FINALIZE;
        EQUALS(expectedInvalidHereafterScriptHash);
    }
    {
        BEFORE_EACH;

        nativeScriptHashBuilder_startComplexScript_all(&builder, 0);

        FINALIZE;
        EQUALS(expectedEmptyAllScriptHash);
    }
    {
        BEFORE_EACH;

        nativeScriptHashBuilder_startComplexScript_any(&builder, 0);

        FINALIZE;
        EQUALS(expectedEmptyAnyScriptHash);
    }
    {
        BEFORE_EACH;

        nativeScriptHashBuilder_startComplexScript_n_of_k(&builder, 0, 0);

        FINALIZE;
        EQUALS(expectedEmptyNofKScriptHash);
    }
    {
        BEFORE_EACH;

        nativeScriptHashBuilder_startComplexScript_all(&builder, 1);
        nativeScriptHashBuilder_startComplexScript_any(&builder, 1);
        nativeScriptHashBuilder_startComplexScript_n_of_k(&builder, 0, 0);

        FINALIZE;
        EQUALS(expectedNestedComplexScripts);
    }
}

#undef EQUALS
#undef FINALIZE
#undef BEFORE_EACH
#undef BUF_FROM_STR

#endif  // DEVEL && APP_FEATURE_NATIVE_SCRIPT_HASH
