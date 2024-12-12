#ifdef DEVEL

#include "cardano.h"
#include "bip44.h"
#include "testUtils.h"

#define HD HARDENED_BIP32

static void pathSpec_init(bip44_path_t* pathSpec, const uint32_t* pathArray, uint32_t pathLength) {
    pathSpec->length = pathLength;
    memmove(pathSpec->path, pathArray, pathLength * 4);
}

void testcase_printToStr(const uint32_t* path,
                         uint32_t pathLen,
                         size_t outputSize,
                         const char* expected) {
    PRINTF("testcase_bip44_printToStr %s\n", expected);

    bip44_path_t pathSpec;
    pathSpec_init(&pathSpec, path, pathLen);

    char result[BIP44_PATH_STRING_SIZE_MAX + 1] = {0};
    ASSERT(outputSize <= SIZEOF(result));

    size_t resultLen = bip44_printToStr(&pathSpec, result, outputSize);

    size_t expectedSize = strlen(expected) + 1;
    EXPECT_EQ(resultLen + 1, expectedSize);
    EXPECT_EQ_BYTES(result, expected, expectedSize);
}

void run_bip44_test() {
#define TESTCASE(path_, outputSize_, expected_)                             \
    {                                                                       \
        uint32_t path[] = {UNWRAP path_};                                   \
        testcase_printToStr(path, ARRAY_LEN(path), outputSize_, expected_); \
    }

    TESTCASE((1, 2, 3, 4, 5), BIP44_PATH_STRING_SIZE_MAX + 1, "m/1/2/3/4/5");
    TESTCASE((1, 2, 3, 4, 5), BIP44_PATH_STRING_SIZE_MAX + 1, "m/1/2/3/4/5");
    TESTCASE((), BIP44_PATH_STRING_SIZE_MAX + 1, "m");
    TESTCASE((HD + 44, HD + 1815, HD + 0, 1, 55),
             BIP44_PATH_STRING_SIZE_MAX + 1,
             "m/44'/1815'/0'/1/55");
    TESTCASE((HD + 44, HD + 1815), BIP44_PATH_STRING_SIZE_MAX + 1, "m/44'/1815'");
#undef TESTCASE
}

#endif  // DEVEL
