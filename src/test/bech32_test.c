#ifdef DEVEL

#include "bech32.h"
#include "hexUtils.h"
#include "testUtils.h"

void testcase_bech32(const char* hrp, const char* inputBytesHex, const char* expectedStr) {
    PRINTF("testcase_bech32: %s %s\n", hrp, inputBytesHex);
    uint8_t inputBuffer[100] = {0};
    size_t inputSize;
    inputSize = decode_hex(inputBytesHex, inputBuffer, SIZEOF(inputBuffer));

    {
        // check encoding
        char outputStr[300] = {0};
        size_t outputLen = bech32_encode(hrp, inputBuffer, inputSize, outputStr, 300);
        EXPECT_EQ(outputLen, strlen(expectedStr));
        EXPECT_EQ_BYTES(expectedStr, outputStr, outputLen + 1);
    }

    {
        // check for buffer overflows
        const size_t expectedLen = strlen(expectedStr);  // not enough to fit ending '\0'
        char outputStr[300] = {0};
        outputStr[expectedLen] = '$';  // sentinel
        EXPECT_THROWS(bech32_encode(hrp, inputBuffer, inputSize, outputStr, expectedLen),
                      ERR_ASSERT);
        EXPECT_EQ(outputStr[expectedLen], '$');
    }
}

void run_bech32_test() {
    struct {
        const char* hrp;
        const char* inputBytesHex;
        const char* expectedHex;
    } testVectors[] = {
        /* cspell:disable */
        {"a", "", "a12uel5l"},
        {"an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio",
         "",
         "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tg"
         "s"},
        {"abcdef",
         "00443214c74254b635cf84653a56d7c675be77df",
         "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw"},
        {"1",
         "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
         "0000000000000",
         "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247"
         "j"},
        {"split",
         "c5f38b70305f519bf66d85fb6cf03058f3dde463ecd7918f2dc743918f2d",
         "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w"},
        {"addr",
         "009493315cd92eb5d8c4304e67b7e16ae36d61d34502694657811a2c8e32c728d3861e164cab28cb8f0064481"
         "39c8f1740ffb8e7aa9e5232dc",
         "addr1qz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3jcu5d8ps7zex2k2xt3uqxgjqnnj83ws8lhrn6"
         "48jjxtwqcyl47r"}
        /* cspell:enable */
    };
    ITERATE(it, testVectors) {
        testcase_bech32(PTR_PIC(it->hrp), PTR_PIC(it->inputBytesHex), PTR_PIC(it->expectedHex));
    }
}

#endif  // DEVEL
