#include "common.h"
#include "testUtils.h"

uint8_t hex_parseNibble(const char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    THROW(ERR_UNEXPECTED_TOKEN);
}

uint8_t hex_parseNibblePair(const char* buffer) {
    uint8_t first = hex_parseNibble(buffer[0]);
    uint8_t second = hex_parseNibble(buffer[1]);
    return (uint8_t)((first << 4) + second);
}

size_t decode_hex(const char* inStr, uint8_t* outBuffer, size_t outMaxSize) {
    ASSERT(outMaxSize < BUFFER_SIZE_PARANOIA);

    size_t len = strlen(inStr);
    ASSERT(len % 2 == 0);

    size_t outLen = len / 2;
    ASSERT(outLen <= outMaxSize);

    while (len >= 2) {
        *outBuffer = hex_parseNibblePair(inStr);
        len -= 2;
        inStr += 2;
        outBuffer += 1;
    }
    return outLen;
}

static const char HEX_ALPHABET[] = "0123456789abcdef";

// returns the length of the string written to out
size_t encode_hex(const uint8_t* bytes, size_t bytesLength, char* out, size_t outMaxSize) {
    ASSERT(bytesLength < BUFFER_SIZE_PARANOIA);
    ASSERT(outMaxSize < BUFFER_SIZE_PARANOIA);
    ASSERT(outMaxSize >= 2 * bytesLength + 1);

    size_t i = 0;
    for (; i < bytesLength; i++) {
        out[2 * i] = HEX_ALPHABET[bytes[i] >> 4];
        out[2 * i + 1] = HEX_ALPHABET[bytes[i] & 0x0F];
    }
    ASSERT(i == bytesLength);
    out[2 * i] = '\0';

    return 2 * bytesLength;
}

void test_hex_nibble_parsing() {
    struct {
        char nibble;
        int value;
    } testVectors[] = {
        {'0', 0},  {'1', 1},  {'2', 2},  {'3', 3},  {'4', 4},  {'5', 5},
        {'6', 6},  {'7', 7},  {'8', 8},  {'9', 9},

        {'a', 10}, {'b', 11}, {'c', 12}, {'d', 13}, {'e', 14}, {'f', 15},

        {'A', 10}, {'B', 11}, {'C', 12}, {'D', 13}, {'E', 14}, {'F', 15},
    };
    PRINTF("test_hex_nibble\n");

    ITERATE(it, testVectors) {
        EXPECT_EQ(hex_parseNibble(it->nibble), it->value);
    }

    struct {
        char nibble;
    } invalidVectors[] = {
        {'\x00'}, {'\x01'}, {'.'}, {'/'}, {':'}, {';'}, {'?'}, {'@'}, {'G'}, {'H'},  {'Z'},
        {'['},    {'\\'},   {'_'}, {'`'}, {'g'}, {'h'}, {'z'}, {'{'}, {127}, {128u}, {255u},
    };
    PRINTF("test_hex_nibble invalid\n");
    ITERATE(it, invalidVectors) {
        EXPECT_THROWS(hex_parseNibble(it->nibble), ERR_UNEXPECTED_TOKEN);
    }
}

void test_hex_parsing() {
    struct {
        const char* hex;
        uint8_t raw;
    } testVectors[] = {
        {"ff", 0xff},
        {"00", 0x00},
        {"1a", 0x1a},
        {"2b", 0x2b},
        {"3c", 0x3c},
        {"4d", 0x4d},
        {"5f", 0x5f},
        {"98", 0x98},
    };

    PRINTF("test_hex_parsing\n");
    ITERATE(it, testVectors) {
        EXPECT_EQ(hex_parseNibblePair(PTR_PIC(it->hex)), it->raw);
    }
}

void run_hex_test() {
    test_hex_nibble_parsing();
    test_hex_parsing();
}
