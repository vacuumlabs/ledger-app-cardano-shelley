#ifdef DEVEL

#include "common.h"
#include "testUtils.h"
#include "hexUtils.h"

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

#endif  // DEVEL
