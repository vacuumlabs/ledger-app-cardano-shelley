#ifdef DEVEL

#include "cbor.h"
#include "hexUtils.h"
#include "testUtils.h"

// Test vectors are taken from
// https://tools.ietf.org/html/rfc7049#appendix-A
static void test_cbor_peek_token() {
    const struct {
        const char* hex;
        uint8_t type;
        uint8_t width;
        uint64_t value;
    } testVectors[] = {
        {"00", CBOR_TYPE_UNSIGNED, 0, 0},
        {"01", CBOR_TYPE_UNSIGNED, 0, 1},
        {"0a", CBOR_TYPE_UNSIGNED, 0, 10},
        {"17", CBOR_TYPE_UNSIGNED, 0, 23},

        {"1818", CBOR_TYPE_UNSIGNED, 1, 24},

        {"1903e8", CBOR_TYPE_UNSIGNED, 2, 1000},

        {"1a000f4240", CBOR_TYPE_UNSIGNED, 4, 1000000},

        {"1b000000e8d4a51000", CBOR_TYPE_UNSIGNED, 8, 1000000000000},
        {"1bffFFffFFffFFffFF", CBOR_TYPE_UNSIGNED, 8, 18446744073709551615u},

        {"20", CBOR_TYPE_NEGATIVE, 0, -1},
        {"29", CBOR_TYPE_NEGATIVE, 0, -10},
        {"37", CBOR_TYPE_NEGATIVE, 0, -24},

        {"3818", CBOR_TYPE_NEGATIVE, 1, -25},
        {"38ff", CBOR_TYPE_NEGATIVE, 1, -256},

        {"390100", CBOR_TYPE_NEGATIVE, 2, -257},
        {"39ffff", CBOR_TYPE_NEGATIVE, 2, -65536},

        {"3a00010000", CBOR_TYPE_NEGATIVE, 4, -65537},
        {"3affffffff", CBOR_TYPE_NEGATIVE, 4, -4294967296},

        {"3b0000000100000000", CBOR_TYPE_NEGATIVE, 8, -4294967297},
        {"3b7FFFFFFFFFFFFFFF", CBOR_TYPE_NEGATIVE, 8, INT64_MIN},

        {"40", CBOR_TYPE_BYTES, 0, 0},
        {"44", CBOR_TYPE_BYTES, 0, 4},

        {"80", CBOR_TYPE_ARRAY, 0, 0},
        {"83", CBOR_TYPE_ARRAY, 0, 3},
        {"9819", CBOR_TYPE_ARRAY, 1, 25},

        {"9f", CBOR_TYPE_ARRAY_INDEF, 0, 0},

        {"a0", CBOR_TYPE_MAP, 0, 0},
        {"a1", CBOR_TYPE_MAP, 0, 1},

        {"d818", CBOR_TYPE_TAG, 1, 24},

        {"ff", CBOR_TYPE_INDEF_END, 0, 0},
    };

    ITERATE(it, testVectors) {
        PRINTF("test_cbor_peek_token %s\n", PTR_PIC(it->hex));
        uint8_t buf[20] = {0};
        size_t bufSize = decode_hex(PTR_PIC(it->hex), buf, SIZEOF(buf));

        cbor_token_t res = cbor_parseToken(buf, bufSize);
        EXPECT_EQ(res.type, it->type);
        EXPECT_EQ(res.width, it->width);
        EXPECT_EQ(res.value, it->value);
        EXPECT_EQ(res.width + 1, bufSize);
    }
}

// test whether we reject non-canonical serialization
static void test_cbor_parse_noncanonical() {
    const struct {
        const char* hex;
    } testVectors[] = {
        {"1800"},
        {"1817"},

        {"190000"},
        {"1900ff"},

        {"1a00000000"},
        {"1a0000ffff"},

        {"1b0000000000000000"},
        {"1b00000000ffffffff"},
        // CBOR NEGATIVE type but smaller than INT64_MIN
        {"1cffFFffFFffFFffFF"},

    };

    ITERATE(it, testVectors) {
        PRINTF("test_cbor_parse_noncanonical %s\n", PTR_PIC(it->hex));
        uint8_t buf[20] = {0};
        size_t bufSize = decode_hex(PTR_PIC(it->hex), buf, SIZEOF(buf));
        EXPECT_THROWS(cbor_parseToken(buf, bufSize), ERR_UNEXPECTED_TOKEN);
    }
}

static void test_cbor_serialization() {
    const struct {
        const char* hex;
        uint8_t type;
        uint64_t value;
    } testVectors[] = {
        {"00", CBOR_TYPE_UNSIGNED, 0},
        {"01", CBOR_TYPE_UNSIGNED, 1},
        {"0a", CBOR_TYPE_UNSIGNED, 10},
        {"17", CBOR_TYPE_UNSIGNED, 23},

        {"1818", CBOR_TYPE_UNSIGNED, 24},

        {"1903e8", CBOR_TYPE_UNSIGNED, 1000},

        {"1a000f4240", CBOR_TYPE_UNSIGNED, 1000000},

        {"1b000000e8d4a51000", CBOR_TYPE_UNSIGNED, 1000000000000},
        {"1bffFFffFFffFFffFF", CBOR_TYPE_UNSIGNED, 18446744073709551615u},

        // 0b0010 0000
        {"20", CBOR_TYPE_NEGATIVE, -1},
        // 0b0010 1001
        {"29", CBOR_TYPE_NEGATIVE, -10},

        // 0b0011 0111
        {"37", CBOR_TYPE_NEGATIVE, -24},
        // 0b0011 1000 == type | 24
        {"3818", CBOR_TYPE_NEGATIVE, -25},

        {"38ff", CBOR_TYPE_NEGATIVE, -256},
        // 0b0011 1001 == type | 25
        {"390100", CBOR_TYPE_NEGATIVE, -257},

        {"39ffff", CBOR_TYPE_NEGATIVE, -65536},
        // 0b0011 1010 == type | 26
        {"3a00010000", CBOR_TYPE_NEGATIVE, -65537},

        {"3affffffff", CBOR_TYPE_NEGATIVE, -4294967296},
        // 0b0011 1011 == type | 27
        {"3b0000000100000000", CBOR_TYPE_NEGATIVE, -4294967297},

        {"3b7FFFFFFFFFFFFFFF", CBOR_TYPE_NEGATIVE, INT64_MIN},

        {"40", CBOR_TYPE_BYTES, 0},
        {"44", CBOR_TYPE_BYTES, 4},

        {"80", CBOR_TYPE_ARRAY, 0},
        {"83", CBOR_TYPE_ARRAY, 3},
        {"9819", CBOR_TYPE_ARRAY, 25},

        {"9f", CBOR_TYPE_ARRAY_INDEF, 0},

        {"a0", CBOR_TYPE_MAP, 0},
        {"a1", CBOR_TYPE_MAP, 1},

        {"ff", CBOR_TYPE_INDEF_END, 0},
    };

    ITERATE(it, testVectors) {
        PRINTF("test_cbor_serialization %s\n", PTR_PIC(it->hex));
        uint8_t expected[50] = {0};
        size_t expectedSize = decode_hex(PTR_PIC(it->hex), expected, SIZEOF(expected));
        uint8_t buffer[50] = {0};
        size_t bufferSize = cbor_writeToken(it->type, it->value, buffer, SIZEOF(buffer));
        EXPECT_EQ(bufferSize, expectedSize);
        EXPECT_EQ_BYTES(buffer, expected, expectedSize);
    }

    // Check invalid type
    const struct {
        uint8_t type;
    } invalidVectors[] = {
        {1},
        {2},
        {47},
    };

    ITERATE(it, invalidVectors) {
        uint8_t buf[10] = {0};
        EXPECT_THROWS(cbor_writeToken(it->type, 0, buf, SIZEOF(buf)), ERR_UNEXPECTED_TOKEN);
    }
}

void run_cbor_test() {
    test_cbor_peek_token();
    test_cbor_parse_noncanonical();
    test_cbor_serialization();
}

#endif  // DEVEL
