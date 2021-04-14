#ifdef DEVEL

#include "cbor.h"
#include "hexUtils.h"
#include "testUtils.h"

// Test vectors are taken from
// https://tools.ietf.org/html/rfc7049#appendix-A
static void test_cbor_peek_token()
{
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
		uint8_t buf[20];
		size_t bufSize = decode_hex(PTR_PIC(it->hex), buf, SIZEOF(buf));

		cbor_token_t res = cbor_parseToken(buf, bufSize);
		EXPECT_EQ(res.type, it->type);
		EXPECT_EQ(res.width, it->width);
		EXPECT_EQ(res.value, it->value);
		EXPECT_EQ(res.width + 1, bufSize);
	}

}

// test whether we reject non-canonical serialization
static void test_cbor_parse_noncanonical()
{
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
	};

	ITERATE(it, testVectors) {
		PRINTF("test_cbor_parse_noncanonical %s\n", PTR_PIC(it->hex));
		uint8_t buf[20];
		size_t bufSize = decode_hex(PTR_PIC(it->hex), buf, SIZEOF(buf));
		EXPECT_THROWS(cbor_parseToken(buf, bufSize), ERR_UNEXPECTED_TOKEN);
	}
}

static void test_cbor_serialization()
{
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
		uint8_t expected[50];
		size_t expectedSize = decode_hex(PTR_PIC(it->hex), expected, SIZEOF(expected));
		uint8_t buffer[50];
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
		uint8_t buf[10];
		EXPECT_THROWS(cbor_writeToken(it->type, 0, buf, SIZEOF(buf)), ERR_UNEXPECTED_TOKEN);
	}
}

void run_cbor_test()
{
	test_cbor_peek_token();
	test_cbor_parse_noncanonical();
	test_cbor_serialization();
}

#endif // DEVEL
