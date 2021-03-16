#ifdef DEVEL

#include "common.h"
#include "textUtils.h"
#include "testUtils.h"

void testcase_formatAda(
        uint64_t amount,
        const char* expected
)
{
	PRINTF("testcase_formatAda %s\n", expected);
	char tmp[30];
	size_t len = str_formatAdaAmount(amount, tmp, SIZEOF(tmp));
	EXPECT_EQ(len, strlen(expected));
	EXPECT_EQ(strcmp(tmp, expected), 0);
}

void test_formatAda()
{
	testcase_formatAda(0,       "0.000000 ADA");
	testcase_formatAda(1,       "0.000001 ADA");
	testcase_formatAda(10,      "0.000010 ADA");
	testcase_formatAda(123456,  "0.123456 ADA");
	testcase_formatAda(1000000, "1.000000 ADA");
	testcase_formatAda(
	        12345678901234567890u,
	        "12,345,678,901,234.567890 ADA"
	);

	{
		PRINTF("test_formatAda edge cases");
		char tmp[16];
		os_memset(tmp, 'X', SIZEOF(tmp));
		str_formatAdaAmount(0, tmp, 13);
		EXPECT_EQ(tmp[12], 0);
		EXPECT_EQ(tmp[13], 'X');

		EXPECT_THROWS(str_formatAdaAmount(10000000, tmp, 13),
		              ERR_DATA_TOO_LARGE);
		EXPECT_EQ(tmp[13], 'X');
	}
}

void testcase_formatTtl(
        uint64_t ttl,
        const char* expected
)
{
	PRINTF("testcase_formatTtl %s\n", expected);

	{
		char tmp[30];
		size_t len = str_formatValidityBoundary(ttl, tmp, SIZEOF(tmp));
		EXPECT_EQ(len, strlen(expected));
		EXPECT_EQ(strcmp(tmp, expected), 0);
	}

	{
		// check for buffer overflows
		char tmp[30];
		EXPECT_THROWS(str_formatValidityBoundary(ttl, tmp, strlen(expected)), ERR_ASSERT);
	}
}

void test_formatTtl()
{
	// Byron
	testcase_formatTtl( 		    123, "epoch 0 / slot 123");
	testcase_formatTtl( 5 * 21600 + 124, "epoch 5 / slot 124");
	// Shelley
	testcase_formatTtl( 4492800, "epoch 208 / slot 0");
	testcase_formatTtl( 4924799, "epoch 208 / slot 431999");
	testcase_formatTtl( 4924800, "epoch 209 / slot 0");
	// Wrong
	testcase_formatTtl(1000001llu * 432000 + 124, "epoch more than 1000000");
	testcase_formatTtl( -1ll, "epoch more than 1000000");

}

void testcase_formatUint64(
        uint64_t number,
        const char* expected
)
{
	PRINTF("testcase_formatUint64 %s\n", expected);

	{
		char tmp[30];
		size_t len = str_formatUint64(number, tmp, SIZEOF(tmp));
		EXPECT_EQ(len, strlen(expected));
		EXPECT_EQ(strcmp(tmp, expected), 0);
	}

	{
		// check for buffer overflows
		char tmp[30];
		EXPECT_THROWS(str_formatUint64(number, tmp, strlen(expected)), ERR_DATA_TOO_LARGE);
	}
}

void test_formatUint64()
{
	testcase_formatUint64( 0, "0");
	testcase_formatUint64( 1, "1");
	testcase_formatUint64( 4924800, "4924800");
	testcase_formatUint64( 4924799, "4924799");
	testcase_formatUint64( -1ll, "18446744073709551615");
}

void run_textUtils_test()
{
	test_formatAda();
	test_formatTtl();
	test_formatUint64();
}

#endif // DEVEL
