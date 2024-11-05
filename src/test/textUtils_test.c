#ifdef DEVEL

#include "common.h"
#include "textUtils.h"
#include "testUtils.h"

void testcase_formatDecimal(uint64_t amount, size_t places, const char* expected) {
    PRINTF("testcase_formatDecimal %s\n", expected);
    char tmp[30] = {0};
    size_t len = str_formatDecimalAmount(amount, places, tmp, SIZEOF(tmp));
    EXPECT_EQ(len, strlen(expected));
    EXPECT_EQ(strcmp(tmp, expected), 0);
}

void test_formatDecimal() {
    testcase_formatDecimal(0, 0, "0");
    testcase_formatDecimal(0, 4, "0.0000");
    testcase_formatDecimal(1, 8, "0.00000001");
    testcase_formatDecimal(10, 8, "0.00000010");
    testcase_formatDecimal(123456, 4, "12.3456");
    testcase_formatDecimal(1000000, 3, "1,000.000");
    testcase_formatDecimal(12345678901234567890u, 12, "12,345,678.901234567890");

    {
        PRINTF("test_formatDecimal edge cases");
        char tmp[16] = {0};
        memset(tmp, 'X', SIZEOF(tmp));
        str_formatDecimalAmount(0, 4, tmp, 9);
        EXPECT_EQ(tmp[6], 0);
        EXPECT_EQ(tmp[7], 'X');

        memset(tmp, 'X', SIZEOF(tmp));
        EXPECT_THROWS(str_formatDecimalAmount(10000000, 5, tmp, 9), ERR_ASSERT);
        EXPECT_EQ(tmp[9], 'X');
    }
}

void testcase_formatAda(uint64_t amount, const char* expected) {
    PRINTF("testcase_formatAda %s\n", expected);
    char tmp[40] = {0};
    size_t len = str_formatAdaAmount(amount, tmp, SIZEOF(tmp));
    EXPECT_EQ(len, strlen(expected));
    EXPECT_EQ(strcmp(tmp, expected), 0);
}

void test_formatAda() {
    testcase_formatAda(0, "0.000000 ADA");
    testcase_formatAda(1, "0.000001 ADA");
    testcase_formatAda(10, "0.000010 ADA");
    testcase_formatAda(123456, "0.123456 ADA");
    testcase_formatAda(1000000, "1.000000 ADA");
    testcase_formatAda(12345678901234567890u, "12,345,678,901,234.567890 ADA");

    {
        PRINTF("test_formatAda edge cases");
        char tmp[16] = {0};
        memset(tmp, 'X', SIZEOF(tmp));
        str_formatAdaAmount(0, tmp, 14);
        EXPECT_EQ(tmp[12], 0);
        EXPECT_EQ(tmp[14], 'X');

        memset(tmp, 'X', SIZEOF(tmp));
        EXPECT_THROWS(str_formatAdaAmount(10000000, tmp, 14), ERR_ASSERT);
        EXPECT_EQ(tmp[14], 'X');
    }
}

void testcase_formatTtl(uint64_t ttl, const char* expected) {
    PRINTF("testcase_formatTtl %s\n", expected);

    {
        char tmp[30] = {0};
        size_t len = str_formatValidityBoundary(ttl, tmp, SIZEOF(tmp));
        EXPECT_EQ(len, strlen(expected));
        EXPECT_EQ(strcmp(tmp, expected), 0);
    }

    {
        // check for buffer overflows
        char tmp[30] = {0};
        EXPECT_THROWS(str_formatValidityBoundary(ttl, tmp, strlen(expected)), ERR_ASSERT);
    }
}

void test_formatTtl() {
    // Byron
    testcase_formatTtl(123, "epoch 0 / slot 123");
    testcase_formatTtl(5 * 21600 + 124, "epoch 5 / slot 124");
    // Shelley
    testcase_formatTtl(4492800, "epoch 208 / slot 0");
    testcase_formatTtl(4924799, "epoch 208 / slot 431999");
    testcase_formatTtl(4924800, "epoch 209 / slot 0");
    // Wrong
    testcase_formatTtl(1000001llu * 432000 + 124, "epoch more than 1000000");
    testcase_formatTtl(-1ll, "epoch more than 1000000");
}

void testcase_formatUint64(uint64_t number, const char* expected) {
    PRINTF("testcase_formatUint64 %s\n", expected);

    {
        char tmp[30] = {0};
        size_t len = str_formatUint64(number, tmp, SIZEOF(tmp));
        EXPECT_EQ(len, strlen(expected));
        EXPECT_EQ(strcmp(tmp, expected), 0);
    }

    {
        // check for buffer overflows
        char tmp[30] = {0};
        EXPECT_THROWS(str_formatUint64(number, tmp, strlen(expected)), ERR_ASSERT);
    }
}

void testcase_formatInt64(int64_t number, const char* expected) {
    PRINTF("testcase_formatInt64 %s\n", expected);

    {
        char tmp[30] = {0};
        size_t len = str_formatInt64(number, tmp, SIZEOF(tmp));
        EXPECT_EQ(len, strlen(expected));
        EXPECT_EQ(strcmp(tmp, expected), 0);
    }

    {
        // check for buffer overflows
        char tmp[30] = {0};
        EXPECT_THROWS(str_formatInt64(number, tmp, strlen(expected)), ERR_ASSERT);
    }
}

void test_formatUint64() {
    testcase_formatUint64(0, "0");
    testcase_formatUint64(1, "1");
    testcase_formatUint64(4924800, "4924800");
    testcase_formatUint64(4924799, "4924799");
    testcase_formatUint64(-1ll, "18446744073709551615");
}

void test_formatInt64() {
    testcase_formatInt64(0, "0");
    testcase_formatInt64(1, "1");
    testcase_formatInt64(4924800, "4924800");
    testcase_formatInt64(4924799, "4924799");
    testcase_formatInt64(-1ll, "-1");
    testcase_formatInt64(-922337203685477580, "-922337203685477580");
    testcase_formatInt64(INT64_MIN, "-9223372036854775808");
}

void run_textUtils_test() {
    test_formatDecimal();
    test_formatAda();
    test_formatTtl();
    test_formatUint64();
    test_formatInt64();
}

#endif  // DEVEL
