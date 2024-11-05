#if defined(DEVEL) && defined(APP_FEATURE_POOL_REGISTRATION)

#include "ipUtils.h"
#include "utils.h"

static void test1() {
    TRACE("ipUtils test");

    // in:  fe80:0000:0000:0000:a299:9bff:fe18:50d1
    // out: fe80::a299:9bff:fe18:50d1

    uint8_t in[16] = {0xfe,
                      0x80,
                      0x00,
                      0x00,
                      0x00,
                      0x00,
                      0x00,
                      0x00,
                      0xa2,
                      0x99,
                      0x9b,
                      0xff,
                      0xfe,
                      0x18,
                      0x50,
                      0xd1};

    char s[46] = {0};
    inet_ntop6(in, s, SIZEOF(s));

    ASSERT(!strcmp(s, "fe80::a299:9bff:fe18:50d1"));
}

static void test2() {
    TRACE("ipUtils test");

    // in:  2001:0db8:1111:000a:00b0:0000:0000:0200
    // out: 2001:db8:1111:a:b0::200

    uint8_t in[16] = {0x20,
                      0x01,
                      0x0d,
                      0xb8,
                      0x11,
                      0x11,
                      0x00,
                      0x0a,
                      0x00,
                      0xb0,
                      0x00,
                      0x00,
                      0x00,
                      0x00,
                      0x02,
                      0x00};

    char s[46] = {0};
    inet_ntop6(in, s, SIZEOF(s));

    ASSERT(!strcmp(s, "2001:db8:1111:a:b0::200"));
}

static void test3() {
    TRACE("ipUtils test");

    // in:  0:0:0:0:0:ffff:c000:280
    // out: ::ffff:192.0.2.128

    uint8_t in[16] = {0x00,
                      0x00,
                      0x00,
                      0x00,
                      0x00,
                      0x00,
                      0x00,
                      0x00,
                      0x00,
                      0x00,
                      0xff,
                      0xff,
                      0xc0,
                      0x00,
                      0x02,
                      0x80};

    char s[46] = {0};
    inet_ntop6(in, s, SIZEOF(s));

    ASSERT(!strcmp(s, "::ffff:192.0.2.128"));
}

void run_ipUtils_test() {
    test1();
    test2();
    test3();
}

#endif  // DEVEL && APP_FEATURE_POOL_REGISTRATION
