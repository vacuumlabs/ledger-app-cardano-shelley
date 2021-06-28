#ifndef H_CARDANO_APP_IP_UTILS
#define H_CARDANO_APP_IP_UTILS

#include "os.h"

#define IPV4_STR_SIZE_MAX (sizeof "255.255.255.255")
#define IPV6_STR_SIZE_MAX (sizeof "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255")

void inet_ntop4 (const uint8_t *src, char *dst, size_t dstSize);
void inet_ntop6 (const uint8_t *src, char *dst, size_t dstSize);

#ifdef DEVEL
void run_ipUtils_test();
#endif // DEVEL

#endif  // H_CARDANO_APP_SIGN_TX_UTILS
