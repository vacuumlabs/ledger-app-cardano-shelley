#ifndef H_CARDANO_APP_TEXT_UTILS
#define H_CARDANO_APP_TEXT_UTILS

#include "common.h"

size_t str_formatAdaAmount(uint64_t amount, char* out, size_t outSize);

#ifdef DEVEL
void str_traceAdaAmount(const char *prefix, uint64_t amount);
#define TRACE_ADA_AMOUNT(PREFIX, AMOUNT) \
	do { \
		str_traceAdaAmount(PREFIX, AMOUNT); \
	} while(0)
#else
#define TRACE_ADA_AMOUNT(PREFIX, AMOUNT)
#endif

size_t str_formatTtl(uint64_t ttl, char* out, size_t outSize);

size_t str_formatMetadata(const uint8_t* metadataHash, size_t metadataHashSize, char* out, size_t outSize);

void str_validateText(const uint8_t* url, size_t urlSize);

#ifdef DEVEL
// only used in tests
size_t urlToBuffer(const char* url, uint8_t* buffer, size_t bufferSize);
size_t dnsNameToBuffer(const char* dnsName, uint8_t* buffer, size_t bufferSize);
#endif

void run_textUtils_test();

#endif
