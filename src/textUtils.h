#ifndef H_CARDANO_APP_TEXT_UTILS
#define H_CARDANO_APP_TEXT_UTILS

#include "common.h"

size_t str_formatAdaAmount(uint64_t amount, char* out, size_t outSize);

size_t str_formatUint64(uint64_t number, char* out, size_t outSize);

#ifdef DEVEL
void str_traceAdaAmount(const char *prefix, uint64_t amount);
#define TRACE_ADA_AMOUNT(PREFIX, AMOUNT) \
	do { \
		str_traceAdaAmount(PREFIX, AMOUNT); \
	} while(0)
#else
#define TRACE_ADA_AMOUNT(PREFIX, AMOUNT)
#endif

#ifdef DEVEL
void str_traceUint64(uint64_t number);
#define TRACE_UINT64(NUMBER) \
	do { \
		str_traceUint64(NUMBER); \
	} while(0)
#else
#define TRACE_UINT64(NUMBER)
#endif

size_t str_formatTtl(uint64_t ttl, char* out, size_t outSize);

size_t str_formatMetadata(const uint8_t* metadataHash, size_t metadataHashSize, char* out, size_t outSize);

void str_validateTextBuffer(const uint8_t* text, size_t textSize);


#ifdef DEVEL

size_t str_textToBuffer(const char* text, uint8_t* buffer, size_t bufferSize);

void run_textUtils_test();

#endif

#endif // H_CARDANO_APP_TEXT_UTILS
