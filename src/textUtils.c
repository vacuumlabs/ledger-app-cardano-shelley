#include <string.h>

#include "textUtils.h"
#include "hex_utils.h"

#define WRITE_CHAR(ptr, end, c) \
	{ \
		ASSERT(ptr + 1 <= end); \
		*ptr = (c); \
		ptr++; \
	}

size_t str_formatAdaAmount(uint64_t amount, char* out, size_t outSize)
{
	ASSERT(outSize < BUFFER_SIZE_PARANOIA);

	char scratchBuffer[30];
	char* ptr = BEGIN(scratchBuffer);
	char* end = END(scratchBuffer);

	// We print in reverse

	// decimal digits
	for (int dec = 0; dec < 6; dec++) {
		WRITE_CHAR(ptr, end, '0' + (amount % 10));
		amount /= 10;
	}
	WRITE_CHAR(ptr, end, '.');
	// We want at least one iteration
	int place = 0;
	do {
		// thousands separator
		if (place && (place % 3 == 0)) {
			WRITE_CHAR(ptr, end, ',');
		}
		WRITE_CHAR(ptr, end, '0' + (amount % 10));
		amount /= 10;
		place++;
	} while (amount > 0);

	// Size without terminating character
	STATIC_ASSERT(sizeof(ptr - scratchBuffer) == sizeof(size_t), "bad size_t size");
	size_t rawSize = (size_t) (ptr - scratchBuffer);

	if (rawSize + 1 > outSize) {
		THROW(ERR_DATA_TOO_LARGE);
	}

	// Copy reversed & append terminator
	for (size_t i = 0; i < rawSize; i++) {
		out[i] = scratchBuffer[rawSize - 1 - i];
	}
	out[rawSize] = 0;

	return rawSize;
}

// TODO add tests
size_t str_formatTtl(uint64_t ttl, char* out, size_t outSize)
{
	// FIXME TODO uint64 does not fit into %d
	snprintf(out, outSize, "%d", ttl);
	return strlen(out);
}

// TODO add tests
size_t str_formatMetadata(const uint8_t* metadataHash, size_t metadataHashSize, char* out, size_t outSize)
{
	return encode_hex(metadataHash, metadataHashSize, out, outSize);
}
