#include "textUtils.h"
#include "hexUtils.h"

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


// TODO: This is valid only for mainnet
static struct {
	uint64_t startBlockNumber;
	uint64_t startEpoch;
	uint64_t slotsInEpoch;
} EPOCH_SLOTS_CONFIG[] = {
	{4492800, 208, 432000},
	{0, 0, 21600}
};

size_t str_formatTtl(uint64_t ttl, char* out, size_t outSize)
{
	ASSERT(outSize < BUFFER_SIZE_PARANOIA);

	unsigned i = 0;
	while (ttl < EPOCH_SLOTS_CONFIG[i].startBlockNumber) {
		i++;
		ASSERT(i < ARRAY_LEN(EPOCH_SLOTS_CONFIG));
	}

	ASSERT(ttl >= EPOCH_SLOTS_CONFIG[i].startBlockNumber);

	uint64_t startBlockNumber = EPOCH_SLOTS_CONFIG[i].startBlockNumber;
	uint64_t startEpoch = EPOCH_SLOTS_CONFIG[i].startEpoch;
	uint64_t slotsInEpoch = EPOCH_SLOTS_CONFIG[i].slotsInEpoch;

	uint64_t epoch = startEpoch + (ttl - startBlockNumber) / slotsInEpoch;
	uint64_t slotInEpoch = (ttl - startBlockNumber) % slotsInEpoch;

	ASSERT(sizeof(int) >= sizeof(uint32_t));

	ASSERT(outSize > 0); // so we can write null terminator
	if (epoch > 1000000)  {
		// thousands of years
		snprintf(out, outSize, "epoch more than 1000000");
	} else {
		snprintf(out, outSize, "epoch %d / slot %d", (int) epoch, (int) slotInEpoch);
	}

	// snprintf does not return length written
	size_t len = strlen(out);
	// make sure we did not truncate
	ASSERT(len + 1 < outSize);

	return strlen(out);
}

size_t str_formatMetadata(const uint8_t* metadataHash, size_t metadataHashSize, char* out, size_t outSize)
{
	return encode_hex(metadataHash, metadataHashSize, out, outSize);
}
