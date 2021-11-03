#include "cbor.h"
#include "endian.h"

// Note(ppershing): consume functions should either
// a) *consume* expected value, or
// b) *throw* but not consume anything from the stream

static const uint64_t VALUE_W1_UPPER_THRESHOLD = 24;
static const uint64_t VALUE_W2_UPPER_THRESHOLD = (uint64_t) 1 << 8;
static const uint64_t VALUE_W4_UPPER_THRESHOLD = (uint64_t) 1 << 16;
static const uint64_t VALUE_W8_UPPER_THRESHOLD = (uint64_t) 1 << 32;


cbor_token_t cbor_parseToken(const uint8_t* buf, size_t size)
{
#define ENSURE_AVAILABLE_BYTES(x) if (x > size) THROW(ERR_NOT_ENOUGH_INPUT);
	ENSURE_AVAILABLE_BYTES(1);
	const uint8_t tag = buf[0];
	cbor_token_t result;

	// tag extensions first
	if (tag == CBOR_TYPE_ARRAY_INDEF || tag == CBOR_TYPE_INDEF_END) {
		result.type = tag;
		result.width = 0;
		result.value = 0;
		return result;
	}

	result.type = tag & CBOR_TYPE_MASK;

	switch (result.type) {
	case CBOR_TYPE_UNSIGNED:
	case CBOR_TYPE_NEGATIVE:
	case CBOR_TYPE_BYTES:
	case CBOR_TYPE_ARRAY:
	case CBOR_TYPE_MAP:
	case CBOR_TYPE_TAG:
		break;
	default:
		// We don't know how to parse others
		// (particularly CBOR_TYPE_PRIMITIVES)
		THROW(ERR_UNEXPECTED_TOKEN);
	}

	const uint8_t val = (tag & CBOR_VALUE_MASK);
	if (val < 24) {
		result.width = 0;
		result.value = val;
		// return result;
	} else {
		// shift buffer
		// Holds minimum value for a given byte-width.
		// Anything below this is not canonical CBOR as
		// it could be represented by a shorter CBOR notation
		uint64_t limit_min;
		switch (val) {
		case 24:
			ENSURE_AVAILABLE_BYTES(1 + 1);
			result.width = 1;
			result.value = u1be_read(buf + 1);
			limit_min = VALUE_W1_UPPER_THRESHOLD;
			break;
		case 25:
			ENSURE_AVAILABLE_BYTES(1 + 2);
			result.width = 2;
			result.value = u2be_read(buf + 1);
			limit_min = VALUE_W2_UPPER_THRESHOLD;
			break;
		case 26:
			ENSURE_AVAILABLE_BYTES(1 + 4);
			result.width = 4;
			result.value = u4be_read(buf + 1);
			limit_min = VALUE_W4_UPPER_THRESHOLD;
			break;
		case 27:
			ENSURE_AVAILABLE_BYTES(1 + 8);
			result.width = 8;
			result.value = u8be_read(buf + 1);
			limit_min = VALUE_W8_UPPER_THRESHOLD;
			break;
		default:
			// Values above 27 are not valid in CBOR.
			// Exception is indefinite length marker
			// but this has been handled separately.
			THROW(ERR_UNEXPECTED_TOKEN);
		}

		if (result.value < limit_min) {
			// This isn't canonical CBOR
			THROW(ERR_UNEXPECTED_TOKEN);
		}
	}

	if (result.type == CBOR_TYPE_NEGATIVE) {
		if (result.value > INT64_MAX) {
			THROW(ERR_UNEXPECTED_TOKEN);
		}
		int64_t negativeValue;
		if (result.value < INT64_MAX) {
			negativeValue = -((int64_t)(result.value + 1));
		} else {
			negativeValue = INT64_MIN;
		}
		result.value = negativeValue;
	}

	return result;
#undef ENSURE_AVAILABLE_BYTES
}

size_t cbor_writeToken(uint8_t type, uint64_t value, uint8_t* buffer, size_t bufferSize)
{
	ASSERT(bufferSize < BUFFER_SIZE_PARANOIA);

#define CHECK_BUF_LEN(requiredSize) if ((size_t) requiredSize > bufferSize) THROW(ERR_DATA_TOO_LARGE);
	if (type == CBOR_TYPE_ARRAY_INDEF || type == CBOR_TYPE_INDEF_END || type == CBOR_TYPE_NULL) {
		CHECK_BUF_LEN(1);
		buffer[0] = type;
		return 1;
	}

	if (type & CBOR_VALUE_MASK) {
		// type should not have any value
		THROW(ERR_UNEXPECTED_TOKEN);
	}

	// Check sanity
	switch (type) {
	case CBOR_TYPE_NEGATIVE: {
		int64_t negativeValue;
		// reinterpret an actually negative value hidden in an unsigned in the safe way
		STATIC_ASSERT(SIZEOF(negativeValue) == SIZEOF(value), "incompatible signed and unsigned type sizes");
		memmove(&negativeValue, &value, SIZEOF(value));
		if (negativeValue >= 0) {
			THROW(ERR_UNEXPECTED_TOKEN);
		}
		value = (uint64_t)(-negativeValue) - 1;
		// intentional fallthrough
	}
	case CBOR_TYPE_UNSIGNED:
	case CBOR_TYPE_BYTES:
	case CBOR_TYPE_TEXT:
	case CBOR_TYPE_ARRAY:
	case CBOR_TYPE_MAP:
	case CBOR_TYPE_TAG:
		break;
	default:
		// not supported
		THROW(ERR_UNEXPECTED_TOKEN);
	}

	// Warning(ppershing): It might be tempting but we don't want to call stream_appendData() twice
	// Instead we have to construct the whole buffer at once to make append operation atomic.

	if (value < VALUE_W1_UPPER_THRESHOLD) {
		CHECK_BUF_LEN(1);
		u1be_write(buffer, (uint8_t) (type | value));
		return 1;
	} else if (value < VALUE_W2_UPPER_THRESHOLD) {
		CHECK_BUF_LEN(1 + 1);
		u1be_write(buffer, type | 24);
		u1be_write(buffer + 1, (uint8_t) value);
		return 1 + 1;
	} else if (value < VALUE_W4_UPPER_THRESHOLD) {
		CHECK_BUF_LEN(1 + 2);
		u1be_write(buffer, type | 25);
		u2be_write(buffer + 1, (uint16_t) value);
		return 1 + 2;
	} else if (value < VALUE_W8_UPPER_THRESHOLD) {
		CHECK_BUF_LEN(1 + 4);
		u1be_write(buffer, type | 26);
		u4be_write(buffer + 1, (uint32_t) value);
		return 1 + 4;
	} else {
		CHECK_BUF_LEN(1 + 8);
		u1be_write(buffer, type | 27);
		u8be_write(buffer + 1, value);
		return 1 + 8;
	}
#undef CHECK_BUF_LEN
}

bool cbor_mapKeyFulfillsCanonicalOrdering(
        const uint8_t* previousBuffer, size_t previousSize,
        const uint8_t* nextBuffer, size_t nextSize
)
{
	ASSERT(previousSize < BUFFER_SIZE_PARANOIA);
	ASSERT(nextSize < BUFFER_SIZE_PARANOIA);

	if (previousSize != nextSize) {
		return previousSize < nextSize;
	}
	for (size_t i = 0; i < previousSize; ++i) {
		if (*previousBuffer != *nextBuffer) {
			return *previousBuffer < *nextBuffer;
		}
		++previousBuffer;
		++nextBuffer;
	}
	// key duplication is an error
	return false;
}

