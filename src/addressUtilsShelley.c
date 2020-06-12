#include "bufView.h"
#include "hash.h"
#include "keyDerivation.h"
#include "addressUtilsByron.h"
#include "addressUtilsShelley.h"
#include "bip44.h"

uint8_t getAddressType(uint8_t addressHeader)
{
	return addressHeader & (0b1111 << 4);
}

bool isSupportedAddressType(uint8_t addressHeader)
{
	const uint8_t addressType = getAddressType(addressHeader);
	switch (addressType) {
		case BASE:
		case POINTER:
		case ENTERPRISE:
		case BYRON:
		case REWARD:
			return true;
		default:
			return false;
	}
}

uint8_t getNetworkId(uint8_t addressHeader)
{
	return addressHeader & 0b00001111;
}

static size_t addPublicKeyHash(write_view_t* view, const bip44_path_t* pathSpec)
{
    extendedPublicKey_t extPubKey;
    deriveExtendedPublicKey(pathSpec, &extPubKey);

    uint8_t hashedPubKey[PUBLIC_KEY_HASH_LENGTH];
    blake2b_224_hash(
        extPubKey.pubKey, SIZEOF(extPubKey.pubKey),
        hashedPubKey, SIZEOF(hashedPubKey)
    );

    view_appendData(view, hashedPubKey, SIZEOF(hashedPubKey));

    return PUBLIC_KEY_HASH_LENGTH;
}

size_t deriveAddress_base_accountStakingKey(
        uint8_t addressHeader, const bip44_path_t* pathSpec,
        uint8_t* outBuffer, size_t outSize
)
{
    ASSERT(outSize < BUFFER_SIZE_PARANOIA);
	write_view_t out = make_write_view(outBuffer, outBuffer + outSize);

    view_appendData(&out, &addressHeader, 1);

    addPublicKeyHash(&out, pathSpec);
    {
        bip44_path_t stakingKeyPath;
        bip44_stakingKeyPathFromAddresPath(&stakingKeyPath, pathSpec);

        addPublicKeyHash(&out, &stakingKeyPath);
    }

    const int ADDRESS_LEN = 1 + 2 * PUBLIC_KEY_HASH_LENGTH;
    ASSERT(out.ptr - out.begin == ADDRESS_LEN);
    return ADDRESS_LEN;
}

size_t deriveAddress_base_foreignStakingKey(
        uint8_t addressHeader, const bip44_path_t* pathSpec,
        uint8_t* stakingKeyHash,
        uint8_t* outBuffer, size_t outSize
)
{
    ASSERT(outSize < BUFFER_SIZE_PARANOIA);
	write_view_t out = make_write_view(outBuffer, outBuffer + outSize);

    view_appendData(&out, &addressHeader, 1);

    addPublicKeyHash(&out, pathSpec);
    view_appendData(&out, stakingKeyHash, PUBLIC_KEY_HASH_LENGTH);
    // TODO perhaps ask for explicit hash length as an additional argument for safety?

    const int ADDRESS_LEN = 1 + 2 * PUBLIC_KEY_HASH_LENGTH;
    ASSERT(out.ptr - out.begin == ADDRESS_LEN);
    return ADDRESS_LEN;
}

static size_t appendVariableLengthInteger(write_view_t* view, certificateIndex_t value) {
    uint8_t chunks[10]; // 7-bit chunks, at most 10 in uint64
    size_t outputSize = 0;
    {
        certificateIndex_t bits = value;
        while (bits > 0) {
            // take next 7 bits from the right
            chunks[outputSize++] = bits & 0b01111111;
            bits >>= 7;
        }
    }
    if (value > 0) {
        ASSERT(outputSize > 0); 
        for (size_t i = outputSize - 1; i > 0; --i) {
            // highest bit set to 1 since more bytes follow
            uint8_t nextByte = chunks[i] | 0b10000000;
            view_appendData(view, &nextByte, 1);
        }
    } else {
        outputSize = 1;
        chunks[0] = 0;
    }

    // write remaining byte        
    view_appendData(view, &chunks[0], 1);

    return outputSize;
}

size_t deriveAddress_pointer(
        uint8_t addressHeader, const bip44_path_t* pathSpec,
        const certificatePointer_t* stakingKeyPointer,
        uint8_t* outBuffer, size_t outSize
)
{
    ASSERT(outSize < BUFFER_SIZE_PARANOIA);
	write_view_t out = make_write_view(outBuffer, outBuffer + outSize);
    size_t addressLength = 0;

    view_appendData(&out, &addressHeader, 1);
    addressLength += 1;

    addressLength += addPublicKeyHash(&out, pathSpec);

    // staking key pointer
    addressLength += appendVariableLengthInteger(&out, stakingKeyPointer->blockIndex);
    addressLength += appendVariableLengthInteger(&out, stakingKeyPointer->txIndex);
    addressLength += appendVariableLengthInteger(&out, stakingKeyPointer->certificateIndex);

    ASSERT(out.ptr >= out.begin);
    ASSERT((size_t)(out.ptr - out.begin) == addressLength);
    return addressLength;
}

size_t deriveAddress_enterprise(
        uint8_t addressHeader, const bip44_path_t* pathSpec,
        uint8_t* outBuffer, size_t outSize
)
{
    ASSERT(outSize < BUFFER_SIZE_PARANOIA);
	write_view_t out = make_write_view(outBuffer, outBuffer + outSize);

    view_appendData(&out, &addressHeader, 1);

    addPublicKeyHash(&out, pathSpec);

    const int ADDRESS_LEN = 1 + PUBLIC_KEY_HASH_LENGTH;
    ASSERT(out.ptr - out.begin == ADDRESS_LEN);
    return ADDRESS_LEN;
}

size_t deriveAddress_byron(
        uint8_t addressHeader MARK_UNUSED, const bip44_path_t* pathSpec,
        uint8_t* outBuffer, size_t outSize
)
{
    // the old Byron version
    // TODO network_id is ignored, should be?
    return deriveAddress(pathSpec, outBuffer, outSize);
}

size_t deriveAddress_reward(
        uint8_t addressHeader, const bip44_path_t* pathSpec,
        uint8_t* outBuffer, size_t outSize
)
{
    ASSERT(getAddressType(addressHeader) == REWARD);
    ASSERT(outSize < BUFFER_SIZE_PARANOIA);
	write_view_t out = make_write_view(outBuffer, outBuffer + outSize);

    view_appendData(&out, &addressHeader, 1);

    // staking key path expected
    ASSERT(bip44_isValidStakingKeyPath(pathSpec));
    addPublicKeyHash(&out, pathSpec); 

    const int ADDRESS_LEN = 1 + PUBLIC_KEY_HASH_LENGTH;
    ASSERT(out.ptr - out.begin == ADDRESS_LEN);
    return ADDRESS_LEN;
}
