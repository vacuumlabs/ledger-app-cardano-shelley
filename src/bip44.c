#include "common.h"
#include "bip44.h"
#include "endian.h"
#include "hash.h"
#include "keyDerivation.h"

static const uint32_t CARDANO_CHAIN_EXTERNAL = 0;
static const uint32_t CARDANO_CHAIN_INTERNAL = 1;
static const uint32_t CARDANO_CHAIN_STAKING_KEY = 2;

static const uint32_t MAX_REASONABLE_ACCOUNT = 100;
static const uint32_t MAX_REASONABLE_ADDRESS = 1000000;

static const uint32_t MAX_REASONABLE_COLD_KEY_INDEX = 100;


size_t bip44_parseFromWire(
        bip44_path_t* pathSpec,
        const uint8_t *dataBuffer, size_t dataSize
)
{
	// Ensure we have length
	VALIDATE(dataSize >= 1, ERR_INVALID_DATA);

	// Cast length to size_t
	size_t length = dataBuffer[0];

	// Ensure length is valid
	VALIDATE(length <= ARRAY_LEN(pathSpec->path), ERR_INVALID_DATA);
	VALIDATE(length * 4 + 1 <= dataSize, ERR_INVALID_DATA);

	pathSpec->length = length;

	size_t offset = 1;
	for (size_t i = 0; i < length; i++) {
		pathSpec->path[i] = u4be_read(dataBuffer + offset);
		offset += 4;
	}
	return offset;
}

bool isHardened(uint32_t value)
{
	return value == (value | HARDENED_BIP32);
}

uint32_t unharden(uint32_t value)
{
	ASSERT(isHardened(value));
	return value & (~HARDENED_BIP32);
}

// Byron: /44'/1815'
bool bip44_hasByronPrefix(const bip44_path_t* pathSpec)
{
#define CHECK(cond) if (!(cond)) return false
	CHECK(pathSpec->length > BIP44_I_COIN_TYPE);
	CHECK(pathSpec->path[BIP44_I_PURPOSE] == (PURPOSE_BYRON | HARDENED_BIP32));
	CHECK(pathSpec->path[BIP44_I_COIN_TYPE] == (ADA_COIN_TYPE | HARDENED_BIP32));
	return true;
#undef CHECK
}

// Shelley: /1852'/1815'
bool bip44_hasShelleyPrefix(const bip44_path_t* pathSpec)
{
#define CHECK(cond) if (!(cond)) return false
	CHECK(pathSpec->length > BIP44_I_COIN_TYPE);
	CHECK(pathSpec->path[BIP44_I_PURPOSE] == (PURPOSE_SHELLEY | HARDENED_BIP32));
	CHECK(pathSpec->path[BIP44_I_COIN_TYPE] == (ADA_COIN_TYPE | HARDENED_BIP32));
	return true;
#undef CHECK
}

bool bip44_hasValidCardanoWalletPrefix(const bip44_path_t* pathSpec)
{
	return bip44_hasByronPrefix(pathSpec) || bip44_hasShelleyPrefix(pathSpec);
}

bool bip44_hasValidCardanoPoolColdKeyPrefix(const bip44_path_t* pathSpec)
{
#define CHECK(cond) if (!(cond)) return false
	CHECK(pathSpec->length > BIP44_I_COIN_TYPE);
	CHECK(pathSpec->path[BIP44_I_PURPOSE] == (PURPOSE_POOL_COLD_KEY | HARDENED_BIP32));
	CHECK(pathSpec->path[BIP44_I_COIN_TYPE] == (ADA_COIN_TYPE | HARDENED_BIP32));
	return true;
#undef CHECK
}

// Account

bool bip44_containsAccount(const bip44_path_t* pathSpec)
{
	return pathSpec->length > BIP44_I_ACCOUNT;
}

uint32_t bip44_getAccount(const bip44_path_t* pathSpec)
{
	ASSERT(pathSpec->length > BIP44_I_ACCOUNT);
	return pathSpec->path[BIP44_I_ACCOUNT];
}

uint32_t bip44_getColdKeyIndex(const bip44_path_t* pathSpec)
{
	ASSERT(pathSpec->length > BIP44_I_POOL_COLD_KEY);
	return pathSpec->path[BIP44_I_POOL_COLD_KEY];
}

bool bip44_hasReasonableAccount(const bip44_path_t* pathSpec)
{
	if (!bip44_containsAccount(pathSpec)) return false;
	uint32_t account = bip44_getAccount(pathSpec);
	if (!isHardened(account)) return false;
	return unharden(account) <= MAX_REASONABLE_ACCOUNT;
}

bool bip44_hasReasonablePoolColdKeyIndex(const bip44_path_t* pathSpec)
{
	if (!bip44_isValidPoolColdKeyPath(pathSpec)) return false;
	uint32_t cold_key_index = bip44_getColdKeyIndex(pathSpec);

	if (!isHardened(cold_key_index)) return false;
	return unharden(cold_key_index) <= MAX_REASONABLE_COLD_KEY_INDEX;
}

// ChainType

bool bip44_containsChainType(const bip44_path_t* pathSpec)
{
	return pathSpec->length > BIP44_I_CHAIN;
}

uint32_t bip44_getChainTypeValue(const bip44_path_t* pathSpec)
{
	ASSERT(pathSpec->length > BIP44_I_CHAIN);
	return pathSpec->path[BIP44_I_CHAIN];
}

static bool bip44_hasValidChainTypeForAddress(const bip44_path_t* pathSpec)
{
	if (!bip44_containsChainType(pathSpec)) return false;
	const uint32_t chainType = bip44_getChainTypeValue(pathSpec);

	return (chainType == CARDANO_CHAIN_EXTERNAL) || (chainType == CARDANO_CHAIN_INTERNAL);
}

// Address

bool bip44_containsAddress(const bip44_path_t* pathSpec)
{
	return pathSpec->length > BIP44_I_ADDRESS;
}

uint32_t bip44_getAddressValue(const bip44_path_t* pathSpec)
{
	ASSERT(pathSpec->length > BIP44_I_ADDRESS);
	return pathSpec->path[BIP44_I_ADDRESS];
}

bool bip44_hasReasonableAddress(const bip44_path_t* pathSpec)
{
	if (!bip44_containsAddress(pathSpec)) return false;
	const uint32_t address = bip44_getAddressValue(pathSpec);
	return (address <= MAX_REASONABLE_ADDRESS);
}

// path is valid as the spending path in all addresses except REWARD
bool bip44_isValidAddressPath(const bip44_path_t* pathSpec)
{
	return bip44_hasValidCardanoWalletPrefix(pathSpec) &&
	       bip44_hasValidChainTypeForAddress(pathSpec) &&
	       bip44_containsAddress(pathSpec);
}

// Staking keys (one per account, should end with /2/0 after account)
bool bip44_isValidStakingKeyPath(const bip44_path_t* pathSpec)
{
	if (!bip44_containsAddress(pathSpec)) return false;
	if (bip44_containsMoreThanAddress(pathSpec)) return false;
	if (!bip44_hasShelleyPrefix(pathSpec)) return false;

	const uint32_t chainType = bip44_getChainTypeValue(pathSpec);
	if (chainType != CARDANO_CHAIN_STAKING_KEY) return false;

	return (bip44_getAddressValue(pathSpec) == 0);
}

bool bip44_isValidPoolColdKeyPath(const bip44_path_t* pathSpec)
{
#define CHECK(cond) if (!(cond)) return false
	CHECK(pathSpec->length == BIP44_I_POOL_COLD_KEY + 1);
	CHECK(bip44_hasValidCardanoPoolColdKeyPrefix(pathSpec));
	CHECK(pathSpec->path[BIP44_I_POOL_COLD_KEY_USECASE] == 0 + HARDENED_BIP32);
	CHECK(pathSpec->path[BIP44_I_POOL_COLD_KEY] >= HARDENED_BIP32);
	return true;
#undef CHECK
}

bool bip44_containsMoreThanAddress(const bip44_path_t* pathSpec)
{
	return (pathSpec->length > BIP44_I_ADDRESS + 1);
}

// returns the length of the resulting string
size_t bip44_printToStr(const bip44_path_t* pathSpec, char* out, size_t outSize)
{
	ASSERT(outSize < BUFFER_SIZE_PARANOIA);
	// We have to have space for terminating null
	ASSERT(outSize > 0);
	char* ptr = out;
	char* end = (out + outSize);

#define WRITE(fmt, ...) \
	{ \
		ASSERT(ptr <= end); \
		STATIC_ASSERT(sizeof(end - ptr) == sizeof(size_t), "bad size_t size"); \
		size_t availableSize = (size_t) (end - ptr); \
		/* Note(ppershing): We do not bother checking return */ \
		/* value of snprintf as it always returns 0. */ \
		/* Go figure out ... */ \
		snprintf(ptr, availableSize, fmt, ##__VA_ARGS__); \
		size_t res = strlen(ptr); \
		/* if snprintf filled all the remaining space, there is no space for '\0', */ \
		/* i.e. outSize is insufficient, we messed something up */ \
		/* usually, outSize >= BIP44_PATH_STRING_SIZE_MAX */ \
		ASSERT(res + 1 <= availableSize); \
		ptr += res; \
	}

	WRITE("m");

	ASSERT(pathSpec->length <= ARRAY_LEN(pathSpec->path));

	for (size_t i = 0; i < pathSpec->length; i++) {
		const uint32_t value = pathSpec->path[i];

		if ((value & HARDENED_BIP32) == HARDENED_BIP32) {
			WRITE("/%d'", (int) (value & ~HARDENED_BIP32));
		} else {
			WRITE("/%d", (int) value);
		}
	}
#undef WRITE
	ASSERT(ptr < end);
	ASSERT(ptr >= out);

	return ptr - out;
}


bip44_path_type_t bip44_classifyPath(const bip44_path_t* pathSpec)
{
	if (bip44_hasValidCardanoPoolColdKeyPrefix(pathSpec)) {
		if (bip44_isValidPoolColdKeyPath(pathSpec)) {
			return PATH_POOL_COLD_KEY;
		} else {
			return PATH_INVALID;
		}
	}

	if (bip44_hasValidCardanoWalletPrefix(pathSpec)) {
		switch (pathSpec->length) {

		case 3: {
			return PATH_WALLET_ACCOUNT;
		}

		case 5: {
			const uint8_t chainType = bip44_getChainTypeValue(pathSpec);
			switch (chainType) {

			case CARDANO_CHAIN_INTERNAL:
			case CARDANO_CHAIN_EXTERNAL:
				return PATH_WALLET_SPENDING_KEY;

			case CARDANO_CHAIN_STAKING_KEY:
				if (bip44_isValidStakingKeyPath(pathSpec)) {
					return PATH_WALLET_STAKING_KEY;
				} else {
					return PATH_INVALID;
				}

			default:
				return PATH_INVALID;
			}
		}

		// TODO too many returns in various depths, split into relevant parts when multisig is added
		default:
			return PATH_INVALID;
		}
	}

	return PATH_INVALID;
}

bool bip44_isPathReasonable(const bip44_path_t* pathSpec)
{
	switch (bip44_classifyPath(pathSpec)) {

	case PATH_WALLET_ACCOUNT:
		return bip44_hasReasonableAccount(pathSpec);

	case PATH_WALLET_SPENDING_KEY:
		return bip44_hasReasonableAccount(pathSpec) && bip44_hasReasonableAddress(pathSpec);

	case PATH_WALLET_STAKING_KEY:
		return bip44_hasReasonableAccount(pathSpec);

	case PATH_POOL_COLD_KEY:
		return bip44_hasReasonablePoolColdKeyIndex(pathSpec);

	default:
		// we are not supposed to call this for invalid paths
		ASSERT(false);
	}
	return false;
}

void bip44_pathToKeyHash(const bip44_path_t* pathSpec, uint8_t* hash, size_t hashSize)
{
	extendedPublicKey_t extPubKey;
	deriveExtendedPublicKey(pathSpec, &extPubKey);

	switch (hashSize) {
	case 28:
		ASSERT(hashSize * 8 == 224);

		blake2b_224_hash(
		        extPubKey.pubKey, SIZEOF(extPubKey.pubKey),
		        hash, hashSize
		);
		return;

	default:
		ASSERT(false);
	}
}


#ifdef DEVEL
void bip44_PRINTF(const bip44_path_t* pathSpec)
{
	char tmp[BIP44_PATH_STRING_SIZE_MAX];
	SIZEOF(*pathSpec);
	bip44_printToStr(pathSpec, tmp, SIZEOF(tmp));
	PRINTF("%s", tmp);
};
#endif // DEVEL
