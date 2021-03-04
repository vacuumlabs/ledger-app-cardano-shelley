#ifndef H_CARDANO_APP_BIP44
#define H_CARDANO_APP_BIP44

#include "common.h"

#define BIP44_MAX_PATH_ELEMENTS 5u
// each element in path is uint32, so at most 10 decimal digits
// plus ' for hardened plus / as a separator, plus the initial m and '\0'
#define BIP44_PATH_STRING_SIZE_MAX (1 + 12 * BIP44_MAX_PATH_ELEMENTS + 1)

typedef struct {
	uint32_t path[BIP44_MAX_PATH_ELEMENTS];
	uint32_t length;
} bip44_path_t;


static const uint32_t PURPOSE_BYRON = 44;
static const uint32_t PURPOSE_SHELLEY = 1852;

static const uint32_t PURPOSE_POOL_COLD_KEY = 1853;

static const uint32_t ADA_COIN_TYPE = 1815;

static const uint32_t HARDENED_BIP32 = ((uint32_t) 1 << 31);


size_t bip44_parseFromWire(
        bip44_path_t* pathSpec,
        const uint8_t* dataBuffer, size_t dataSize
);

// Indexes into pathSpec
enum {
	BIP44_I_PURPOSE = 0,
	BIP44_I_COIN_TYPE = 1,
	BIP44_I_ACCOUNT = 2,
	BIP44_I_CHAIN = 3,
	BIP44_I_ADDRESS = 4,
	BIP44_I_REST = 5,

	// cold key derivation path specific enums
	BIP44_I_POOL_COLD_KEY_USECASE = 2,
	BIP44_I_POOL_COLD_KEY = 3,
};


bool bip44_hasByronPrefix(const bip44_path_t* pathSpec);
bool bip44_hasShelleyPrefix(const bip44_path_t* pathSpec);
bool bip44_hasValidCardanoWalletPrefix(const bip44_path_t* pathSpec);

bool bip44_containsAccount(const bip44_path_t* pathSpec);
uint32_t bip44_getAccount(const bip44_path_t* pathSpec);
bool bip44_hasReasonableAccount(const bip44_path_t* pathSpec);

bool bip44_containsChainType(const bip44_path_t* pathSpec);

bool bip44_containsAddress(const bip44_path_t* pathSpec);
bool bip44_isValidAddressPath(const bip44_path_t* pathSpec);
bool bip44_hasReasonableAddress(const bip44_path_t* pathSpec);

bool bip44_isValidStakingKeyPath(const bip44_path_t* pathSpec);

bool bip44_containsMoreThanAddress(const bip44_path_t* pathSpec);

bool bip44_isValidPoolColdKeyPath(const bip44_path_t* pathSpec);
bool bip44_hasReasonablePoolColdKeyIndex(const bip44_path_t* pathSpec);

bool isHardened(uint32_t value);
uint32_t unharden(uint32_t value);

size_t bip44_printToStr(const bip44_path_t*, char* out, size_t outSize);


typedef enum {
	// hd wallet account
	PATH_WALLET_ACCOUNT,

	// hd wallet address
	PATH_WALLET_ADDRESS,

	// hd wallet reward adress, withdrawal witness, pool owner
	PATH_WALLET_STAKING_KEY,

	// unknown paths with wallet prefix
	PATH_WALLET_INVALID,

	// pool cold key in pool registrations and retirements
	PATH_POOL_COLD_KEY,
	// unknown paths with pool cold key prefix
	PATH_POOL_COLD_KEY_INVALID,

	PATH_UNKNOWN,
} bip44_path_type_t;

bip44_path_type_t bip44_classifyPath(const bip44_path_t* pathSpec);

bool bip44_isPathReasonable(const bip44_path_t* pathSpec);


#ifdef DEVEL
void run_bip44_test();
void bip44_PRINTF(const bip44_path_t* pathSpec);
#define BIP44_PRINTF(PATH) bip44_PRINTF(PATH)
#else
#define BIP44_PRINTF(PATH)
#endif // DEVEL

#endif // H_CARDANO_APP_BIP44
