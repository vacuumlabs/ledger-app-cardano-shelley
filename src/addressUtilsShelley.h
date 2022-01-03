#ifndef H_CARDANO_APP_ADDRESS_UTILS_SHELLEY
#define H_CARDANO_APP_ADDRESS_UTILS_SHELLEY

#include "common.h"
#include "cardano.h"
#include "bip44.h"
#include "bufView.h"

typedef enum {
	// base address contains explicit payment info (key hash / script hash)
	// and explicit staking info
	BASE_PAYMENT_KEY_STAKE_KEY          = 0b0000,
	BASE_PAYMENT_SCRIPT_STAKE_KEY       = 0b0001,
	BASE_PAYMENT_KEY_STAKE_SCRIPT       = 0b0010,
	BASE_PAYMENT_SCRIPT_STAKE_SCRIPT    = 0b0011,

	// pointer address contains explicit payment info and a pointer to blockchain for staking info
	POINTER_KEY                         = 0b0100,
	POINTER_SCRIPT                      = 0b0101,

	// enterprise address contains explicit payment info and no staking info
	ENTERPRISE_KEY                      = 0b0110,
	ENTERPRISE_SCRIPT                   = 0b0111,

	// legacy addresses, aka bootstrap addresses
	BYRON                               = 0b1000,

	// reward address (aka reward account) contains only staking info
	REWARD_KEY                          = 0b1110,
	REWARD_SCRIPT                       = 0b1111,
} address_type_t;

uint8_t getAddressHeader(const uint8_t* addressBuffer, size_t addressSize);

address_type_t getAddressType(uint8_t addressHeader);
bool isSupportedAddressType(uint8_t addressHeader);
bool isShelleyAddressType(uint8_t addressType);
uint8_t constructShelleyAddressHeader(address_type_t type, uint8_t networkId);

uint8_t getNetworkId(uint8_t addressHeader);
bool isValidNetworkId(uint8_t networkId);


// describes which staking info should be incorporated into address
// (see stakingDataSource in addressParams_t)
typedef enum {
	NO_STAKING = 0x11,
	STAKING_KEY_PATH = 0x22,
	STAKING_KEY_HASH = 0x33,
	BLOCKCHAIN_POINTER = 0x44,
	STAKING_SCRIPT_HASH = 0x55,
} staking_data_source_t;

bool isValidStakingChoice(staking_data_source_t stakingDataSource);

typedef enum {
	SPENDING_PATH,
	SPENDING_SCRIPT_HASH,
	SPENDING_NONE,
} spending_choice_t;

typedef uint32_t blockchainIndex_t; // must be unsigned

typedef struct {
	blockchainIndex_t blockIndex;
	blockchainIndex_t txIndex;
	blockchainIndex_t certificateIndex;
} blockchainPointer_t;

typedef struct {
	address_type_t type;
	union {
		uint32_t protocolMagic; // if type == BYRON
		uint8_t networkId; // all the other types (i.e. Shelley)
	};
	union {
		bip44_path_t spendingKeyPath;
		uint8_t spendingScriptHash[SCRIPT_HASH_LENGTH];
	};
	staking_data_source_t stakingDataSource;
	union {
		bip44_path_t stakingKeyPath;
		uint8_t stakingKeyHash[ADDRESS_KEY_HASH_LENGTH];
		blockchainPointer_t stakingKeyBlockchainPointer;
		uint8_t stakingScriptHash[SCRIPT_HASH_LENGTH];
	};
} addressParams_t;

bool isStakingInfoConsistentWithAddressType(const addressParams_t* addressParams);
staking_data_source_t determineStakingChoice(address_type_t addressType);

size_t deriveAddress(const addressParams_t* addressParams, uint8_t* outBuffer, size_t outSize);

__noinline_due_to_stack__
size_t constructRewardAddressFromKeyPath(
        const bip44_path_t* path, uint8_t networkId, uint8_t* outBuffer, size_t outSize
);

typedef enum {
	REWARD_HASH_SOURCE_KEY,
	REWARD_HASH_SOURCE_SCRIPT,
} reward_address_hash_source_t;

__noinline_due_to_stack__
size_t constructRewardAddressFromHash(
        uint8_t networkId,
        reward_address_hash_source_t source,
        const uint8_t* hashBuffer, size_t hashSize,
        uint8_t* outBuffer, size_t outSize
);

void printBlockchainPointerToStr(blockchainPointer_t blockchainPointer, char* out, size_t outSize);

size_t humanReadableAddress(const uint8_t* address, size_t addressSize, char* out, size_t outSize);

void view_parseAddressParams(read_view_t* view, addressParams_t* params);

bool isValidAddressParams(const addressParams_t* addressParams);
spending_choice_t determineSpendingChoice(address_type_t addressType);

#ifdef DEVEL
void run_addressUtilsShelley_test();
#endif // DEVEL

#endif // H_CARDANO_APP_ADDRESS_UTILS_SHELLEY
