#ifndef H_CARDANO_APP_ADDRESS_UTILS_SHELLEY
#define H_CARDANO_APP_ADDRESS_UTILS_SHELLEY

#include "common.h"
#include "cardano.h"
#include "bip44.h"
#include "bufView.h"

// supported address types
// (we avoid all types related to scripts) NOT ANYMORE, BABY!
typedef enum {
	BASE_STAKE_KEY_PAYMENT_KEY 			= 0b0000,
	BASE_STAKE_KEY_PAYMENT_SCRIPT 		= 0b0001,
	BASE_STAKE_SCRIPT_PAYMENT_KEY 		= 0b0010,
	BASE_STAKE_SCRIPT_PAYMENT_SCRIPT 	= 0b0011,
	POINTER_KEY							= 0b0100,
	POINTER_SCRIPT						= 0b0101,
	ENTERPRISE_KEY						= 0b0110,
	ENTERPRISE_SCRIPT					= 0b0111,
	BYRON								= 0b1000,
	REWARD_KEY							= 0b1110,
	REWARD_SCRIPT						= 0b1111,

	BASE       = 0b0000,  // 0x0
	POINTER    = 0b0100,  // 0x4
	ENTERPRISE = 0b0110,  // 0x6
	// BYRON      = 0b1000,  // 0x8
	REWARD     = 0b1110,  // 0xE
	MULTISIG   = 0b1111,  // 0xF TODO
} address_type_t;

uint8_t getAddressHeader(uint8_t* addressBuffer, size_t addressSize);

address_type_t getAddressType(uint8_t addressHeader);
bool isSupportedAddressType(uint8_t addressHeader);
bool isShelleyAddressType(uint8_t addressType);
uint8_t constructShelleyAddressHeader(address_type_t type, uint8_t networkId);

uint8_t getNetworkId(uint8_t addressHeader);
bool isValidNetworkId(uint8_t networkId);


// describes which staking info should be incorporated into address
// (see stakingChoice in addressParams_t)
typedef enum {
	NO_STAKING = 0x11,
	STAKING_KEY_PATH = 0x22,
	STAKING_KEY_HASH = 0x33,
	BLOCKCHAIN_POINTER = 0x44
} staking_choice_t;

bool isValidStakingChoice(staking_choice_t stakingChoice);


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
	bip44_path_t spendingKeyPath;
	staking_choice_t stakingChoice;
	union {
		bip44_path_t stakingKeyPath;
		uint8_t stakingKeyHash[ADDRESS_KEY_HASH_LENGTH];
		blockchainPointer_t stakingKeyBlockchainPointer;
	};
} addressParams_t;

bool isStakingInfoConsistentWithAddressType(const addressParams_t* addressParams);

size_t deriveAddress(const addressParams_t* addressParams, uint8_t* outBuffer, size_t outSize);

__noinline_due_to_stack__
size_t constructRewardAddressFromKeyPath(
        const bip44_path_t* path, uint8_t networkId, uint8_t* outBuffer, size_t outSize
);
__noinline_due_to_stack__
size_t constructRewardAddressFromKeyHash(
        uint8_t networkId,
        const uint8_t* stakingKeyHashBuffer, size_t stakingKeyHashSize,
        uint8_t* outBuffer, size_t outSize
);

void printBlockchainPointerToStr(blockchainPointer_t blockchainPointer, char* out, size_t outSize);

size_t humanReadableAddress(const uint8_t* address, size_t addressSize, char* out, size_t outSize);

void view_parseAddressParams(read_view_t* view, addressParams_t* params);

bool isValidAddressParams(const addressParams_t* addressParams);

#ifdef DEVEL
void run_addressUtilsShelley_test();
#endif // DEVEL

#endif // H_CARDANO_APP_ADDRESS_UTILS_SHELLEY
