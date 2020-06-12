#ifndef H_CARDANO_APP_ADDRESS_UTILS_SHELLEY
#define H_CARDANO_APP_ADDRESS_UTILS_SHELLEY

#include "common.h"
#include "bip44.h"

#define PUBLIC_KEY_HASH_LENGTH 28

// A list of supported address types.
enum {
	BASE = 0b0000 << 4,        // 0x0
	POINTER = 0b0100 << 4,     // 0x4
	ENTERPRISE = 0b0110 << 4,  // 0x6
	BYRON = 0b1000 << 4,       // 0x8
	REWARD = 0b1110 << 4,      // 0xE
};

typedef uint32_t certificateIndex_t; // must be unsigned

typedef struct {
        certificateIndex_t blockIndex;
        certificateIndex_t txIndex;
        certificateIndex_t certificateIndex;
} certificatePointer_t;

uint8_t getAddressType(uint8_t addressHeader);
uint8_t getNetworkId(uint8_t addressHeader);
bool isSupportedAddressType(uint8_t addressHeader);

size_t deriveAddress_base_accountStakingKey(
        uint8_t addressHeader, const bip44_path_t* pathSpec,
        uint8_t* outBuffer, size_t outSize
);
size_t deriveAddress_base_foreignStakingKey(
        uint8_t addressHeader, const bip44_path_t* pathSpec,
        uint8_t* stakingKeyHash,
        uint8_t* outBuffer, size_t outSize
);

size_t deriveAddress_pointer(
        uint8_t addressHeader, const bip44_path_t* pathSpec,
        const certificatePointer_t* stakingKeyPointer,
        uint8_t* outBuffer, size_t outSize
);

size_t deriveAddress_enterprise(
        uint8_t addressHeader, const bip44_path_t* pathSpec,
        uint8_t* outBuffer, size_t outSize
);

size_t deriveAddress_byron(
        uint8_t addressHeader, const bip44_path_t* pathSpec,
        uint8_t* outBuffer, size_t outSize
);

size_t deriveAddress_reward(
        uint8_t addressHeader, const bip44_path_t* pathSpec,
        uint8_t* outBuffer, size_t outSize
);

void run_addressUtilsShelley_test();

#endif
