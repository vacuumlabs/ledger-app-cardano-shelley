#ifndef H_CARDANO_APP_CARDANO
#define H_CARDANO_APP_CARDANO

#include "common.h"

// Just a trick to make the numbers readable
#define __CONCAT4(A,B,C,D) A ## B ## C ## D

#define LOVELACE_MAX_SUPPLY (__CONCAT4(45, 000, 000, 000) * 1000000)
#define LOVELACE_INVALID    (__CONCAT4(47, 000, 000, 000) * 1000000)

STATIC_ASSERT(LOVELACE_MAX_SUPPLY < LOVELACE_INVALID, "bad LOVELACE_INVALID");

#define ADDRESS_KEY_HASH_LENGTH 28
#define POOL_KEY_HASH_LENGTH 28
#define VRF_KEY_HASH_LENGTH 32
#define TX_HASH_LENGTH 32
#define METADATA_HASH_LENGTH 32

#define MINTING_POLICY_ID_SIZE 28
#define ASSET_NAME_SIZE_MAX 32

#define REWARD_ACCOUNT_SIZE (1 + ADDRESS_KEY_HASH_LENGTH)

// for Shelley, address is at most 1 + 28 + 28 = 57 bytes,
// encoded in bech32 as 10 (prefix) + 8/5 * 57 + 6 (checksum) = 108 chars

// for Byron, the address can contain 64B of data (according to Duncan),
// plus 46B with empty data; 100B in base58 has
// length at most 139
// (previously, we used 128 bytes)
// https://stackoverflow.com/questions/48333136/size-of-buffer-to-hold-base58-encoded-data
#define MAX_ADDRESS_SIZE 128
#define MAX_HUMAN_ADDRESS_SIZE 150

#define MAINNET_PROTOCOL_MAGIC 764824073
#define MAINNET_NETWORK_ID 1

#define TESTNET_NETWORK_ID 0

#endif // H_CARDANO_APP_CARDANO
