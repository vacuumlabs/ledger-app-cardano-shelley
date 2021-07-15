#ifndef H_CARDANO_APP_CARDANO
#define H_CARDANO_APP_CARDANO

#include "common.h"
#include "bip44.h"

// Just a trick to make the numbers readable
#define __CONCAT4(A,B,C,D) A ## B ## C ## D

#define LOVELACE_MAX_SUPPLY (__CONCAT4(45, 000, 000, 000) * 1000000)
#define LOVELACE_INVALID    (__CONCAT4(47, 000, 000, 000) * 1000000)

STATIC_ASSERT(LOVELACE_MAX_SUPPLY < LOVELACE_INVALID, "bad LOVELACE_INVALID");

#define ADDRESS_KEY_HASH_LENGTH 28
#define POOL_KEY_HASH_LENGTH 28
#define VRF_KEY_HASH_LENGTH 32
#define TX_HASH_LENGTH 32
#define AUX_DATA_HASH_LENGTH 32
#define POOL_METADATA_HASH_LENGTH 32
#define CATALYST_REGISTRATION_PAYLOAD_HASH_LENGTH 32
#define ED25519_SIGNATURE_LENGTH 64
#define SCRIPT_HASH_LENGTH 28

#define MINTING_POLICY_ID_SIZE 28
#define ASSET_NAME_SIZE_MAX 32

#define REWARD_ACCOUNT_SIZE (1 + ADDRESS_KEY_HASH_LENGTH)

#define OP_CERT_BODY_LENGTH 48

// for Shelley, address is at most 1 + 28 + 28 = 57 bytes,
// encoded in bech32 as 10 (prefix) + 8/5 * 57 + 6 (checksum) = 108 chars
// reward accounts are just 1 + 28 = 29 bytes,
// so 10 + 8/5 * 29 + 6 = 65 chars at most

// for Byron, the address can contain 64B of data (according to Duncan),
// plus 46B with empty data; 100B in base58 has
// length at most 139
// (previously, we used 128 bytes)
// https://stackoverflow.com/questions/48333136/size-of-buffer-to-hold-base58-encoded-data
#define MAX_ADDRESS_SIZE 128
#define MAX_HUMAN_ADDRESS_SIZE 150
#define MAX_HUMAN_REWARD_ACCOUNT_SIZE 65

#define MAINNET_PROTOCOL_MAGIC 764824073
#define MAINNET_NETWORK_ID 1

#define TESTNET_NETWORK_ID 0


typedef enum {
	KEY_REFERENCE_PATH = 1,
	KEY_REFERENCE_HASH = 2,	//TODO KoMa KEY??? reference?
} key_reference_type_t;


typedef struct {
	key_reference_type_t keyReferenceType;
	union {
		bip44_path_t path;
		uint8_t hashBuffer[REWARD_ACCOUNT_SIZE];
	};
} reward_account_t;

void rewardAccountToBuffer(
        const reward_account_t* rewardAccount,
        uint8_t networkId,
        uint8_t* rewardAccountBuffer
);


// ==============================  OUTPUTS  ==============================

typedef struct {
	uint8_t policyId[MINTING_POLICY_ID_SIZE];
} token_group_t;

typedef struct {
	uint8_t assetNameBytes[ASSET_NAME_SIZE_MAX];
	size_t assetNameSize;
	uint64_t amount;
} output_token_amount_t;


// ==============================  CERTIFICATES  ==============================

#define POOL_METADATA_URL_LENGTH_MAX 64
#define DNS_NAME_SIZE_MAX 64

#define IPV4_SIZE 4
#define IPV6_SIZE 16

// see the calculation in ui_displayMarginScreen() in uiScreens.c
#define MARGIN_DENOMINATOR_MAX 1000000000000000ul // 10^15

// there may be other types we do not support
typedef enum {
	CERTIFICATE_TYPE_STAKE_REGISTRATION = 0,
	CERTIFICATE_TYPE_STAKE_DEREGISTRATION = 1,
	CERTIFICATE_TYPE_STAKE_DELEGATION = 2,
	CERTIFICATE_TYPE_STAKE_POOL_REGISTRATION = 3,
	CERTIFICATE_TYPE_STAKE_POOL_RETIREMENT = 4,
} certificate_type_t;

typedef enum {
	RELAY_SINGLE_HOST_IP = 0,
	RELAY_SINGLE_HOST_NAME = 1,
	RELAY_MULTIPLE_HOST_NAME = 2
} relay_format_t;

typedef struct {
	bool isNull;
	uint8_t ip[IPV4_SIZE];
} ipv4_t;

typedef struct {
	bool isNull;
	uint8_t ip[IPV6_SIZE];
} ipv6_t;

typedef struct {
	bool isNull;
	uint16_t number;
} ipport_t;

typedef struct {
	relay_format_t format;

	ipport_t port;

	ipv4_t ipv4;
	ipv6_t ipv6;

	size_t dnsNameSize;
	uint8_t dnsName[DNS_NAME_SIZE_MAX];
} pool_relay_t;


#endif // H_CARDANO_APP_CARDANO
