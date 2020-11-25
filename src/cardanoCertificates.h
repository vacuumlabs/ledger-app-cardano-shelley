#ifndef H_CARDANO_APP_CARDANO_CERTIFICATES
#define H_CARDANO_APP_CARDANO_CERTIFICATES

#include "cardano.h"

#define IPV4_SIZE 4
#define IPV6_SIZE 16

// there are other types we do not support
typedef enum {
	CERTIFICATE_TYPE_STAKE_REGISTRATION = 0,
	CERTIFICATE_TYPE_STAKE_DEREGISTRATION = 1,
	CERTIFICATE_TYPE_STAKE_DELEGATION = 2,
	CERTIFICATE_TYPE_STAKE_POOL_REGISTRATION = 3
} certificate_type_t;

typedef struct {
	uint8_t poolKeyHash[POOL_KEY_HASH_LENGTH];
	uint8_t vrfKeyHash[VRF_KEY_HASH_LENGTH];
	uint64_t pledge;
	uint64_t cost;
	uint64_t marginNumerator;
	uint64_t marginDenominator;
	uint8_t rewardAccount[1 + ADDRESS_KEY_HASH_LENGTH];
} pool_registration_params_t;

typedef struct {
	uint8_t ip[IPV4_SIZE];
} ipv4_t;

typedef struct {
	uint8_t ip[IPV6_SIZE];
} ipv6_t;

// see the calculation in ui_displayPoolMarginScreen() in uiScreens.c
#define MARGIN_DENOMINATOR_MAX 1000000000000000ul // 10^15

#define POOL_METADATA_URL_MAX_LENGTH 64
#define DNS_NAME_MAX_LENGTH 64

#endif // H_CARDANO_APP_CARDANO_CERTIFICATES