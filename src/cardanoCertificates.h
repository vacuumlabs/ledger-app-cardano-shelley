#ifndef H_CARDANO_APP_CARDANO_CERTIFICATES
#define H_CARDANO_APP_CARDANO_CERTIFICATES

#include "cardano.h"

// there are other types we do not support
enum {
	CERTIFICATE_TYPE_STAKE_REGISTRATION = 0,
	CERTIFICATE_TYPE_STAKE_DEREGISTRATION = 1,
	CERTIFICATE_TYPE_STAKE_DELEGATION = 2,
	CERTIFICATE_TYPE_STAKE_POOL_REGISTRATION = 3
};

typedef struct {
	uint8_t operatorHash[POOL_KEY_HASH_LENGTH];
	uint8_t vrfKeyHash[VRF_KEY_HASH_LENGTH];
	uint64_t pledge;
	uint64_t cost;
	uint64_t marginNumerator;
	uint64_t marginDenominator;
	uint8_t rewardAccount[1 + ADDRESS_KEY_HASH_LENGTH];
} pool_registration_params_t;

// see the calculation in ui_displayMarginScreen() in uiScreens.c
#define MARGIN_DENOMINATOR_MAX 1000000000000000ul // 10^15

#endif // H_CARDANO_APP_CARDANO_CERTIFICATES