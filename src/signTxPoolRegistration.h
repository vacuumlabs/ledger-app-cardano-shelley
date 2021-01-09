#ifndef H_CARDANO_APP_SIGN_TX_POOL_REGISTRATION
#define H_CARDANO_APP_SIGN_TX_POOL_REGISTRATION

#include "common.h"
#include "cardano.h"
#include "cardanoCertificates.h"
#include "txHashBuilder.h"

#define POOL_MAX_OWNERS 1000
#define POOL_MAX_RELAYS 1000

// SIGN_STAGE_CERTIFICATES = 28
// CERTIFICATE_TYPE_STAKE_POOL_REGISTRATION = 3
typedef enum {
	STAKE_POOL_REGISTRATION_INIT = 2830,
	STAKE_POOL_REGISTRATION_POOL_KEY = 2831,
	STAKE_POOL_REGISTRATION_VRF_KEY = 2832,
	STAKE_POOL_REGISTRATION_FINANCIALS = 2833,
	STAKE_POOL_REGISTRATION_REWARD_ACCOUNT = 2834,
	STAKE_POOL_REGISTRATION_OWNERS = 2835,
	STAKE_POOL_REGISTRATION_RELAYS = 2836,
	STAKE_POOL_REGISTRATION_METADATA = 2837,
	STAKE_POOL_REGISTRATION_CONFIRM = 2838,
	STAKE_POOL_REGISTRATION_FINISHED = 2839,
} sign_tx_pool_registration_state_t;

typedef struct {
	data_description_kind_t descriptionKind;
	uint8_t hash[POOL_KEY_HASH_LENGTH];
	bip44_path_t path;
} pool_id_t;

typedef struct {
	data_description_kind_t descriptionKind;
	uint8_t buffer[REWARD_ACCOUNT_SIZE];
	bip44_path_t path;
} pool_reward_account_t;

typedef struct {
	data_description_kind_t descriptionKind;
	uint8_t keyHash[ADDRESS_KEY_HASH_LENGTH];
	bip44_path_t path;
} pool_owner_t;

typedef struct {
	uint8_t url[POOL_METADATA_URL_MAX_LENGTH];
	size_t urlSize;
	uint8_t hash[METADATA_HASH_LENGTH];
} pool_metadata_t;


typedef struct {
	sign_tx_pool_registration_state_t state;

	int ui_step;

	uint16_t currentOwner;
	uint16_t numOwnersGivenByPath;
	uint16_t currentRelay;

	uint16_t numOwners;
	uint16_t numRelays;

	union {
		pool_id_t poolId;
		uint8_t vrfKeyHash[VRF_KEY_HASH_LENGTH];
		struct {
			uint64_t pledge;
			uint64_t cost;
			uint64_t marginNumerator;
			uint64_t marginDenominator;
		};
		pool_reward_account_t poolRewardAccount;
		pool_owner_t owner;
		pool_metadata_t metadata;
	} stateData;
} pool_registration_context_t;


void signTxPoolRegistration_init();

bool signTxPoolRegistration_isValidInstruction(uint8_t p2);
void signTxPoolRegistration_handleAPDU(uint8_t p2, uint8_t* wireDataBuffer, size_t wireDataSize);

bool signTxPoolRegistration_isFinished();

#endif // H_CARDANO_APP_SIGN_TX_POOL_REGISTRATION
