#ifndef H_CARDANO_APP_SIGN_TX_POOL_REGISTRATION
#define H_CARDANO_APP_SIGN_TX_POOL_REGISTRATION

#include "common.h"
#include "cardano.h"
#include "cardanoCertificates.h"
#include "txHashBuilder.h"

#define POOL_METADATA_URL_MAX_LENGTH 64

#define POOL_MAX_OWNERS 1000
#define POOL_MAX_RELAYS 1000

// SIGN_STAGE_CERTIFICATES = 28
// CERTIFICATE_TYPE_STAKE_POOL_REGISTRATION = 3
typedef enum {
	STAKE_POOL_REGISTRATION_PARAMS = 2830,
	STAKE_POOL_REGISTRATION_OWNERS = 2831,
	STAKE_POOL_REGISTRATION_RELAYS = 2832,
	STAKE_POOL_REGISTRATION_METADATA = 2833,
	STAKE_POOL_REGISTRATION_CONFIRM = 2834,
	STAKE_POOL_REGISTRATION_FINISHED = 2835
} sign_tx_pool_registration_state_t;

enum {
	SIGN_TX_POOL_OWNER_TYPE_PATH = 1,
	SIGN_TX_POOL_OWNER_TYPE_KEY_HASH = 2,
};

typedef struct {
	uint8_t url[POOL_METADATA_URL_MAX_LENGTH];
	size_t urlSize;
	uint8_t hash[METADATA_HASH_LENGTH];
} pool_metadata_t;

typedef struct {
	uint8_t ownerType;
	uint8_t keyHash[ADDRESS_KEY_HASH_LENGTH];
	bip44_path_t path;
} pool_owner_t;

typedef struct {
	sign_tx_pool_registration_state_t state;
	int ui_step;
	uint16_t currentOwner;
	uint16_t numOwnersGivenByPath;
	uint16_t currentRelay;

	uint16_t numOwners;
	uint16_t numRelays;

	pool_registration_params_t poolParams;

	union {
		pool_owner_t owner;
		pool_metadata_t metadata;
	};
} pool_registration_context_t;

void signTxPoolRegistration_init();

bool signTxPoolRegistration_isValidInstruction(uint8_t p2);
void signTxPoolRegistration_handleAPDU(uint8_t p2, uint8_t* wireDataBuffer, size_t wireDataSize);

bool signTxPoolRegistration_isFinished();

#endif
