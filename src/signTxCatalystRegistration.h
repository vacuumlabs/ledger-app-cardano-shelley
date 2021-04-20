#ifndef H_CARDANO_APP_SIGN_TX_CATALYST_REGISTRATION
#define H_CARDANO_APP_SIGN_TX_CATALYST_REGISTRATION

#include "common.h"
#include "cardano.h"
#include "auxDataHashBuilder.h"
#include "addressUtilsShelley.h"


#define CATALYST_VOTING_PUBLIC_KEY_LENGTH 32

// SIGN_STAGE_AUX_DATA = 32
// AUX_DATA_TYPE_CATALYST_REGISTRATION = 1
typedef enum {
	STATE_CATALYST_REGISTRATION_VOTING_KEY = 3210,
	STATE_CATALYST_REGISTRATION_STAKING_KEY = 3211,
	STATE_CATALYST_REGISTRATION_VOTING_REWARDS_ADDRESS = 3212,
	STATE_CATALYST_REGISTRATION_NONCE = 3213,
	STATE_CATALYST_REGISTRATION_CONFIRM = 3214,
	STATE_CATALYST_REGISTRATION_FINISHED = 3215
} sign_tx_catalyst_registration_state_t;

typedef struct {
	sign_tx_catalyst_registration_state_t state;
	int ui_step;

	/*
	* Staking key path kept outside of stateData to produce the Catalyst registration
	* signature at the end of the flow without re-requesting the staking key path
	* (with the undesired side-effect of allowing signing with a different key than included
	* in the registration payload)
	*/
	bip44_path_t stakingKeyPath;
	uint8_t auxDataHash[AUX_DATA_HASH_LENGTH];

	union {
		uint8_t votingPubKey[CATALYST_VOTING_PUBLIC_KEY_LENGTH];
		addressParams_t votingRewardsAddressParams;
		uint64_t nonce;
		uint8_t registrationSignature[ED25519_SIGNATURE_LENGTH];
	} stateData;
} catalyst_registration_context_t;

void signTxCatalystRegistration_init();

bool signTxCatalystRegistration_isValidInstruction(uint8_t p2);
void signTxCatalystRegistration_handleAPDU(uint8_t p2, uint8_t* wireDataBuffer, size_t wireDataSize);

bool signTxCatalystRegistration_isFinished();

#endif // H_CARDANO_APP_SIGN_TX_CATALYST_REGISTRATION
