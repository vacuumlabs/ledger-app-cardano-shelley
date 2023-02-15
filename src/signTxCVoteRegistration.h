#ifndef H_CARDANO_APP_SIGN_TX_CVOTE_REGISTRATION
#define H_CARDANO_APP_SIGN_TX_CVOTE_REGISTRATION

#include "common.h"
#include "cardano.h"
#include "auxDataHashBuilder.h"
#include "txHashBuilder.h"
#include "addressUtilsShelley.h"


#define CVOTE_PUBLIC_KEY_LENGTH 32

// SIGN_STAGE_AUX_DATA = 24
// AUX_DATA_TYPE_CVOTE_REGISTRATION = 1
typedef enum {
	STATE_CVOTE_REGISTRATION_INIT = 2410,
	STATE_CVOTE_REGISTRATION_VOTE_KEY = 2411,
	STATE_CVOTE_REGISTRATION_DELEGATIONS = 2412,
	STATE_CVOTE_REGISTRATION_STAKING_KEY = 2413,
	STATE_CVOTE_REGISTRATION_PAYMENT_ADDRESS = 2414,
	STATE_CVOTE_REGISTRATION_NONCE = 2415,
	STATE_CVOTE_REGISTRATION_VOTING_PURPOSE = 2416,
	STATE_CVOTE_REGISTRATION_CONFIRM = 2417,
	STATE_CVOTE_REGISTRATION_FINISHED = 2418
} sign_tx_cvote_registration_state_t;

typedef enum {
	DELEGATION_KEY = 1,
	DELEGATION_PATH = 2
} cvote_delegation_type_t;

typedef struct {
	sign_tx_cvote_registration_state_t state;
	int ui_step;

	cvote_registration_format_t format;
	uint16_t numDelegations; // if 0, only a single key expected, no delegations
	uint16_t currentDelegation;
	/*
	* Staking key path kept outside of stateData to produce the CIP-36 voting registration
	* signature at the end of the flow without re-requesting the staking key path
	* (with the undesired side-effect of allowing signing with a different key than included
	* in the registration payload)
	*/
	bip44_path_t stakingKeyPath;

	uint8_t auxDataHash[AUX_DATA_HASH_LENGTH];

	union {
		struct {
			cvote_delegation_type_t type;
			bip44_path_t votePubKeyPath;
			uint8_t votePubKey[CVOTE_PUBLIC_KEY_LENGTH];
			uint32_t weight;
		} delegation;
		tx_output_destination_storage_t paymentDestination;
		uint64_t nonce;
		uint64_t votingPurpose;
		uint8_t registrationSignature[ED25519_SIGNATURE_LENGTH];
	} stateData;
} cvote_registration_context_t;

void signTxCVoteRegistration_init();

bool signTxCVoteRegistration_isValidInstruction(uint8_t p2);
void signTxCVoteRegistration_handleAPDU(uint8_t p2, const uint8_t* wireDataBuffer, size_t wireDataSize);

bool signTxCVoteRegistration_isFinished();

#endif // H_CARDANO_APP_SIGN_TX_CVOTE_REGISTRATION
