#ifndef H_CARDANO_APP_SIGN_TX_GOVERNANCE_VOTING_REGISTRATION
#define H_CARDANO_APP_SIGN_TX_GOVERNANCE_VOTING_REGISTRATION

#include "common.h"
#include "cardano.h"
#include "auxDataHashBuilder.h"
#include "addressUtilsShelley.h"


#define GOVERNANCE_VOTING_PUBLIC_KEY_LENGTH 32

// SIGN_STAGE_AUX_DATA = 24
// AUX_DATA_TYPE_GOVERNANCE_VOTING_REGISTRATION = 1
typedef enum {
	STATE_GOVERNANCE_VOTING_REGISTRATION_VOTING_KEY = 2410,
	STATE_GOVERNANCE_VOTING_REGISTRATION_STAKING_KEY = 2411,
	STATE_GOVERNANCE_VOTING_REGISTRATION_VOTING_REWARDS_ADDRESS = 2412,
	STATE_GOVERNANCE_VOTING_REGISTRATION_NONCE = 2413,
	STATE_GOVERNANCE_VOTING_REGISTRATION_CONFIRM = 2414,
	STATE_GOVERNANCE_VOTING_REGISTRATION_FINISHED = 2415
} sign_tx_governance_voting_registration_state_t;

typedef struct {
	sign_tx_governance_voting_registration_state_t state;
	int ui_step;

	/*
	* Staking key path kept outside of stateData to produce the governance voting registration
	* signature at the end of the flow without re-requesting the staking key path
	* (with the undesired side-effect of allowing signing with a different key than included
	* in the registration payload)
	*/
	bip44_path_t stakingKeyPath;
	uint8_t auxDataHash[AUX_DATA_HASH_LENGTH];

	union {
		uint8_t votingPubKey[GOVERNANCE_VOTING_PUBLIC_KEY_LENGTH];
		addressParams_t votingRewardsAddressParams;
		uint64_t nonce;
		uint8_t registrationSignature[ED25519_SIGNATURE_LENGTH];
	} stateData;
} governance_voting_registration_context_t;

void signTxGovernanceVotingRegistration_init();

bool signTxGovernanceVotingRegistration_isValidInstruction(uint8_t p2);
void signTxGovernanceVotingRegistration_handleAPDU(uint8_t p2, const uint8_t* wireDataBuffer, size_t wireDataSize);

bool signTxGovernanceVotingRegistration_isFinished();

#endif // H_CARDANO_APP_SIGN_TX_GOVERNANCE_VOTING_REGISTRATION
