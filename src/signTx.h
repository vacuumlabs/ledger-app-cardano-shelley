#ifndef H_CARDANO_APP_SIGN_TX
#define H_CARDANO_APP_SIGN_TX

#include "common.h"
#include "hash.h"
#include "handlers.h"
#include "txHashBuilder.h"
#include "bip44.h"
#include "addressUtilsShelley.h"
#include "signTxOutput.h"
#include "signTxPoolRegistration.h"
#include "signTxCatalystRegistration.h"
#include "auxData.h"

typedef enum {
	SIGN_STAGE_NONE = 0,
	SIGN_STAGE_INIT = 23,
	SIGN_STAGE_AUX_DATA = 24,
	SIGN_STAGE_AUX_DATA_CATALYST_REGISTRATION_SUBMACHINE = 25,
	SIGN_STAGE_BODY_INPUTS = 26,
	SIGN_STAGE_BODY_OUTPUTS = 27,
	SIGN_STAGE_BODY_OUTPUTS_SUBMACHINE = 28,
	SIGN_STAGE_BODY_FEE = 29,
	SIGN_STAGE_BODY_TTL = 30,
	SIGN_STAGE_BODY_CERTIFICATES = 31,
	SIGN_STAGE_BODY_CERTIFICATES_POOL = 32, // pool registration certificate sub-machine
	SIGN_STAGE_BODY_WITHDRAWALS = 33,
	SIGN_STAGE_BODY_VALIDITY_INTERVAL = 34,
	SIGN_STAGE_CONFIRM = 35,
	SIGN_STAGE_WITNESSES = 36,
} sign_tx_stage_t;

enum {
	SIGN_MAX_INPUTS = 1000,
	SIGN_MAX_OUTPUTS = 1000,
	SIGN_MAX_CERTIFICATES = 1000,
	SIGN_MAX_REWARD_WITHDRAWALS = 1000
};

typedef struct {
	// the presence of a stake pool registration certificate
	// significantly affects restrictions on the whole tx
	bool isSigningPoolRegistrationAsOwner;

	uint8_t networkId; // part of Shelley address
	uint32_t protocolMagic; // part of Byron address
} common_tx_data_t;

typedef struct {
	certificate_type_t type;
	bip44_path_t keyPath;
	// only for specific types
	uint8_t poolKeyHash[POOL_KEY_HASH_LENGTH];
} sign_tx_certificate_data_t;

typedef struct {
	bip44_path_t path;
	uint8_t signature[64];
} sign_tx_witness_data_t;

typedef struct {
	bip44_path_t path;
	uint64_t amount;
} sign_tx_withdrawal_data_t;

typedef struct {
	uint16_t currentInput;
	uint16_t currentOutput;
	uint16_t currentCertificate;
	uint16_t currentWithdrawal;

	bool feeReceived;
	bool ttlReceived;
	bool validityIntervalStartReceived;

	tx_hash_builder_t txHashBuilder;

	union {
		uint64_t fee;
		uint64_t ttl;
		sign_tx_certificate_data_t certificate;
		sign_tx_withdrawal_data_t withdrawal;
		uint64_t validityIntervalStart;
	} stageData;

	union {
		pool_registration_context_t pool_registration_subctx;
		output_context_t output_subctx;
	} stageContext;
} ins_sign_tx_body_context_t;

typedef struct {
	uint16_t currentWitness;
	struct {
		sign_tx_witness_data_t witness;
	} stageData;
} ins_sign_tx_witnesses_context_t;

typedef struct {
	aux_data_type_t auxDataType;
	aux_data_hash_builder_t auxDataHashBuilder;
	bool auxDataReceived;

	struct {
		catalyst_registration_context_t catalyst_registration_subctx;
	} stageContext;
} ins_sign_tx_aux_data_context_t;

typedef struct {
	sign_tx_stage_t stage;

	common_tx_data_t commonTxData;

	uint16_t numInputs;
	uint16_t numOutputs;
	bool includeTtl;
	uint16_t numCertificates;
	uint16_t numWithdrawals; // reward withdrawals
	bool includeValidityIntervalStart;
	uint16_t numWitnesses;
	bool includeAuxData;

	uint8_t auxDataHash[AUX_DATA_HASH_LENGTH];
	uint8_t txHash[TX_HASH_LENGTH];

	union {
		ins_sign_tx_aux_data_context_t aux_data_ctx;
		ins_sign_tx_body_context_t body_ctx;
		ins_sign_tx_witnesses_context_t witnesses_ctx;
	} txPartCtx;

	int ui_step;
} ins_sign_tx_context_t;

handler_fn_t signTx_handleAPDU;

enum {
	SIGN_TX_INCLUDED_NO = 1,
	SIGN_TX_INCLUDED_YES = 2
};

inline bool signTx_parseIncluded(uint8_t value)
{
	switch (value) {
	case SIGN_TX_INCLUDED_YES:
		return true;

	case SIGN_TX_INCLUDED_NO:
		return false;

	default:
		THROW(ERR_INVALID_DATA);
	}
}

#endif // H_CARDANO_APP_SIGN_TX
