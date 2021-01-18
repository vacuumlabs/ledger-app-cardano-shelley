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

// the use case significantly affects restrictions on tx being signed
typedef enum {
	SIGN_TX_USECASE_ORDINARY_TX = 3, // enum value 3 is needed for backwards compatibility
	SIGN_TX_USECASE_POOL_REGISTRATION_OWNER = 4,

	#ifdef POOL_OPERATOR_APP
	SIGN_TX_USECASE_POOL_REGISTRATION_OPERATOR = 5,
	#endif
} sign_tx_usecase_t;

typedef enum {
	SIGN_STAGE_NONE = 0,
	SIGN_STAGE_INIT = 23,
	SIGN_STAGE_INPUTS = 24,
	SIGN_STAGE_OUTPUTS = 25,
	SIGN_STAGE_OUTPUTS_SUBMACHINE = 26,
	SIGN_STAGE_FEE = 27,
	SIGN_STAGE_TTL = 28,
	SIGN_STAGE_CERTIFICATES = 29,
	SIGN_STAGE_CERTIFICATES_POOL = 30, // pool registration certificate sub-machine
	SIGN_STAGE_WITHDRAWALS = 31,
	SIGN_STAGE_METADATA = 32,
	SIGN_STAGE_VALIDITY_INTERVAL = 33,
	SIGN_STAGE_CONFIRM = 34,
	SIGN_STAGE_WITNESSES = 35,
} sign_tx_stage_t;

enum {
	SIGN_MAX_INPUTS = 1000,
	SIGN_MAX_OUTPUTS = 1000,
	SIGN_MAX_CERTIFICATES = 1000,
	SIGN_MAX_REWARD_WITHDRAWALS = 1000
};

typedef struct {
	// significantly affects restrictions on the tx
	sign_tx_usecase_t signTxUsecase;

	uint8_t networkId; // part of Shelley address
	uint32_t protocolMagic; // part of Byron address
} common_tx_data_t;

typedef struct {
	certificate_type_t type;
	bip44_path_t pathSpec; // interpretation depends on type

	// only for specific types
	uint8_t poolKeyHash[POOL_KEY_HASH_LENGTH];
	uint64_t epoch;
} sign_tx_certificate_data_t;

typedef struct {
	bip44_path_t path;
	uint64_t amount;
} sign_tx_withdrawal_data_t;

typedef struct {
	uint8_t metadataHash[METADATA_HASH_LENGTH];
} sign_tx_metadata_data_t;

typedef struct {
	bip44_path_t path;
	uint8_t signature[64];
} sign_tx_witness_data_t;

typedef struct {
	sign_tx_stage_t stage;

	uint16_t numInputs;
	uint16_t numOutputs;
	bool includeTtl;
	uint16_t numCertificates;
	uint16_t numWithdrawals; // reward withdrawals
	bool includeMetadata;
	bool includeValidityIntervalStart;
	uint16_t numWitnesses;

	uint16_t currentInput;
	uint16_t currentOutput;
	uint16_t currentCertificate;
	uint16_t currentWithdrawal;
	uint16_t currentWitness;

	bool feeReceived;
	bool ttlReceived;
	bool metadataReceived;
	bool validityIntervalStartReceived;

	// TODO move these to commonTxData?
	tx_hash_builder_t txHashBuilder;
	uint8_t txHash[TX_HASH_LENGTH];

	common_tx_data_t commonTxData;

	// this holds data valid only through the processing of a single APDU
	union {
		uint64_t fee;
		uint64_t ttl;
		sign_tx_certificate_data_t certificate;
		sign_tx_withdrawal_data_t withdrawal;
		sign_tx_metadata_data_t metadata;
		uint64_t validityIntervalStart;
		sign_tx_witness_data_t witness;
	} stageData;

	union {
		pool_registration_context_t pool_registration_subctx;
		output_context_t output_subctx;
	} stageContext;

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
