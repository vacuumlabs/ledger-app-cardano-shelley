#ifndef H_CARDANO_APP_SIGN_TX
#define H_CARDANO_APP_SIGN_TX

#include "common.h"
#include "hash.h"
#include "handlers.h"
#include "txHashBuilder.h"
#include "bip44.h"
#include "addressUtilsShelley.h"
#include "signTxTypes.h"
#include "signTxPoolRegistration.h"

typedef enum {
	SIGN_STAGE_NONE = 0,
	SIGN_STAGE_INIT = 23,
	SIGN_STAGE_INPUTS = 24,
	SIGN_STAGE_OUTPUTS = 25,
	SIGN_STAGE_FEE = 26,
	SIGN_STAGE_TTL = 27,
	SIGN_STAGE_CERTIFICATES = 28,
	SIGN_STAGE_CERTIFICATES_POOL = 29, // pool registration certificate sub-machine
	SIGN_STAGE_WITHDRAWALS = 30,
	SIGN_STAGE_METADATA = 31,
	SIGN_STAGE_CONFIRM = 32,
	SIGN_STAGE_WITNESSES = 33,
} sign_tx_stage_t;

enum {
	SIGN_MAX_INPUTS = 1000,
	SIGN_MAX_OUTPUTS = 1000,
	SIGN_MAX_CERTIFICATES = 1000,
	SIGN_MAX_REWARD_WITHDRAWALS = 1000
};

typedef struct {
	uint8_t networkId; // part of Shelley address
	uint32_t protocolMagic; // part of Byron address
} common_tx_data_t;

typedef struct {
	uint64_t amount;
	uint8_t addressBuffer[MAX_ADDRESS_SIZE];
	size_t addressSize;

	uint8_t outputType;
	addressParams_t params;
} sign_tx_output_data_t;

typedef struct {
	certificate_type_t type;
	bip44_path_t keyPath;
	// only for specific types
	uint8_t poolKeyHash[POOL_KEY_HASH_LENGTH];
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

	// significantly affects restrictions on the tx
	sign_tx_usecase_t signTxUsecase;

	uint16_t numInputs;
	uint16_t numOutputs;
	uint16_t numCertificates;
	uint16_t numWithdrawals; // reward withdrawals
	uint16_t numWitnesses;
	bool includeMetadata;

	uint16_t currentInput;
	uint16_t currentOutput;
	uint16_t currentCertificate;
	uint16_t currentWithdrawal;
	uint16_t currentWitness;

	bool feeReceived;
	bool ttlReceived;

	tx_hash_builder_t txHashBuilder;
	uint8_t txHash[TX_HASH_LENGTH];

	common_tx_data_t commonTxData;

	union {
		sign_tx_output_data_t output;
		uint64_t fee;
		uint64_t ttl;
		sign_tx_certificate_data_t certificate;
		sign_tx_withdrawal_data_t withdrawal;
		sign_tx_metadata_data_t metadata;
		sign_tx_witness_data_t witness;
	} stageData;

	union {
		pool_registration_context_t pool_registration_subctx;
	} stageContext;

	int ui_step;
} ins_sign_tx_context_t;

handler_fn_t signTx_handleAPDU;

#endif
