#ifndef H_CARDANO_APP_SIGN_TX
#define H_CARDANO_APP_SIGN_TX

#include "common.h"
#include "hash.h"
#include "handlers.h"
#include "txHashBuilder.h"
#include "bip44.h"
#include "addressUtilsShelley.h"
#include "signTxMint.h"
#include "signTxOutput.h"
#include "signTxPoolRegistration.h"
#include "signTxCatalystRegistration.h"
#include "signTxAuxData.h"

// the signing mode significantly affects restrictions on tx being signed
typedef enum {
	SIGN_TX_SIGNINGMODE_ORDINARY_TX = 3, // enum value 3 is needed for backwards compatibility
	SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OWNER = 4,
	SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OPERATOR = 5,
	SIGN_TX_SIGNINGMODE_MULTISIG_TX = 6,
} sign_tx_signingmode_t;

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
	SIGN_STAGE_BODY_CERTIFICATES_POOL_SUBMACHINE = 32, // pool registration certificate sub-machine
	SIGN_STAGE_BODY_WITHDRAWALS = 33,
	SIGN_STAGE_BODY_VALIDITY_INTERVAL = 34,
	SIGN_STAGE_BODY_MINT = 35,
	SIGN_STAGE_BODY_MINT_SUBMACHINE = 36,
	SIGN_STAGE_BODY_SCRIPT_DATA_HASH = 37,
	SIGN_STAGE_BODY_COLLATERALS = 38,
	SIGN_STAGE_CONFIRM = 40,
	SIGN_STAGE_WITNESSES = 41,
} sign_tx_stage_t;

enum {
	SIGN_MAX_INPUTS = UINT16_MAX,
	SIGN_MAX_OUTPUTS = UINT16_MAX,
	SIGN_MAX_CERTIFICATES = UINT16_MAX,
	SIGN_MAX_REWARD_WITHDRAWALS = UINT16_MAX,
	SIGN_MAX_COLLATERALS = UINT16_MAX,
	SIGN_MAX_WITNESSES = SIGN_MAX_INPUTS + SIGN_MAX_OUTPUTS + SIGN_MAX_CERTIFICATES + SIGN_MAX_REWARD_WITHDRAWALS,
};

typedef struct {
	bool isStored;
	bool isByron;
	uint32_t accountNumber;
} single_account_data_t;

typedef struct {
	// significantly affects restrictions on the tx
	sign_tx_signingmode_t txSigningMode;

	uint8_t networkId; // part of Shelley address
	uint32_t protocolMagic; // part of Byron address

	single_account_data_t singleAccountData;
} common_tx_data_t;

typedef struct {
	stake_credential_type_t type;
	union {
		bip44_path_t keyPath;
		uint8_t scriptHash[SCRIPT_HASH_LENGTH];
	};
} stake_credential_t;

typedef struct {
	certificate_type_t type;

	union {
		stake_credential_t stakeCredential;
		bip44_path_t poolIdPath;
	};
	uint64_t epoch;
	uint8_t poolKeyHash[POOL_KEY_HASH_LENGTH];

} sign_tx_certificate_data_t;

typedef struct {
	uint8_t txHashBuffer[TX_HASH_LENGTH];
	uint32_t parsedIndex;
} sign_tx_transaction_input_t;

typedef struct {
	bip44_path_t path;
	uint8_t signature[64];
} sign_tx_witness_data_t;

typedef struct {
	stake_credential_t stakeCredential;
	uint64_t amount;
	uint8_t previousRewardAccount[REWARD_ACCOUNT_SIZE];
} sign_tx_withdrawal_data_t;

typedef struct {
	bool auxDataReceived;
	aux_data_type_t auxDataType;
	aux_data_hash_builder_t auxDataHashBuilder;

	struct {
		catalyst_registration_context_t catalyst_registration_subctx;
	} stageContext;
} ins_sign_tx_aux_data_context_t;

typedef struct {
	uint16_t currentInput;
	uint16_t currentOutput;
	uint16_t currentCertificate;
	uint16_t currentWithdrawal;
	uint16_t currentCollateral;

	bool feeReceived;
	bool ttlReceived;
	bool validityIntervalStartReceived;
	bool mintReceived;
	bool scriptDataHashReceived;

	// TODO move these to commonTxData?
	tx_hash_builder_t txHashBuilder;

	// this holds data valid only through the processing of a single APDU
	union {
		uint64_t fee;
		uint64_t ttl;
		sign_tx_certificate_data_t certificate;
		sign_tx_withdrawal_data_t withdrawal;
		uint64_t validityIntervalStart;
		uint8_t scriptDataHash[SCRIPT_DATA_HASH_LENGTH];
		sign_tx_transaction_input_t collateral;
	} stageData; // TODO rename to reflect single-APDU scope

	union {
		pool_registration_context_t pool_registration_subctx;
		output_context_t output_subctx;
		mint_context_t mint_subctx;
	} stageContext;
} ins_sign_tx_body_context_t;

typedef struct {
	uint16_t currentWitness;
	struct {
		sign_tx_witness_data_t witness;
	} stageData;
} ins_sign_tx_witness_context_t;

typedef struct {
	sign_tx_stage_t stage;

	common_tx_data_t commonTxData;

	bool includeAuxData;
	uint16_t numInputs;
	uint16_t numOutputs;
	bool includeTtl;
	uint16_t numCertificates;
	uint16_t numWithdrawals; // reward withdrawals
	bool includeValidityIntervalStart;
	bool includeMint;
	bool includeScriptDataHash;
	uint16_t numCollaterals;
	uint16_t numWitnesses;

	uint8_t auxDataHash[AUX_DATA_HASH_LENGTH];
	uint8_t txHash[TX_HASH_LENGTH];

	union {
		ins_sign_tx_aux_data_context_t aux_data_ctx;
		ins_sign_tx_body_context_t body_ctx;
		ins_sign_tx_witness_context_t witnesses_ctx;
	} txPartCtx;

	bool poolOwnerByPath;
	bip44_path_t poolOwnerPath;

	int ui_step;
} ins_sign_tx_context_t;

ins_sign_tx_aux_data_context_t* accessAuxDataContext();
ins_sign_tx_body_context_t* accessBodyContext();
ins_sign_tx_witness_context_t* accessWitnessContext();


#ifdef DEVEL
#define AUX_DATA_CTX (ASSERT(accessAuxDataContext() != NULL), accessAuxDataContext())
#define BODY_CTX (ASSERT(accessBodyContext() != NULL), accessBodyContext())
#define WITNESS_CTX (ASSERT(accessWitnessContext() != NULL), accessWitnessContext())
#else
#define AUX_DATA_CTX (accessAuxDataContext())
#define BODY_CTX (accessBodyContext())
#define WITNESS_CTX (accessWitnessContext())
#endif

handler_fn_t signTx_handleAPDU;

static inline bool signTx_parseIncluded(uint8_t value)
{
	switch (value) {
	case ITEM_INCLUDED_YES:
		return true;

	case ITEM_INCLUDED_NO:
		return false;

	default:
		THROW(ERR_INVALID_DATA);
	}
}

#endif // H_CARDANO_APP_SIGN_TX
