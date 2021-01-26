#ifndef H_CARDANO_APP_SIGN_TX_OUTPUT
#define H_CARDANO_APP_SIGN_TX_OUTPUT

#include "common.h"
#include "cardano.h"
#include "cardanoCertificates.h"
#include "addressUtilsShelley.h"

#define OUTPUT_TOKEN_GROUP_NUM_TOKENS_MAX 1000
#define OUTPUT_NUM_TOKEN_GROUPS_MAX 1000

enum {
	OUTPUT_TYPE_ADDRESS_BYTES = 1,
	OUTPUT_TYPE_ADDRESS_PARAMS = 2,
};


// SIGN_STAGE_OUTPUTS = 25
typedef enum {
	STATE_OUTPUT_BASIC_DATA = 2510,
	STATE_OUTPUT_TOKEN_GROUP = 2511,
	STATE_OUTPUT_TOKEN_AMOUNT = 2512,
	STATE_OUTPUT_CONFIRM = 2513,
	STATE_OUTPUT_FINISHED = 2514
} sign_tx_output_state_t;


typedef struct {
	uint8_t policyId[MINTING_POLICY_ID_SIZE];
} token_group_t;

typedef struct {
	uint8_t assetName[ASSET_NAME_SIZE_MAX];
	size_t assetNameSize;
	uint64_t amount;
} token_amount_t;

typedef struct {
	uint8_t outputType;
	union {
		struct {
			uint8_t buffer[MAX_ADDRESS_SIZE];
			size_t size;
		} address;
		addressParams_t params;
	};

	uint64_t adaAmount;
} basic_output_data_t;


typedef struct {
	sign_tx_output_state_t state;

	int ui_step;

	uint16_t numTokenGroups;
	uint16_t currentTokenGroup;
	uint16_t numTokenAmounts;
	uint16_t currentTokenAmount;

	union {
		basic_output_data_t output;
		token_group_t tokenGroup;
		token_amount_t tokenAmount;
	} stateData;

} output_context_t;


void signTxOutput_init();

bool signTxOutput_isValidInstruction(uint8_t p2);
void signTxOutput_handleAPDU(uint8_t p2, uint8_t* wireDataBuffer, size_t wireDataSize);

bool signTxOutput_isFinished();

#endif
