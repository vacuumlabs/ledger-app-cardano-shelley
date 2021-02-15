#ifndef H_CARDANO_APP_SIGN_TX_OUTPUT
#define H_CARDANO_APP_SIGN_TX_OUTPUT

#include "common.h"
#include "cardano.h"
#include "cardanoCertificates.h"
#include "addressUtilsShelley.h"
#include "securityPolicy.h"

#define OUTPUT_ASSET_GROUPS_MAX 1000
#define OUTPUT_TOKENS_IN_GROUP_MAX 1000

enum {
	OUTPUT_TYPE_ADDRESS_BYTES = 1,
	OUTPUT_TYPE_ADDRESS_PARAMS = 2,
};


// SIGN_STAGE_OUTPUTS = 25
typedef enum {
	STATE_OUTPUT_TOP_LEVEL_DATA = 2510,
	STATE_OUTPUT_ASSET_GROUP = 2511,
	STATE_OUTPUT_TOKEN = 2512,
	STATE_OUTPUT_CONFIRM = 2513,
	STATE_OUTPUT_FINISHED = 2514
} sign_tx_output_state_t;


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
} top_level_output_data_t;


typedef struct {
	sign_tx_output_state_t state;

	int ui_step;

	uint16_t numAssetGroups;
	uint16_t currentAssetGroup;
	uint16_t numTokens;
	uint16_t currentToken;

	// this affects whether amounts and tokens are shown
	security_policy_t outputSecurityPolicy;

	union {
		top_level_output_data_t output;
		token_group_t tokenGroup;
		token_amount_t token;
	} stateData;

} output_context_t;


void signTxOutput_init();

bool signTxOutput_isValidInstruction(uint8_t p2);
void signTxOutput_handleAPDU(uint8_t p2, uint8_t* wireDataBuffer, size_t wireDataSize);

bool signTxOutput_isFinished();

#endif
