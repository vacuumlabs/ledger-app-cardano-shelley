#ifndef H_CARDANO_APP_SIGN_TX_OUTPUT
#define H_CARDANO_APP_SIGN_TX_OUTPUT

#include "common.h"
#include "cardano.h"
#include "addressUtilsShelley.h"
#include "securityPolicyType.h"

#define OUTPUT_ASSET_GROUPS_MAX UINT16_MAX
#define OUTPUT_TOKENS_IN_GROUP_MAX UINT16_MAX

enum {
	OUTPUT_TYPE_ADDRESS_BYTES = 1,
	OUTPUT_TYPE_ADDRESS_PARAMS = 2,
};


// SIGN_STAGE_BODY_OUTPUTS = 25
typedef enum {
	STATE_OUTPUT_TOP_LEVEL_DATA = 2510,
	STATE_OUTPUT_ASSET_GROUP = 2511,
	STATE_OUTPUT_TOKEN = 2512,
	STATE_OUTPUT_DATUM_OPTION = 2513,
	STATE_OUTPUT_CONFIRM = 2514,
	STATE_OUTPUT_FINISHED = 2515
} sign_tx_output_state_t;


typedef struct {
	uint8_t outputType;
	uint8_t format;
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
	bool includeDatumHash;
	bool datumHashReceived;
	bool includeScriptRef;

	// this affects whether amounts and tokens are shown
	security_policy_t outputSecurityPolicy;

	union {
		top_level_output_data_t output;
		struct {
			token_group_t tokenGroup;
			output_token_amount_t token;
		};
		struct {
			uint8_t datumOption;
			uint8_t datumHash[OUTPUT_DATUM_HASH_LENGTH];
		};
	} stateData;

} output_context_t;


void signTxOutput_init();

bool signTxOutput_isValidInstruction(uint8_t p2);
void signTxOutput_handleAPDU(uint8_t p2, const uint8_t* wireDataBuffer, size_t wireDataSize);

bool signTxOutput_isFinished();

#endif // H_CARDANO_APP_SIGN_TX_OUTPUT
