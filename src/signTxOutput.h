#ifndef H_CARDANO_APP_SIGN_TX_OUTPUT
#define H_CARDANO_APP_SIGN_TX_OUTPUT

#include "common.h"
#include "cardano.h"
#include "addressUtilsShelley.h"
#include "securityPolicyType.h"
#include "txHashBuilder.h"

#define OUTPUT_ASSET_GROUPS_MAX UINT16_MAX
#define OUTPUT_TOKENS_IN_GROUP_MAX UINT16_MAX

// we want chunks as big as possible to minimize the number of APDUs
// to optimize for speed of data exchange
// length of data in APDU (without INS, P1, P2 etc.) is set to 255 according to ledger devs
// we need 1 B for datum type and 4 B for chunk length
// so it seems safe to set this to 240 B
#define MAX_CHUNK_SIZE 240


// SIGN_STAGE_BODY_OUTPUTS = 25
typedef enum {
	STATE_OUTPUT_TOP_LEVEL_DATA = 2510,
	STATE_OUTPUT_ASSET_GROUP = 2511,
	STATE_OUTPUT_TOKEN = 2512,
	STATE_OUTPUT_DATUM = 2513,
	STATE_OUTPUT_DATUM_INLINE_CHUNKS = 2514,
	STATE_OUTPUT_REFERENCE_SCRIPT = 2515,
	STATE_OUTPUT_REFERENCE_SCRIPT_CHUNKS = 2516,
	STATE_OUTPUT_CONFIRM = 2520,
	STATE_OUTPUT_FINISHED = 2521
} sign_tx_output_state_t;


typedef struct {
	sign_tx_output_state_t state;
	int ui_step;
//	void (*ui_advanceState)();
	const char* ui_text1;
	const char* ui_text2;
	const char* ui_text3;
	const char* ui_text4;

	tx_output_serialization_format_t serializationFormat;
	uint16_t numAssetGroups; // positive if there are tokens
	bool includeDatum;
	bool datumHashReceived; // is this needed?
	bool includeRefScript;

	// this affects whether amounts and tokens are shown
	security_policy_t outputSecurityPolicy;
	security_policy_t outputTokensSecurityPolicy;

	union {
		struct {
			// top level data
			tx_output_destination_storage_t destination;

			uint64_t adaAmount;
			security_policy_t adaAmountSecurityPolicy;
		};
		struct {
			// data for processing a multiasset map
			token_group_t tokenGroup;
			output_token_amount_t token;
			uint16_t currentAssetGroup;
			uint16_t currentToken;
			uint16_t numTokens;
		};
		struct {
			// data for processing datum
			datum_type_t datumType;
			union {
				struct {
					// datum hash
					uint8_t datumHash[OUTPUT_DATUM_HASH_LENGTH];
				};
				struct {
					// inline datum
					size_t datumRemainingBytes;
					size_t datumChunkSize;
					uint8_t datumChunk[MAX_CHUNK_SIZE];
				};
			};
		};
		struct {
			size_t refScriptRemainingBytes;
			size_t refScriptChunkSize;
			uint8_t scriptChunk[MAX_CHUNK_SIZE];
		};
	} stateData;

} output_context_t;


void initializeOutputSubmachine();
bool isCurrentOutputFinished();

bool signTxOutput_isValidInstruction(uint8_t p2);
void signTxOutput_handleAPDU(uint8_t p2, const uint8_t* wireDataBuffer, size_t wireDataSize);

bool signTxCollateralOutput_isValidInstruction(uint8_t p2);
void signTxCollateralOutput_handleAPDU(uint8_t p2, const uint8_t* wireDataBuffer, size_t wireDataSize);

void tx_output_advanceState();
#endif // H_CARDANO_APP_SIGN_TX_OUTPUT
