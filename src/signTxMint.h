#ifndef H_CARDANO_APP_SIGN_TX_MINT
#define H_CARDANO_APP_SIGN_TX_MINT

#ifdef APP_FEATURE_TOKEN_MINTING

#include "common.h"
#include "cardano.h"
#include "addressUtilsShelley.h"
#include "securityPolicyType.h"

#define ASSET_GROUPS_MAX    1000
#define TOKENS_IN_GROUP_MAX 1000

// SIGN_STAGE_BODY_OUTPUTS = 25
typedef enum {
    STATE_MINT_TOP_LEVEL_DATA = 2510,
    STATE_MINT_ASSET_GROUP = 2511,
    STATE_MINT_TOKEN = 2512,
    STATE_MINT_CONFIRM = 2513,
    STATE_MINT_FINISHED = 2514
} sign_tx_mint_state_t;

typedef struct {
    uint8_t assetNameBytes[ASSET_NAME_SIZE_MAX];
    size_t assetNameSize;
    int64_t amount;
} mint_token_amount_t;

typedef struct {
    sign_tx_mint_state_t state;

    int ui_step;

    uint16_t numAssetGroups;
    uint16_t currentAssetGroup;
    uint16_t numTokens;
    uint16_t currentToken;

    // this affects whether amounts and tokens are shown
    security_policy_t mintSecurityPolicy;

    union {
        struct {
            token_group_t tokenGroup;
            mint_token_amount_t token;
        };
    } stateData;

} mint_context_t;

bool signTxMint_isValidInstruction(uint8_t p2);

void signTxMint_init();
void signTxMint_handleAPDU(uint8_t p2, const uint8_t* wireDataBuffer, size_t wireDataSize);

bool signTxMint_isFinished();

#endif  // APP_FEATURE_TOKEN_MINTING

#endif  // H_CARDANO_APP_SIGN_TX_MINT
