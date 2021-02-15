#ifndef H_CARDANO_APP_CARDANO_OUTPUTS
#define H_CARDANO_APP_CARDANO_OUTPUTS

#include "cardano.h"


typedef struct {
	uint8_t policyId[MINTING_POLICY_ID_SIZE];
} token_group_t;

typedef struct {
	uint8_t assetNameBytes[ASSET_NAME_SIZE_MAX];
	size_t assetNameSize;
	uint64_t amount;
} token_amount_t;


#endif // H_CARDANO_APP_CARDANO_OUTPUTS
