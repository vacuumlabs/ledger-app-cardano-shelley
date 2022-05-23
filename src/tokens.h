#ifndef H_CARDANO_APP_TOKENS
#define H_CARDANO_APP_TOKENS

#include "common.h"
#include "cardano.h"

__noinline_due_to_stack__
size_t deriveAssetFingerprintBech32(
        const uint8_t* policyId,
        size_t policyIdSize,
        const uint8_t* assetName,
        size_t assetNameSize,
        char* fingerprint,
        size_t fingerprintMaxSize
);

__noinline_due_to_stack__
size_t str_formatTokenAmountOutput(
        const token_group_t* tokenGroup,
        const uint8_t* assetNameBytes, size_t assetNameSize,
        uint64_t amount,
        char* out, size_t outSize
);

__noinline_due_to_stack__
size_t str_formatTokenAmountMint(
        const token_group_t* tokenGroup,
        const uint8_t* assetNameBytes, size_t assetNameSize,
        int64_t amount,
        char* out, size_t outSize
);

#ifdef DEVEL
void run_tokens_test();
#endif // DEVEL


#endif // H_CARDANO_APP_TOKENS
