#ifndef H_CARDANO_APP_UI_SCREENS
#define H_CARDANO_APP_UI_SCREENS

#include "uiHelpers.h"
#include "addressUtilsShelley.h"
#include "signTxOutput.h"
#include "signTxPoolRegistration.h"

__noinline_due_to_stack__
void ui_displayBech32Screen(
        const char* screenHeader,
        const char* bech32Prefix,
        const uint8_t* buffer, size_t bufferSize,
        ui_callback_fn_t callback
);

__noinline_due_to_stack__
void ui_displayHexBufferScreen(
        const char* screenHeader,
        const uint8_t* buffer, size_t bufferSize,
        ui_callback_fn_t callback
);

__noinline_due_to_stack__
void ui_displayPathScreen(
        const char* screenHeader,
        const bip44_path_t* path,
        ui_callback_fn_t callback
);

__noinline_due_to_stack__
void ui_displayGetPublicKeyPathScreen(
        const bip44_path_t* path,
        ui_callback_fn_t callback
);

__noinline_due_to_stack__
void ui_displayStakingKeyScreen(
        const bip44_path_t* stakingPath,
        ui_callback_fn_t callback
);

__noinline_due_to_stack__
void ui_displayAddressScreen(
        const char* screenHeader,
        const uint8_t* addressBuffer, size_t addressSize,
        ui_callback_fn_t callback
);

__noinline_due_to_stack__
void ui_displayRewardAccountScreen(
        const reward_account_t* rewardAccount,
        uint8_t networkId,
        ui_callback_fn_t callback
);

__noinline_due_to_stack__
void ui_displaySpendingInfoScreen(
        const addressParams_t* addressParams,
        ui_callback_fn_t callback
);

__noinline_due_to_stack__
void ui_displayStakingInfoScreen(
        const addressParams_t* addressParams,
        ui_callback_fn_t callback
);

size_t deriveAssetFingerprint(
        uint8_t* policyId,
        size_t policyIdSize,
        uint8_t* assetName,
        size_t assetNameSize,
        char* fingerprint,
        size_t fingerprintMaxSize
);
__noinline_due_to_stack__
void ui_displayAssetFingerprintScreen(
        token_group_t* tokenGroup,
        uint8_t* assetNameBytes, size_t assetNameSize,
        ui_callback_fn_t callback
);

__noinline_due_to_stack__
void ui_displayAdaAmountScreen(
        const char* screenHeader,
        uint64_t amount,
        ui_callback_fn_t callback
);

__noinline_due_to_stack__
void ui_displayUint64Screen(
        const char* screenHeader,
        uint64_t value,
        ui_callback_fn_t callback
);

__noinline_due_to_stack__
void ui_displayInt64Screen(
        const char* screenHeader,
        int64_t value,
        ui_callback_fn_t callback
);

__noinline_due_to_stack__
void ui_displayValidityBoundaryScreen(
        const char* screenHeader,
        uint64_t boundary,
        uint8_t networkId, uint32_t protocolMagic,
        ui_callback_fn_t callback
);

__noinline_due_to_stack__
void ui_displayNetworkParamsScreen(
        const char* screenHeader,
        uint8_t networkId,
        uint32_t protocolMagic,
        ui_callback_fn_t callback
);

__noinline_due_to_stack__
void ui_displayPoolMarginScreen(
        uint64_t marginNumerator, uint64_t marginDenominator,
        ui_callback_fn_t callback
);

__noinline_due_to_stack__
void ui_displayPoolOwnerScreen(
        const pool_owner_t* owner,
        uint32_t ownerIndex,
        uint8_t networkId,
        ui_callback_fn_t callback
);

__noinline_due_to_stack__
void ui_displayPoolRelayScreen(
        const pool_relay_t* relay,
        size_t relayIndex,
        ui_callback_fn_t callback
);

__noinline_due_to_stack__
void ui_displayIpv4Screen(
        ipv4_t* ipv4,
        ui_callback_fn_t callback
);

__noinline_due_to_stack__
void ui_displayIpv6Screen(
        ipv6_t* ipv6,
        ui_callback_fn_t callback
);

__noinline_due_to_stack__
void ui_displayIpPortScreen(
        ipport_t* port,
        ui_callback_fn_t callback
);

#ifdef DEVEL
void run_uiScreens_test();
#endif // DEVEL

#endif // H_CARDANO_APP_UI_SCREENS
