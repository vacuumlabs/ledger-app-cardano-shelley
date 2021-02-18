#ifndef H_CARDANO_APP_UI_SCREENS
#define H_CARDANO_APP_UI_SCREENS

#include "uiHelpers.h"
#include "addressUtilsShelley.h"
#include "signTxOutput.h"
#include "signTxPoolRegistration.h"

void ui_displayPathScreen(
        const char* screenHeader,
        const bip44_path_t* path,
        ui_callback_fn_t callback
);

void ui_displayAccountScreen(
        const char* screenHeader,
        const bip44_path_t* path,
        ui_callback_fn_t callback
);

void ui_displayAddressScreen(
        const char* screenHeader,
        const uint8_t* addressBuffer, size_t addressSize,
        ui_callback_fn_t callback
);

void ui_displayStakingInfoScreen(
        const addressParams_t* addressParams,
        ui_callback_fn_t callback
);

void ui_displayTokenNameScreen(
        token_amount_t* token,
        ui_callback_fn_t callback
);

void ui_displayAdaAmountScreen(
        const char* screenHeader,
        uint64_t amount,
        ui_callback_fn_t callback
);

void ui_displayUint64Screen(
        const char* screenHeader,
        uint64_t value,
        ui_callback_fn_t callback
);

void ui_displayValidityBoundaryScreen(
        const char* screenHeader,
        uint64_t boundary,
        uint8_t networkId, uint32_t protocolMagic,
        ui_callback_fn_t callback
);

void ui_displayNetworkParamsScreen(
        const char* screenHeader,
        uint8_t networkId,
        uint32_t protocolMagic,
        ui_callback_fn_t callback
);

void ui_displayHexBufferScreen(
        const char* screenHeader,
        const uint8_t* buffer, size_t bufferSize,
        ui_callback_fn_t callback
);

void ui_displayPoolIdScreen(
        const uint8_t* poolIdBuffer,
        size_t poolIdSize,
        ui_callback_fn_t callback
);

void ui_displayPoolMarginScreen(
        uint64_t marginNumerator, uint64_t marginDenominator,
        ui_callback_fn_t callback
);

void ui_displayPoolOwnerScreen(
        const pool_owner_t* owner,
        uint32_t ownerIndex,
        uint8_t networkId,
        ui_callback_fn_t callback
);

void ui_displayIpPortScreen(
        ipport_t* port,
        ui_callback_fn_t callback
);

#endif // H_CARDANO_APP_UI_SCREENS
