#ifndef H_CARDANO_APP_UI_SCREENS_BAGL
#define H_CARDANO_APP_UI_SCREENS_BAGL

#include "uiHelpers.h"
#include "addressUtilsShelley.h"
#include "signTx.h"
#include "signTxOutput.h"
#include "signTxPoolRegistration.h"
#include "bech32.h"

__noinline_due_to_stack__ void ui_displayBech32Screen(const char* screenHeader,
                                                      const char* bech32Prefix,
                                                      const uint8_t* buffer,
                                                      size_t bufferSize,
                                                      ui_callback_fn_t callback);

__noinline_due_to_stack__ void ui_displayHexBufferScreen(const char* screenHeader,
                                                         const uint8_t* buffer,
                                                         size_t bufferSize,
                                                         ui_callback_fn_t callback);

__noinline_due_to_stack__ void ui_displayPathScreen(const char* screenHeader,
                                                    const bip44_path_t* path,
                                                    ui_callback_fn_t callback);

__noinline_due_to_stack__ void ui_displayGetPublicKeyPathScreen(const bip44_path_t* path,
                                                                ui_callback_fn_t callback);

__noinline_due_to_stack__ void ui_displayStakingKeyScreen(const bip44_path_t* stakingPath,
                                                          ui_callback_fn_t callback);

__noinline_due_to_stack__ void ui_displayAddressScreen(const char* screenHeader,
                                                       const uint8_t* addressBuffer,
                                                       size_t addressSize,
                                                       ui_callback_fn_t callback);

__noinline_due_to_stack__ void ui_displayRewardAccountScreen(const reward_account_t* rewardAccount,
                                                             uint8_t networkId,
                                                             ui_callback_fn_t callback);

__noinline_due_to_stack__ void ui_displayPaymentInfoScreen(const addressParams_t* addressParams,
                                                           ui_callback_fn_t callback);

__noinline_due_to_stack__ void ui_displayStakingInfoScreen(const addressParams_t* addressParams,
                                                           ui_callback_fn_t callback);

__noinline_due_to_stack__ void ui_displayAssetFingerprintScreen(const token_group_t* tokenGroup,
                                                                const uint8_t* assetNameBytes,
                                                                size_t assetNameSize,
                                                                ui_callback_fn_t callback);

__noinline_due_to_stack__ void ui_displayAdaAmountScreen(const char* screenHeader,
                                                         uint64_t amount,
                                                         ui_callback_fn_t callback);

__noinline_due_to_stack__ void ui_displayTokenAmountOutputScreen(const token_group_t* tokenGroup,
                                                                 const uint8_t* assetNameBytes,
                                                                 size_t assetNameSize,
                                                                 uint64_t tokenAmount,
                                                                 ui_callback_fn_t callback);

__noinline_due_to_stack__ void ui_displayTokenAmountMintScreen(const token_group_t* tokenGroup,
                                                               const uint8_t* assetNameBytes,
                                                               size_t assetNameSize,
                                                               int64_t tokenAmount,
                                                               ui_callback_fn_t callback);

__noinline_due_to_stack__ void ui_displayUint64Screen(const char* screenHeader,
                                                      uint64_t value,
                                                      ui_callback_fn_t callback);

__noinline_due_to_stack__ void ui_displayInt64Screen(const char* screenHeader,
                                                     int64_t value,
                                                     ui_callback_fn_t callback);

__noinline_due_to_stack__ void ui_displayValidityBoundaryScreen(const char* screenHeader,
                                                                uint64_t boundary,
                                                                uint8_t networkId,
                                                                uint32_t protocolMagic,
                                                                ui_callback_fn_t callback);

__noinline_due_to_stack__ void ui_displayNetworkParamsScreen(const char* screenHeader,
                                                             uint8_t networkId,
                                                             uint32_t protocolMagic,
                                                             ui_callback_fn_t callback);

__noinline_due_to_stack__ void ui_displayPoolMarginScreen(uint64_t marginNumerator,
                                                          uint64_t marginDenominator,
                                                          ui_callback_fn_t callback);

#ifdef APP_FEATURE_POOL_REGISTRATION

__noinline_due_to_stack__ void ui_displayPoolOwnerScreen(const pool_owner_t* owner,
                                                         uint32_t ownerIndex,
                                                         uint8_t networkId,
                                                         ui_callback_fn_t callback);

__noinline_due_to_stack__ void ui_displayPoolRelayScreen(const pool_relay_t* relay,
                                                         size_t relayIndex,
                                                         ui_callback_fn_t callback);

__noinline_due_to_stack__ void ui_displayIpv4Screen(const ipv4_t* ipv4, ui_callback_fn_t callback);

__noinline_due_to_stack__ void ui_displayIpv6Screen(const ipv6_t* ipv6, ui_callback_fn_t callback);

__noinline_due_to_stack__ void ui_displayIpPortScreen(const ipport_t* port,
                                                      ui_callback_fn_t callback);

#endif  // APP_FEATURE_POOL_REGISTRATION

__noinline_due_to_stack__ void ui_displayInputScreen(const sign_tx_transaction_input_t* input,
                                                     ui_callback_fn_t callback);

void fee_high_cb(void);

#endif  // H_CARDANO_APP_UI_SCREENS_BAGL
