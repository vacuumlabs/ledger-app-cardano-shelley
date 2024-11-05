#include "signTxOutput.h"
#include "state.h"
#include "uiHelpers.h"
#include "signTxUtils.h"
#include "txHashBuilder.h"
#include "textUtils.h"
#include "bufView.h"
#include "securityPolicy.h"
#include "tokens.h"
#include "hexUtils.h"
#include "signTxOutput_ui.h"

static output_context_t* accessSubcontext() {
    return &BODY_CTX->stageContext.output_subctx;
}

// ============================== TOP LEVEL DATA ==============================

static bool _needsMissingDatumWarning() {
    output_context_t* subctx = accessSubcontext();
    tx_output_destination_t destination;
    destination.type = subctx->stateData.destination.type;
    switch (destination.type) {
        case DESTINATION_DEVICE_OWNED:
            destination.params = &subctx->stateData.destination.params;
            break;
        case DESTINATION_THIRD_PARTY:
            destination.address.buffer = subctx->stateData.destination.address.buffer;
            destination.address.size = subctx->stateData.destination.address.size;
            break;
    }

    return needsMissingDatumWarning(&destination, subctx->includeDatum);
}

void signTx_handleOutput_address_bytes_ui_runStep() {
    output_context_t* subctx = accessSubcontext();
    TRACE("UI step %d", subctx->ui_step);
    ui_callback_fn_t* this_fn = signTx_handleOutput_address_bytes_ui_runStep;

    ASSERT(subctx->stateData.destination.type == DESTINATION_THIRD_PARTY);

    UI_STEP_BEGIN(subctx->ui_step, this_fn);

    UI_STEP(HANDLE_OUTPUT_ADDRESS_BYTES_STEP_DISPLAY_ADDRESS) {
        ASSERT(subctx->stateData.destination.address.size <=
               SIZEOF(subctx->stateData.destination.address.buffer));
#ifdef HAVE_BAGL
        ui_displayAddressScreen("Send to address",
                                subctx->stateData.destination.address.buffer,
                                subctx->stateData.destination.address.size,
                                this_fn);
#elif defined(HAVE_NBGL)
        char humanAddress[MAX_HUMAN_ADDRESS_SIZE] = {0};
        ui_getAddressScreen(humanAddress,
                            SIZEOF(humanAddress),
                            subctx->stateData.destination.address.buffer,
                            subctx->stateData.destination.address.size);
        fill_and_display_if_required("To", humanAddress, this_fn, respond_with_user_reject);
#endif  // HAVE_BAGL
    }
    UI_STEP(HANDLE_OUTPUT_ADDRESS_BYTES_STEP_WARNING_DATUM) {
        // this warning does not apply to address given by params where we only allow key hash
        // payment part in which case datum is just optional and rarely used
        if (_needsMissingDatumWarning()) {
#ifdef HAVE_BAGL
            ui_displayPaginatedText("WARNING: output",
                                    "could be unspendable due to missing datum",
                                    this_fn);
#elif defined(HAVE_NBGL)
            display_warning("Output could be unspendable\ndue to missing datum",
                            this_fn,
                            respond_with_user_reject);
#endif  // HAVE_BAGL
        } else {
            UI_STEP_JUMP(HANDLE_OUTPUT_ADDRESS_BYTES_STEP_DISPLAY_ADA_AMOUNT);
        }
    }
    UI_STEP(HANDLE_OUTPUT_ADDRESS_BYTES_STEP_DISPLAY_ADA_AMOUNT) {
#ifdef HAVE_BAGL
        ui_displayAdaAmountScreen("Send", subctx->stateData.adaAmount, this_fn);
#elif defined(HAVE_NBGL)
        char adaAmountStr[50] = {0};
        ui_getAdaAmountScreen(adaAmountStr, SIZEOF(adaAmountStr), subctx->stateData.adaAmount);
        fill_and_display_if_required("Amount", adaAmountStr, this_fn, respond_with_user_reject);
#endif  // HAVE_BAGL
    }
    UI_STEP(HANDLE_OUTPUT_ADDRESS_BYTES_STEP_RESPOND) {
        respondSuccessEmptyMsg();
        tx_output_advanceState();
    }
    UI_STEP_END(HANDLE_OUTPUT_ADDRESS_BYTES_STEP_INVALID);
}

void signTx_handleOutput_addressParams_ui_runStep() {
    output_context_t* subctx = accessSubcontext();
    TRACE("UI step %d", subctx->ui_step);
    ui_callback_fn_t* this_fn = signTx_handleOutput_addressParams_ui_runStep;

    ASSERT(subctx->stateData.destination.type == DESTINATION_DEVICE_OWNED);

    UI_STEP_BEGIN(subctx->ui_step, this_fn);

    UI_STEP(HANDLE_OUTPUT_ADDRESS_PARAMS_STEP_DISPLAY_BEGIN) {
#ifdef HAVE_BAGL
        ui_displayPaginatedText(subctx->ui_text1, subctx->ui_text2, this_fn);
#elif defined(HAVE_NBGL)
        set_light_confirmation(true);
        // the ui msg depends on whether we are processing ordinary or collateral output
        char msg[100] = {0};
        snprintf(msg, SIZEOF(msg), "%s\n%s", subctx->ui_text1, subctx->ui_text2);
        ASSERT(strlen(msg) + 1 < SIZEOF(msg));
        display_prompt(msg, "", this_fn, respond_with_user_reject);
#endif  // HAVE_BAGL
    }
    UI_STEP(HANDLE_OUTPUT_ADDRESS_PARAMS_STEP_DISPLAY_PAYMENT_PATH) {
#ifdef HAVE_BAGL
        ui_displayPaymentInfoScreen(&subctx->stateData.destination.params, this_fn);
#elif defined(HAVE_NBGL)
#define PAYMENT_INFO_SIZE MAX(BECH32_STRING_SIZE_MAX, BIP44_PATH_STRING_SIZE_MAX)
        char line1[30];
        char paymentInfoInfo[PAYMENT_INFO_SIZE] = {0};
        ui_getPaymentInfoScreen(line1,
                                SIZEOF(line1),
                                paymentInfoInfo,
                                SIZEOF(paymentInfoInfo),
                                &subctx->stateData.destination.params);
        fill_and_display_if_required(line1, paymentInfoInfo, this_fn, respond_with_user_reject);
#endif  // HAVE_BAGL
    }
    UI_STEP(HANDLE_OUTPUT_ADDRESS_PARAMS_STEP_DISPLAY_STAKING_INFO) {
#ifdef HAVE_BAGL
        ui_displayStakingInfoScreen(&subctx->stateData.destination.params, this_fn);
#elif defined(HAVE_NBGL)
        char line1[30] = {0};
        char stakingInfo[120] = {0};
        ui_getStakingInfoScreen(line1,
                                SIZEOF(line1),
                                stakingInfo,
                                SIZEOF(stakingInfo),
                                &subctx->stateData.destination.params);
        fill_and_display_if_required(line1, stakingInfo, this_fn, respond_with_user_reject);
#endif  // HAVE_BAGL
    }
    UI_STEP(HANDLE_OUTPUT_ADDRESS_PARAMS_STEP_DISPLAY_ADDRESS) {
        uint8_t addressBuffer[MAX_ADDRESS_SIZE] = {0};
        size_t addressSize = deriveAddress(&subctx->stateData.destination.params,
                                           addressBuffer,
                                           SIZEOF(addressBuffer));
        ASSERT(addressSize > 0);
        ASSERT(addressSize <= MAX_ADDRESS_SIZE);

#ifdef HAVE_BAGL
        ui_displayAddressScreen(subctx->ui_text3, addressBuffer, addressSize, this_fn);
#elif defined(HAVE_NBGL)
        char humanAddress[MAX_HUMAN_ADDRESS_SIZE] = {0};
        ui_getAddressScreen(humanAddress, SIZEOF(humanAddress), addressBuffer, addressSize);
        fill_and_display_if_required(subctx->ui_text3,
                                     humanAddress,
                                     this_fn,
                                     respond_with_user_reject);
#endif  // HAVE_BAGL
    }
    UI_STEP(HANDLE_OUTPUT_ADDRESS_PARAMS_STEP_DISPLAY_AMOUNT) {
        if (subctx->stateData.adaAmountSecurityPolicy == POLICY_ALLOW_WITHOUT_PROMPT) {
            UI_STEP_JUMP(HANDLE_OUTPUT_ADDRESS_PARAMS_STEP_RESPOND);
        } else {
#ifdef HAVE_BAGL
            ui_displayAdaAmountScreen(subctx->ui_text4, subctx->stateData.adaAmount, this_fn);
#elif defined(HAVE_NBGL)
            char adaAmountStr[50] = {0};
            ui_getAdaAmountScreen(adaAmountStr, SIZEOF(adaAmountStr), subctx->stateData.adaAmount);
            fill_and_display_if_required(subctx->ui_text4,
                                         adaAmountStr,
                                         this_fn,
                                         respond_with_user_reject);
#endif  // HAVE_BAGL
        }
    }
    UI_STEP(HANDLE_OUTPUT_ADDRESS_PARAMS_STEP_RESPOND) {
        respondSuccessEmptyMsg();
        tx_output_advanceState();
    }
    UI_STEP_END(HANDLE_OUTPUT_ADDRESS_PARAMS_STEP_INVALID);
}

void signTx_handleCollateralOutput_addressBytes_ui_runStep() {
    output_context_t* subctx = accessSubcontext();
    TRACE("UI step %d", subctx->ui_step);
    ui_callback_fn_t* this_fn = signTx_handleCollateralOutput_addressBytes_ui_runStep;

    ASSERT(subctx->stateData.destination.type == DESTINATION_THIRD_PARTY);

    UI_STEP_BEGIN(subctx->ui_step, this_fn);

    UI_STEP(HANDLE_COLLATERAL_OUTPUT_ADDRESS_BYTES_STEP_DISPLAY_INTRO) {
#ifdef HAVE_BAGL
        ui_displayPaginatedText("Collateral", "return output", this_fn);
#elif defined(HAVE_NBGL)
        set_light_confirmation(true);
        display_prompt("Collateral\nreturn output", "", this_fn, respond_with_user_reject);
#endif  // HAVE_BAGL
    }
    UI_STEP(HANDLE_COLLATERAL_OUTPUT_ADDRESS_BYTES_STEP_DISPLAY_ADDRESS) {
        ASSERT(subctx->stateData.destination.address.size <=
               SIZEOF(subctx->stateData.destination.address.buffer));
#ifdef HAVE_BAGL
        ui_displayAddressScreen("Address",
                                subctx->stateData.destination.address.buffer,
                                subctx->stateData.destination.address.size,
                                this_fn);
#elif defined(HAVE_NBGL)
        char humanAddress[MAX_HUMAN_ADDRESS_SIZE] = {0};
        ui_getAddressScreen(humanAddress,
                            SIZEOF(humanAddress),
                            subctx->stateData.destination.address.buffer,
                            subctx->stateData.destination.address.size);
        fill_and_display_if_required("Address", humanAddress, this_fn, respond_with_user_reject);
#endif  // HAVE_BAGL
    }
    UI_STEP(HANDLE_COLLATERAL_OUTPUT_ADDRESS_BYTES_STEP_DISPLAY_ADA_AMOUNT) {
        if (subctx->stateData.adaAmountSecurityPolicy == POLICY_ALLOW_WITHOUT_PROMPT) {
            UI_STEP_JUMP(HANDLE_COLLATERAL_OUTPUT_ADDRESS_BYTES_STEP_RESPOND);
        } else {
#ifdef HAVE_BAGL
            ui_displayAdaAmountScreen("Amount", subctx->stateData.adaAmount, this_fn);
#elif defined(HAVE_NBGL)
            char adaAmountStr[50] = {0};
            ui_getAdaAmountScreen(adaAmountStr, SIZEOF(adaAmountStr), subctx->stateData.adaAmount);
            fill_and_display_if_required("Amount", adaAmountStr, this_fn, respond_with_user_reject);
#endif  // HAVE_BAGL
        }
    }
    UI_STEP(HANDLE_COLLATERAL_OUTPUT_ADDRESS_BYTES_STEP_RESPOND) {
        respondSuccessEmptyMsg();
        tx_output_advanceState();
    }
    UI_STEP_END(HANDLE_COLLATERAL_OUTPUT_ADDRESS_BYTES_STEP_INVALID);
}

// ============================== TOKEN ==============================

void handleToken_ui_runStep() {
    output_context_t* subctx = accessSubcontext();
    TRACE("UI step %d", subctx->ui_step);
    ui_callback_fn_t* this_fn = handleToken_ui_runStep;

    UI_STEP_BEGIN(subctx->ui_step, this_fn);

    UI_STEP(HANDLE_TOKEN_STEP_DISPLAY_NAME) {
#ifdef HAVE_BAGL
        ui_displayAssetFingerprintScreen(&subctx->stateData.tokenGroup,
                                         subctx->stateData.token.assetNameBytes,
                                         subctx->stateData.token.assetNameSize,
                                         this_fn);
#elif defined(HAVE_NBGL)
        char fingerprint[200] = {0};
        ui_getAssetFingerprintScreen(fingerprint,
                                     SIZEOF(fingerprint),
                                     &subctx->stateData.tokenGroup,
                                     subctx->stateData.token.assetNameBytes,
                                     subctx->stateData.token.assetNameSize);
        fill_and_display_if_required("Asset fingerprint",
                                     fingerprint,
                                     this_fn,
                                     respond_with_user_reject);
#endif  // HAVE_BAGL
    }
    UI_STEP(HANDLE_TOKEN_STEP_DISPLAY_AMOUNT) {
#ifdef HAVE_BAGL
        ui_displayTokenAmountOutputScreen(&subctx->stateData.tokenGroup,
                                          subctx->stateData.token.assetNameBytes,
                                          subctx->stateData.token.assetNameSize,
                                          subctx->stateData.token.amount,
                                          this_fn);
#elif defined(HAVE_NBGL)
        char tokenAmountStr[70] = {0};
        ui_getTokenAmountOutputScreen(tokenAmountStr,
                                      SIZEOF(tokenAmountStr),
                                      &subctx->stateData.tokenGroup,
                                      subctx->stateData.token.assetNameBytes,
                                      subctx->stateData.token.assetNameSize,
                                      subctx->stateData.token.amount);
        fill_and_display_if_required("Token amount",
                                     tokenAmountStr,
                                     this_fn,
                                     respond_with_user_reject);
#endif  // HAVE_BAGL
    }
    UI_STEP(HANDLE_TOKEN_STEP_RESPOND) {
        respondSuccessEmptyMsg();

        ASSERT(subctx->stateData.currentToken < subctx->stateData.numTokens);
        subctx->stateData.currentToken++;

        if (subctx->stateData.currentToken == subctx->stateData.numTokens) {
            tx_output_advanceState();
        }
    }
    UI_STEP_END(HANDLE_TOKEN_STEP_INVALID);
}

// ========================== DATUM =============================

void signTxOutput_handleDatumHash_ui_runStep() {
    output_context_t* subctx = accessSubcontext();
    TRACE("UI step %d", subctx->ui_step);
    ui_callback_fn_t* this_fn = signTxOutput_handleDatumHash_ui_runStep;

    UI_STEP_BEGIN(subctx->ui_step, this_fn);

    UI_STEP(HANDLE_DATUM_HASH_STEP_DISPLAY) {
#ifdef HAVE_BAGL
        ui_displayBech32Screen("Datum hash",
                               "datum",
                               subctx->stateData.datumHash,
                               OUTPUT_DATUM_HASH_LENGTH,
                               this_fn);
#elif defined(HAVE_NBGL)
        set_light_confirmation(true);
        char encodedStr[BECH32_STRING_SIZE_MAX] = {0};
        ui_getBech32Screen(encodedStr,
                           SIZEOF(encodedStr),
                           "datum",
                           subctx->stateData.datumHash,
                           OUTPUT_DATUM_HASH_LENGTH);
        fill_and_display_if_required("Datum hash", encodedStr, this_fn, respond_with_user_reject);
#endif  // HAVE_BAGL
    }
    UI_STEP(HANDLE_DATUM_HASH_STEP_RESPOND) {
        respondSuccessEmptyMsg();
        tx_output_advanceState();
    }
    UI_STEP_END(HANDLE_DATUM_HASH_STEP_INVALID);
}

void signTxOutput_handleDatumInline_ui_runStep() {
    output_context_t* subctx = accessSubcontext();
    TRACE("UI step %d", subctx->ui_step);
    ui_callback_fn_t* this_fn = signTxOutput_handleDatumInline_ui_runStep;

    UI_STEP_BEGIN(subctx->ui_step, this_fn);

    UI_STEP(HANDLE_DATUM_INLINE_STEP_DISPLAY) {
        char l1[30];
        size_t datumSize = subctx->stateData.datumRemainingBytes + subctx->stateData.datumChunkSize;
        // datumSize with 6 digits fits on the screen, less than max tx size
        // if more is needed, "bytes" can be replaced by "B" for those larger numbers
        ASSERT(datumSize < UINT32_MAX);
        snprintf(l1, SIZEOF(l1), "Datum %u bytes", (uint32_t) datumSize);
        ASSERT(strlen(l1) + 1 < SIZEOF(l1));

        char l2[20];
        size_t prefixLength = MIN(subctx->stateData.datumChunkSize, 6);
        size_t len = encode_hex(subctx->stateData.datumChunk, prefixLength, l2, SIZEOF(l2));
        snprintf(l2 + len, SIZEOF(l2) - len, "...");
        ASSERT(strlen(l2) + 1 < SIZEOF(l2));

#ifdef HAVE_BAGL
        ui_displayPaginatedText(l1, l2, this_fn);
#elif defined(HAVE_NBGL)
        set_light_confirmation(true);
        display_prompt(l1, l2, this_fn, respond_with_user_reject);
#endif  // HAVE_BAGL
    }
    UI_STEP(HANDLE_DATUM_INLINE_STEP_RESPOND) {
        respondSuccessEmptyMsg();
        tx_output_advanceState();
    }
    UI_STEP_END(HANDLE_DATUM_INLINE_STEP_INVALID);
}

// ========================== REFERENCE SCRIPT =============================

void handleRefScript_ui_runStep() {
    output_context_t* subctx = accessSubcontext();
    TRACE("UI step %d", subctx->ui_step);
    ui_callback_fn_t* this_fn = handleRefScript_ui_runStep;

    UI_STEP_BEGIN(subctx->ui_step, this_fn);
    UI_STEP(HANDLE_SCRIPT_REF_STEP_DISPLAY) {
        char l1[30];
        size_t scriptSize =
            subctx->stateData.refScriptRemainingBytes + subctx->stateData.refScriptChunkSize;
        // scriptSize with 6 digits fits on the screen, less than max tx size
        // if more is needed, "bytes" can be replaced by "B" for those larger numbers
        ASSERT(scriptSize < UINT32_MAX);
        snprintf(l1, SIZEOF(l1), "Script %u bytes", (uint32_t) scriptSize);
        ASSERT(strlen(l1) + 1 < SIZEOF(l1));

        char l2[20];
        size_t prefixLength = MIN(subctx->stateData.refScriptChunkSize, 6);
        size_t len = encode_hex(subctx->stateData.scriptChunk, prefixLength, l2, SIZEOF(l2));
        snprintf(l2 + len, SIZEOF(l2) - len, "...");
        ASSERT(strlen(l2) + 1 < SIZEOF(l2));

#ifdef HAVE_BAGL
        ui_displayPaginatedText(l1, l2, this_fn);
#elif defined(HAVE_NBGL)
        set_light_confirmation(true);
        display_prompt(l1, l2, this_fn, respond_with_user_reject);
#endif  // HAVE_BAGL
    }
    UI_STEP(HANDLE_SCRIPT_REF_STEP_RESPOND) {
        respondSuccessEmptyMsg();
        tx_output_advanceState();
    }
    UI_STEP_END(HANDLE_SCRIPT_REF_STEP_INVALID);
}

// ============================== CONFIRM ==============================

void signTxOutput_handleConfirm_ui_runStep() {
    output_context_t* subctx = accessSubcontext();
    TRACE("UI step %d", subctx->ui_step);
    ui_callback_fn_t* this_fn = signTxOutput_handleConfirm_ui_runStep;

    UI_STEP_BEGIN(subctx->ui_step, this_fn);

    UI_STEP(HANDLE_CONFIRM_STEP_FINAL_CONFIRM) {
#ifdef HAVE_BAGL
        ui_displayPrompt(subctx->ui_text1, subctx->ui_text2, this_fn, respond_with_user_reject);
#elif defined(HAVE_NBGL)
        set_light_confirmation(true);
        // the ui msg depends on whether we are processing ordinary or collateral output
        char msg[100] = {0};
        snprintf(msg, SIZEOF(msg), "%s\n%s", subctx->ui_text1, subctx->ui_text2);
        ASSERT(strlen(msg) + 1 < SIZEOF(msg));
        display_confirmation(msg,
                             "",
                             "Output\nconfirmed",
                             "Output\nrejected",
                             this_fn,
                             respond_with_user_reject);
#endif  // HAVE_BAGL
    }
    UI_STEP(HANDLE_CONFIRM_STEP_RESPOND) {
        respondSuccessEmptyMsg();
        tx_output_advanceState();
    }
    UI_STEP_END(HANDLE_CONFIRM_STEP_INVALID);
}
