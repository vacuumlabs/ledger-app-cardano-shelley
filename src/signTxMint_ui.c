#include "signTxMint.h"
#include "signTxMint_ui.h"
#include "signTxUtils.h"
#include "state.h"
#include "uiHelpers.h"
#include "utils.h"
#include "textUtils.h"
#include "securityPolicy.h"
#include "tokens.h"

#ifdef HAVE_BAGL
#include "uiScreens_bagl.h"
#elif defined(HAVE_NBGL)
#include "uiScreens_nbgl.h"
#endif

static mint_context_t* accessSubcontext() {
    return &BODY_CTX->stageContext.mint_subctx;
}

static inline void advanceState() {
    mint_context_t* subctx = accessSubcontext();
    TRACE("Advancing mint state from: %d", subctx->state);

    switch (subctx->state) {
        case STATE_MINT_TOP_LEVEL_DATA:
            ASSERT(subctx->numAssetGroups > 0);
            ASSERT(subctx->currentAssetGroup == 0);
            subctx->state = STATE_MINT_ASSET_GROUP;
            break;

        case STATE_MINT_ASSET_GROUP:
            ASSERT(subctx->currentAssetGroup < subctx->numAssetGroups);

            // we are going to receive token amounts for this group
            ASSERT(subctx->numTokens > 0);
            ASSERT(subctx->currentToken == 0);

            subctx->state = STATE_MINT_TOKEN;
            break;

        case STATE_MINT_TOKEN:
            // we are done with the current token group
            ASSERT(subctx->currentToken == subctx->numTokens);
            subctx->currentToken = 0;
            ASSERT(subctx->currentAssetGroup < subctx->numAssetGroups);
            subctx->currentAssetGroup++;

            if (subctx->currentAssetGroup == subctx->numAssetGroups) {
                // the whole token bundle has been received
                subctx->state = STATE_MINT_CONFIRM;
            } else {
                subctx->state = STATE_MINT_ASSET_GROUP;
            }
            break;

        case STATE_MINT_CONFIRM:
            subctx->state = STATE_MINT_FINISHED;
            break;

        default:
            ASSERT(false);
    }

    TRACE("Advancing mint state to: %d", subctx->state);
}

__noinline_due_to_stack__ void signTxMint_handleTopLevelData_ui_runStep() {
    mint_context_t* subctx = accessSubcontext();
    TRACE("UI step %d", subctx->ui_step);

    ui_callback_fn_t* this_fn = signTxMint_handleTopLevelData_ui_runStep;

    UI_STEP_BEGIN(subctx->ui_step, this_fn);

    UI_STEP(HANDLE_MINT_TOP_LEVEL_DATA_DISPLAY) {
        char secondLine[50] = {0};
        explicit_bzero(secondLine, SIZEOF(secondLine));
        STATIC_ASSERT(!IS_SIGNED(subctx->numAssetGroups), "signed type for %u");
        snprintf(secondLine, SIZEOF(secondLine), "%u asset groups", subctx->numAssetGroups);
        ASSERT(strlen(secondLine) + 1 < SIZEOF(secondLine));

#ifdef HAVE_BAGL
        ui_displayPaginatedText("Mint", secondLine, this_fn);
#elif defined(HAVE_NBGL)
        display_prompt("Mint", secondLine, this_fn, respond_with_user_reject);
#endif  // HAVE_BAGL
    }
    UI_STEP(HANDLE_MINT_TOP_LEVEL_DATA_RESPOND) {
        respondSuccessEmptyMsg();
        advanceState();
    }
    UI_STEP_END(HANDLE_MINT_TOP_LEVEL_DATA_INVALID);
}

void signTxMint_handleAssetGroup_ui_runStep() {
    mint_context_t* subctx = accessSubcontext();
    TRACE("UI step %d", subctx->ui_step);

    ui_callback_fn_t* this_fn = signTxMint_handleAssetGroup_ui_runStep;

    UI_STEP_BEGIN(subctx->ui_step, this_fn);

    UI_STEP(HANDLE_ASSET_GROUP_STEP_RESPOND) {
        respondSuccessEmptyMsg();
        advanceState();
    }
    UI_STEP_END(HANDLE_ASSET_GROUP_STEP_INVALID);
}

void signTxMint_handleToken_ui_runStep() {
    mint_context_t* subctx = accessSubcontext();
    TRACE("UI step %d", subctx->ui_step);
    ui_callback_fn_t* this_fn = signTxMint_handleToken_ui_runStep;

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
        ui_displayTokenAmountMintScreen(&subctx->stateData.tokenGroup,
                                        subctx->stateData.token.assetNameBytes,
                                        subctx->stateData.token.assetNameSize,
                                        subctx->stateData.token.amount,
                                        this_fn);
#elif defined(HAVE_NBGL)
        char tokenAmountStr[70] = {0};
        ui_getTokenAmountMintScreen(tokenAmountStr,
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

        ASSERT(subctx->currentToken < subctx->numTokens);
        subctx->currentToken++;

        if (subctx->currentToken == subctx->numTokens) {
            advanceState();
        }
    }
    UI_STEP_END(HANDLE_TOKEN_STEP_INVALID);
}

void signTxMint_handleConfirm_ui_runStep() {
    mint_context_t* subctx = accessSubcontext();
    TRACE("UI step %d", subctx->ui_step);
    ui_callback_fn_t* this_fn = signTxMint_handleConfirm_ui_runStep;

    UI_STEP_BEGIN(subctx->ui_step, this_fn);

    UI_STEP(HANDLE_CONFIRM_STEP_FINAL_CONFIRM) {
#ifdef HAVE_BAGL
        ui_displayPrompt("Confirm", "mint?", this_fn, respond_with_user_reject);
#elif defined(HAVE_NBGL)
        display_confirmation("Confirm mint",
                             "",
                             "MINT\nCONFIRMED",
                             "Mint\nrejected",
                             this_fn,
                             respond_with_user_reject);
#endif  // HAVE_BAGL
    }
    UI_STEP(HANDLE_CONFIRM_STEP_RESPOND) {
        respondSuccessEmptyMsg();
        advanceState();
    }
    UI_STEP_END(HANDLE_CONFIRM_STEP_INVALID);
}
