/*******************************************************************************
 **   Ledger App - Cardano Wallet (c) 2022 Ledger
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ********************************************************************************/
#ifdef HAVE_NBGL
#include "app_mode.h"
#include "nbgl_use_case.h"
#include "state.h"
#include "ui.h"
#include "uiHelpers.h"
#include "uiScreens_nbgl.h"
#include "signTx_ui.h"

#define MAX_LINE_PER_PAGE_COUNT   NB_MAX_LINES_IN_REVIEW
#define MAX_TAG_TITLE_LINE_LENGTH 30
#define MAX_TAG_CONTENT_LENGTH    200
#define MAX_TEXT_STRING           60
#define PENDING_ELEMENT_INDEX     NB_MAX_DISPLAYED_PAIRS_IN_REVIEW
enum {
    CANCEL_PROMPT_TOKEN = 1,
    ACCEPT_PAGE_TOKEN,
    CONFIRMATION_STATUS_TOKEN,
};

typedef enum {
    STATUS_TYPE_TRANSACTION,
    STATUS_TYPE_ADDRESS,
} statusType_t;

typedef struct {
    bool standardStatus;
    statusType_t statusType;
    const char* confirmedStatus;  // text displayed in confirmation page (after long press)
    const char* rejectedStatus;   // text displayed in rejection page (after reject confirmed)
    callback_t approvedCallback;
    callback_t rejectedCallback;
    callback_t pendingDisplayPageFn;
    bool pendingElement;
    uint8_t currentLineCount;
    uint8_t currentElementCount;
    char tagTitle[NB_MAX_DISPLAYED_PAIRS_IN_REVIEW + 1][MAX_TAG_TITLE_LINE_LENGTH];
    char tagContent[NB_MAX_DISPLAYED_PAIRS_IN_REVIEW + 1][MAX_TAG_CONTENT_LENGTH];
    char pageText[2][MAX_TEXT_STRING];
    bool lightConfirmation;
    nbgl_layoutTagValueList_t pairList;
    bool no_approved_status;
} UiContext_t;

static nbgl_page_t* pageContext;
static nbgl_layoutTagValue_t tagValues[5];
static UiContext_t uiContext = {
    .rejectedStatus = NULL,
    .confirmedStatus = NULL,
    .currentLineCount = 0,
    .currentElementCount = 0,
    .pendingElement = false,
    .lightConfirmation = 0,
    .no_approved_status = false,
};

// Forward declaration
static void display_cancel(void);
static void display_confirmation_status(void);
static void display_cancel_status(void);
static void trigger_callback(callback_t userAcceptCallback);

static void release_context(void) {
    if (pageContext != NULL) {
        nbgl_pageRelease(pageContext);
        pageContext = NULL;
    }
}

static inline uint16_t get_element_line_count(const char* line) {
    uint16_t nbLines = nbgl_getTextNbLinesInWidth(LARGE_MEDIUM_FONT,
                                                  line,
                                                  SCREEN_WIDTH - 2 * BORDER_MARGIN,
                                                  false);

    return nbLines + 1;  // For title
}

static void ui_callback(void) {
    nbgl_useCaseSpinner("Processing");
    uiContext.approvedCallback();
}

static void set_callbacks(callback_t approvedCallback, callback_t rejectedCallback) {
    uiContext.approvedCallback = approvedCallback;
    uiContext.rejectedCallback = rejectedCallback;
}

static void fill_current_element(const char* text, const char* content) {
    strncpy(uiContext.tagTitle[uiContext.currentElementCount], text, MAX_TAG_TITLE_LINE_LENGTH);
    strncpy(uiContext.tagContent[uiContext.currentElementCount], content, MAX_TAG_CONTENT_LENGTH);

    uiContext.currentElementCount++;
    uiContext.currentLineCount += get_element_line_count(content);
}

static void fill_pending_element(const char* text, const char* content) {
    strncpy(uiContext.tagTitle[PENDING_ELEMENT_INDEX], text, MAX_TAG_TITLE_LINE_LENGTH);
    strncpy(uiContext.tagContent[PENDING_ELEMENT_INDEX], content, MAX_TAG_CONTENT_LENGTH);

    uiContext.pendingElement = true;
}

static void reset_transaction_current_context(void) {
    uiContext.currentElementCount = 0;
    uiContext.currentLineCount = 0;
}

void nbgl_reset_transaction_full_context(void) {
    reset_transaction_current_context();
    uiContext.standardStatus = false;
    uiContext.statusType = STATUS_TYPE_TRANSACTION;
    uiContext.pendingElement = 0;
    uiContext.lightConfirmation = false;
    uiContext.rejectedStatus = NULL;
    uiContext.confirmedStatus = NULL;
    uiContext.approvedCallback = NULL;
    uiContext.rejectedCallback = NULL;
    uiContext.pendingDisplayPageFn = NULL;
    uiContext.no_approved_status = false;
}

void set_light_confirmation(bool needed) {
    uiContext.lightConfirmation = needed;
}

static void display_callback(int token, unsigned char index) {
    (void) index;
    callback_t callback;

    switch (token) {
        case CANCEL_PROMPT_TOKEN:
            display_cancel();
            break;
        case ACCEPT_PAGE_TOKEN:
            if (uiContext.pendingDisplayPageFn) {
                // Hook the approve callback so that the pending page is displayed
                // Once this page is approved, the approve callback will be called
                callback = uiContext.pendingDisplayPageFn;
                uiContext.pendingDisplayPageFn = NULL;
            } else {
                callback = ui_callback;
            }
            callback();
            break;
        case CONFIRMATION_STATUS_TOKEN:
            display_confirmation_status();
            break;
        default:
            TRACE("%d unknown", token);
    }
}

static void _display_confirmation(void) {
    TRACE("_confirmation");

    release_context();

    nbgl_pageNavigationInfo_t info = {.activePage = 0,
                                      .nbPages = 0,
                                      .navType = NAV_WITH_TAP,
                                      .progressIndicator = true,
                                      .navWithTap.backButton = false,
                                      .navWithTap.nextPageText = NULL,
                                      .navWithTap.quitText = "Reject transaction",
                                      .quitToken = CANCEL_PROMPT_TOKEN,
                                      .tuneId = TUNE_TAP_CASUAL};

    nbgl_pageContent_t content = {.type = INFO_LONG_PRESS,
                                  .infoLongPress.icon = &C_cardano_64,
                                  .infoLongPress.text = uiContext.pageText[0],
                                  .infoLongPress.longPressText = "Hold to sign",
                                  .infoLongPress.longPressToken = CONFIRMATION_STATUS_TOKEN,
                                  .infoLongPress.tuneId = TUNE_TAP_NEXT};

    pageContext = nbgl_pageDrawGenericContent(&display_callback, &info, &content);

#ifdef HEADLESS
    nbgl_refresh();
    trigger_callback(ui_callback);
#endif
}

static void light_confirm_callback(bool confirm) {
    if (confirm) {
        display_confirmation_status();
    } else {
        display_cancel_status();
    }
}

static void _display_light_confirmation(void) {
    TRACE("_light_confirmation");

    // TODO "reject transaction" is used as a constant string in several places
    // and then applied also for signing messages and operational certificates.
    // We should change this as part of the upcoming larger UX rewrite.
    nbgl_useCaseChoice(&C_cardano_64,
                       uiContext.pageText[0],
                       "",
                       "Confirm",
                       "Reject Transaction",
                       light_confirm_callback);

#ifdef HEADLESS
    trigger_callback(ui_callback);
#endif
}

static void display_cancel(void) {
    if (uiContext.lightConfirmation) {
        display_cancel_status();
    } else {
        nbgl_useCaseConfirm("Reject transaction?",
                            NULL,
                            "Yes, reject",
                            "Go back to transaction",
                            display_cancel_status);
    }
}

static void cancellation_status_callback(void) {
    if (uiContext.rejectedCallback) {
        uiContext.rejectedCallback();
    }
    ui_idle_flow();
    nbgl_reset_transaction_full_context();
}

static void display_cancel_status(void) {
    ui_idle();

    // If rejectedStatus string is not NULL, then use it to display
    // the status notification after the user has rejected the transaction.
    if (uiContext.rejectedStatus) {
        nbgl_useCaseStatus(uiContext.rejectedStatus, false, cancellation_status_callback);
    }
    // Otherwise use the statusType to determine the status to display.
    // The string is managed by the SDK.
    else {
        switch (uiContext.statusType) {
            case STATUS_TYPE_TRANSACTION:
                nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_REJECTED,
                                         cancellation_status_callback);
                break;
            case STATUS_TYPE_ADDRESS:
                nbgl_useCaseReviewStatus(STATUS_TYPE_ADDRESS_REJECTED,
                                         cancellation_status_callback);
                break;
        }
    }
}

static void _display_page(void) {
    TRACE("_page");

    release_context();

    for (uint8_t i = 0; i < uiContext.currentElementCount; i++) {
        tagValues[i].item = uiContext.tagTitle[i];
        tagValues[i].value = uiContext.tagContent[i];
    }

    nbgl_pageNavigationInfo_t info = {.activePage = 0,
                                      .nbPages = 0,
                                      .navType = NAV_WITH_TAP,
                                      .progressIndicator = true,
                                      .navWithTap.backButton = false,
                                      .navWithTap.nextPageText = "Tap to continue",
                                      .navWithTap.nextPageToken = ACCEPT_PAGE_TOKEN,
                                      .navWithTap.quitText = "Reject transaction",
                                      .quitToken = CANCEL_PROMPT_TOKEN,
                                      .tuneId = TUNE_TAP_CASUAL};

    nbgl_pageContent_t content = {.type = TAG_VALUE_LIST,
                                  .tagValueList.nbPairs = uiContext.currentElementCount,
                                  .tagValueList.pairs = (nbgl_layoutTagValue_t*) tagValues};

    pageContext = nbgl_pageDrawGenericContent(&display_callback, &info, &content);
    reset_transaction_current_context();

#ifdef HEADLESS
    nbgl_refresh();
    trigger_callback(ui_callback);
#endif
}

static void _display_prompt(void) {
    TRACE("_prompt");

    nbgl_useCaseReviewStart(&C_cardano_64,
                            uiContext.pageText[0],
                            uiContext.pageText[1],
                            "Reject transaction",
                            ui_callback,
                            &display_cancel);
#ifdef HEADLESS
    nbgl_refresh();
    trigger_callback(ui_callback);
#endif
}

static void _display_warning(void) {
    TRACE("_warning");

    nbgl_useCaseReviewStart(&C_Warning_64px,
                            "WARNING",
                            uiContext.pageText[0],
                            "Reject if not sure",
                            ui_callback,
                            &display_cancel);
#ifdef HEADLESS
    nbgl_refresh();
    trigger_callback(ui_callback);
#endif
}

static void display_choice_callback(bool choice) {
    if (choice) {
        ui_callback();
    } else {
        display_cancel();
    }
}

static void _display_choice(void) {
    TRACE("_choice");

    nbgl_useCaseChoice(&C_Important_Circle_64px,
                       uiContext.pageText[0],
                       uiContext.pageText[1],
                       "Allow",
                       "Don't Allow",
                       display_choice_callback);
#ifdef HEADLESS
    nbgl_refresh();
    trigger_callback(ui_callback);
#endif
}

static void confirmation_status_callback(void) {
    // If confirmedStatus string is not NULL, then use it to display
    // the status notification after the user has confirmed the transaction.
    if (uiContext.confirmedStatus) {
        nbgl_useCaseStatus(uiContext.confirmedStatus, true, ui_idle_flow);
        nbgl_reset_transaction_full_context();
        // Otherwise, if the standardStatus flag is set, then use the statusType
        // to determine the status to display (the string is managed by the SDK).
    } else if (uiContext.standardStatus) {
        switch (uiContext.statusType) {
            case STATUS_TYPE_TRANSACTION:
                nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_SIGNED, ui_idle_flow);
                break;
            case STATUS_TYPE_ADDRESS:
                nbgl_useCaseReviewStatus(STATUS_TYPE_ADDRESS_VERIFIED, ui_idle_flow);
                break;
        }
        nbgl_reset_transaction_full_context();
        // If neither of the above conditions are met, then the status notification
        // display is delayed until the confirmation process is finished.
        // A spinner is displayed in the meantime.
    } else {
        nbgl_useCaseSpinner("Processing");
    }
}

static void display_confirmation_status(void) {
    if (uiContext.approvedCallback) {
        ui_callback();
    }

    if (!uiContext.no_approved_status) {
        confirmation_status_callback();
    }
}

static void trigger_callback(callback_t userAcceptCallback) {
    set_app_callback(userAcceptCallback);
    nbgl_useCaseSpinner("Processing");
}

static void handle_pending_element(void) {
    TRACE("Add pending element");
    ASSERT(uiContext.currentElementCount == 0);
    ASSERT(uiContext.currentLineCount == 0);

    fill_current_element(uiContext.tagTitle[PENDING_ELEMENT_INDEX],
                         uiContext.tagContent[PENDING_ELEMENT_INDEX]);

    uiContext.pendingElement = false;
}

static void _display_page_or_call_function(callback_t displayPageFn) {
    if (uiContext.pendingElement) {
        handle_pending_element();
    }

    if (uiContext.currentElementCount > 0) {
        // We were request to display a page using displayPageFn and then call
        // specific callbacks. However we have pending elements to display first.
        // Therefore, temporally save displayPageFn in pendingDisplayPageFn and
        // display these pending elements.
        // Once these pending elements page is approved, the generic display_callback()
        // function will be called, and it will then execute the function stored
        // in pendingDisplayPageFn instead of the approvedCallback.
        // therefore our screen will be displayed, and if it is approved, at this moment
        // the approvedCallback will be called.
        uiContext.pendingDisplayPageFn = displayPageFn;
        _display_page();
    } else {
        displayPageFn();
    }
}

// Fillers
void force_display(callback_t userAcceptCallback, callback_t userRejectCallback) {
    if (uiContext.currentLineCount > 0) {
        TRACE("Force page display");
        set_callbacks(userAcceptCallback, userRejectCallback);
        _display_page();
    } else {
        TRACE("Nothing to do");
        trigger_callback(userAcceptCallback);
    }
}

// Fill page content. If the content's number of lines exceeds the maximum number of lines per page,
// the page is displayed and the pending element is added.
void fill_and_display_if_required(const char* line1,
                                  const char* line2,
                                  callback_t userAcceptCallback,
                                  callback_t userRejectCallback) {
    ASSERT(strlen(line1) <= MAX_TAG_TITLE_LINE_LENGTH);
    ASSERT(strlen(line2) <= MAX_TAG_CONTENT_LENGTH);

    if (uiContext.pendingElement) {
        handle_pending_element();
    }

    if (uiContext.currentLineCount + get_element_line_count(line2) > MAX_LINE_PER_PAGE_COUNT) {
        TRACE("Display page and add pending element");
        fill_pending_element(line1, line2);
        set_callbacks(userAcceptCallback, userRejectCallback);
        _display_page();
    } else {
        TRACE("Add element to page");
        fill_current_element(line1, line2);
        trigger_callback(userAcceptCallback);
    }
}

void fill_address_data(char* text, char* content, callback_t callback) {
    fill_current_element(text, content);
    trigger_callback(callback);
}

void display_confirmation(const char* text1,
                          const char* text2,
                          const char* confirmText,
                          const char* rejectText,
                          callback_t userAcceptCallback,
                          callback_t userRejectCallback) {
    TRACE("Displaying confirmation");

    uiContext.confirmedStatus = confirmText;
    uiContext.rejectedStatus = rejectText;

    set_callbacks(userAcceptCallback, userRejectCallback);

    strncpy(uiContext.pageText[0], text1, MAX_TEXT_STRING);
    strncpy(uiContext.pageText[1], text2, MAX_TEXT_STRING);

    if (uiContext.lightConfirmation) {
        _display_page_or_call_function(&_display_light_confirmation);
    } else {
        _display_page_or_call_function(&_display_confirmation);
    }
}

void display_confirmation_no_approved_status(const char* text1,
                                             const char* text2,
                                             const char* rejectText,
                                             callback_t userAcceptCallback,
                                             callback_t userRejectCallback) {
    uiContext.no_approved_status = true;
    display_confirmation(text1, text2, NULL, rejectText, userAcceptCallback, userRejectCallback);
}

void display_prompt(const char* text1,
                    const char* text2,
                    callback_t userAcceptCallback,
                    callback_t userRejectCallback) {
    TRACE("Displaying Prompt");

    set_callbacks(userAcceptCallback, userRejectCallback);

    strncpy(uiContext.pageText[0], text1, MAX_TEXT_STRING);
    strncpy(uiContext.pageText[1], text2, MAX_TEXT_STRING);

    _display_page_or_call_function(&_display_prompt);
}

void display_warning(const char* text,
                     callback_t userAcceptCallback,
                     callback_t userRejectCallback) {
    TRACE("Displaying Warning");

    set_callbacks(userAcceptCallback, userRejectCallback);
    strncpy(uiContext.pageText[0], text, MAX_TEXT_STRING);
    _display_page_or_call_function(&_display_warning);
}

void display_choice(const char* text1,
                    const char* text2,
                    callback_t userAcceptCallback,
                    callback_t userRejectCallback) {
    TRACE("Displaying choice");

    set_callbacks(userAcceptCallback, userRejectCallback);
    strncpy(uiContext.pageText[0], text1, MAX_TEXT_STRING);
    strncpy(uiContext.pageText[1], text2, MAX_TEXT_STRING);
    _display_page_or_call_function(&_display_choice);
}

void display_address(callback_t userAcceptCallback, callback_t userRejectCallback) {
    TRACE("Displaying Address");
    set_callbacks(userAcceptCallback, userRejectCallback);

    uint8_t address_index = 0;

    // Address field is not displayed in pairList, so there is one element less.
    uiContext.pairList.nbPairs = uiContext.currentElementCount - 1;
    uiContext.pairList.pairs = tagValues;

    uiContext.standardStatus = true;
    uiContext.statusType = STATUS_TYPE_ADDRESS;

    for (uint8_t i = 0; i < uiContext.currentElementCount; i++) {
        if (strcmp(uiContext.tagTitle[i], "Address")) {
            tagValues[i].item = uiContext.tagTitle[i];
            tagValues[i].value = uiContext.tagContent[i];
        } else {
            address_index = i;
        }
    }

    nbgl_useCaseAddressReview(uiContext.tagContent[address_index],
                              &uiContext.pairList,
                              &C_cardano_64,
                              "Verify Cardano address",
                              NULL,
                              light_confirm_callback);
    reset_transaction_current_context();

#ifdef HEADLESS
    nbgl_refresh();
    trigger_callback(&display_confirmation_status);
#endif
}

void display_error(void) {
    TRACE("Displaying Error");

    nbgl_reset_transaction_full_context();
    nbgl_useCaseStatus("An error has occurred", false, ui_idle_flow);
}

void display_status(const char* text) {
    nbgl_useCaseStatus(text, true, ui_idle_flow);
}

void fee_high_cb(int token, uint8_t index) {
    UNUSED(index);
    char adaAmountStr[50] = {0};

    switch (token) {
        case TOKEN_HIGH_FEES_NEXT:
            ui_getAdaAmountScreen(adaAmountStr, SIZEOF(adaAmountStr), BODY_CTX->stageData.fee);
            fill_and_display_if_required("Fees",
                                         adaAmountStr,
                                         signTx_handleFee_ui_runStep,
                                         respond_with_user_reject);
            break;
        case TOKEN_HIGH_FEES_REJECT:
            nbgl_useCaseConfirm("Reject transaction?",
                                NULL,
                                "Yes, reject",
                                "Go back to transaction",
                                display_cancel_status);
            break;
        default:
            break;
    }
}

void display_warning_fee(void) {
    nbgl_pageInfoDescription_t info = {0};

    info.footerText = "Reject";
    info.footerToken = TOKEN_HIGH_FEES_REJECT;
    info.isSwipeable = true;
    info.tapActionToken = TOKEN_HIGH_FEES_NEXT;
    info.topRightStyle = NO_BUTTON_STYLE;
    info.tuneId = TUNE_LOOK_AT_ME;

    info.centeredInfo.icon = &C_Important_Circle_64px;
    info.centeredInfo.text1 = "Fee are above\n5 ADA";
    info.centeredInfo.text3 = "Swipe to review";
    info.centeredInfo.style = LARGE_CASE_GRAY_INFO;

    nbgl_pageDrawInfo(fee_high_cb, NULL, &info);

#ifdef HEADLESS
    nbgl_refresh();
    fee_high_cb(TOKEN_HIGH_FEES_NEXT, 0);
#endif
}

#endif  // HAVE_NBGL
