/******************************************************************************* *   Ledger App - Bitcoin Wallet
 *   (c) 2022 Ledger
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
#include "nbgl_page.h"
#include "nbgl_touch.h"
#include "state.h"
#include "ui.h"
#include "uiHelpers.h"
#include "uiScreens_nbgl.h"

#define MAX_LINE_PER_PAGE_COUNT 9
#define MAX_TAG_PER_PAGE_COUNT 5
#define MAX_TAG_TITLE_LINE_LENGTH 30
#define MAX_TAG_CONTENT_LENGTH 200
#define MAX_TAG_CONTENT_CHAR_PER_LINE 22
#define MAX_TEXT_STRING 50

enum {
  QUIT_APP_TOKEN,
  QUIT_INFO_TOKEN,
  SETTINGS_TOKEN,
  EXPERT_MODE_TOKEN,
  INFO_TOKEN,

  CANCEL_PROMPT_TOKEN,
  ACCEPT_TOKEN,
  ACCEPT_PAGE_TOKEN,
  CANCEL_MESSAGE_TOKEN,
  CONFIRMATION_MESSAGE_TOKEN,

  _WARNING_TOKEN,
  _PAGE_TOKEN,
  _CONFIRMATION_TOKEN,
  _PROMPT_TOKEN,
};

typedef struct {
  char *confirmed;   // text displayed in confirmation page (after long press)
  char *rejected; // text displayed in rejection page (after reject confirmed)
  void (*approved_cb)(void);
  void (*abandon_cb)(void);
  void (*pendingCb)(void);
  bool pendingElement;
  uint8_t currentLineCount;
  uint8_t currentElementCount;
  char tagTitle[MAX_TAG_PER_PAGE_COUNT + 1][MAX_TAG_TITLE_LINE_LENGTH];
  char tagContent[MAX_TAG_PER_PAGE_COUNT + 1][MAX_TAG_CONTENT_LENGTH];
  char pageText[2][MAX_TEXT_STRING];
} UiContext_t;

static const int INS_NONE = -1;
static const char *const infoContents[] = {APPVERSION, "(c) 2022 Ledger"};
static const char *const settingsBarTexts[] = {"App mode", "About"};
static const char *const appMode[] = {"Normal mode", "Expert mode"};
static const char settingsBarTokens[] = {EXPERT_MODE_TOKEN, INFO_TOKEN};
static nbgl_page_t *pageContext;
static nbgl_layoutTagValue_t tagValues[5];
static int8_t saved_token;
static UiContext_t uiContext = {
    .rejected = NULL,
    .confirmed = NULL,
    .currentLineCount = 0,
    .currentElementCount = 0,
};

// Forward declaration
static void _display_warning(void);
static void _display_page(void);
static void _display_confirmation(void);
static void _display_prompt(void);
static void display_cancel(void);
static void display_confirmation_message(void);
static void display_cancel_message(void);
static void menu_callback(int token, uint8_t unused);
static void ui_expert_mode(void);
static void ui_menu_settings(void);
static void ui_menu_about(void);
static void ui_idle_flow(void);

static void releaseContext(void) {
  if (pageContext != NULL) {
    nbgl_pageRelease(pageContext);
    pageContext = NULL;
  }
}

static void menu_callback(int token, uint8_t unused) {
  (void) unused;
  switch (token) {
  case QUIT_APP_TOKEN:
    releaseContext();
    os_sched_exit(-1);
    break;
  case QUIT_INFO_TOKEN:
    ui_idle_flow();
    break;
  case SETTINGS_TOKEN:
    saved_token = SETTINGS_TOKEN;
    ui_menu_settings();
    break;
  case INFO_TOKEN:
    ui_menu_about();
    break;
  case EXPERT_MODE_TOKEN:
    ui_expert_mode();
    break;
  case CONFIRMATION_MESSAGE_TOKEN:
    saved_token = CONFIRMATION_MESSAGE_TOKEN;
    break;
  }
}

static void expert_mode_callback(int token, uint8_t index) {
  switch (token) {
  case EXPERT_MODE_TOKEN:
    app_mode_expert(index == 1);
    break;
  case SETTINGS_TOKEN:
    ui_menu_settings();
    break;
  case QUIT_INFO_TOKEN:
    ui_idle_flow();
    break;
  }
}

static void ui_expert_mode(void) {
  releaseContext();
  nbgl_layoutDescription_t layoutDescription = {
      .modal = false, .onActionCallback = &expert_mode_callback};
  nbgl_layout_t *layout = nbgl_layoutGet(&layoutDescription);

  nbgl_layoutRadioChoice_t layoutRadioChoice = {.names = (char** )appMode,
                                                .localized = false,
                                                .nbChoices = 2,
                                                .initChoice = app_mode_expert(),
                                                .token = EXPERT_MODE_TOKEN,
                                                .tuneId = TUNE_TAP_CASUAL};

  nbgl_layoutBar_t layoutBar = {.iconLeft = &C_leftArrow32px,
                                .text = (char *) "Select app mode",
                                .iconRight = NULL,
                                .subText = NULL,
                                .token = SETTINGS_TOKEN,
                                .inactive = false,
                                .centered = true,
                                .tuneId = TUNE_TAP_CASUAL};

  nbgl_layoutAddTouchableBar(layout, &layoutBar);
  nbgl_layoutAddRadioChoice(layout, &layoutRadioChoice);
  nbgl_layoutAddBottomButton(layout, &C_cross32px, QUIT_INFO_TOKEN, true,
                             TUNE_TAP_CASUAL);
  nbgl_layoutDraw(layout);
  nbgl_refresh();
  nbgl_layoutRelease(layout);
}

static void ui_menu_about(void) {
  const char *infoTypes[] = {"Version", "Cardano App"};

  nbgl_pageContent_t content = {.title = "About Cardano",
                                .titleToken = SETTINGS_TOKEN,
                                .isTouchableTitle = true};
  nbgl_pageNavigationInfo_t nav = {.activePage = 0,
                                   .nbPages = 1,
                                   .navType = NAV_WITH_BUTTONS,
                                   .navWithButtons.quitButton = true,
                                   .navWithButtons.navToken = QUIT_INFO_TOKEN,
                                   .tuneId = TUNE_TAP_CASUAL};
  content.type = INFOS_LIST;
  content.infosList.nbInfos = 2;
  content.infosList.infoTypes = (const char **)infoTypes;
  content.infosList.infoContents = (const char **)infoContents;

  releaseContext();
  pageContext = nbgl_pageDrawGenericContent(&menu_callback, &nav, &content);
  nbgl_refresh();
}

static void ui_menu_settings(void) {
  nbgl_pageContent_t content = {.title = "Cardano settings",
                                .titleToken = QUIT_INFO_TOKEN,
                                .isTouchableTitle = true};
  nbgl_pageNavigationInfo_t nav = {.activePage = 0,
                                   .nbPages = 1,
                                   .navType = NAV_WITH_BUTTONS,
                                   .navWithButtons.quitButton = true,
                                   .navWithButtons.navToken = QUIT_INFO_TOKEN,
                                   .tuneId = TUNE_TAP_CASUAL};
  content.type = BARS_LIST;
  content.barsList.nbBars = 2;
  content.barsList.tokens = (uint8_t *)settingsBarTokens;
  content.barsList.barTexts = (const char **)settingsBarTexts;

  releaseContext();
  pageContext = nbgl_pageDrawGenericContent(&menu_callback, &nav, &content);
  nbgl_refresh();
}

static void ui_idle_flow(void) {
  nbgl_useCaseHome("Cardano", &C_cardano_64, NULL, true, ui_menu_settings, exit);
}

static inline uint8_t getElementLineCount(const char* line) {
    return strlen(line) / MAX_TAG_CONTENT_CHAR_PER_LINE + 2;
}
static void display_callback(int token, unsigned char index) {
    (void) index;

    switch (token) {
        case CANCEL_PROMPT_TOKEN:
            display_cancel();
            break;
        case CANCEL_MESSAGE_TOKEN:
            display_cancel_message();
            break;
        case ACCEPT_PAGE_TOKEN:
            uiContext.currentElementCount = 0;
            uiContext.currentLineCount = 0;
            uiContext.approved_cb();
            break;
        case ACCEPT_TOKEN:
            if (index == 0) {
                uiContext.approved_cb();
            }
            else {
                display_cancel();
            }
            break;
        case _WARNING_TOKEN:
            _display_warning();
            break;
        case _PAGE_TOKEN:
            _display_page();
            break;
        case _CONFIRMATION_TOKEN:
            _display_confirmation();
            break;
        case CONFIRMATION_MESSAGE_TOKEN:
            display_confirmation_message();
            break;
        case _PROMPT_TOKEN:
            _display_prompt();
            break;
        default: 
            TRACE("%d unknown", token);
    }
}

#ifdef HEADLESS
static void headless_cb(void) {
    releaseContext();
    uiContext.approved_cb();
}
#endif // HEADLESS

static void _display_confirmation(void) {
    TRACE("_confirmation");
    if (uiContext.pendingCb) {
        uiContext.approved_cb = uiContext.pendingCb;
        uiContext.pendingCb = NULL;
    }
    saved_token = _CONFIRMATION_TOKEN;

    nbgl_pageNavigationInfo_t info = {
        .activePage = 0,
        .nbPages = 0,
        .navType = NAV_WITH_TAP,
        .progressIndicator = true,
        .navWithTap.backButton = false,
        .navWithTap.nextPageText = NULL,
        .navWithTap.quitText = "Reject",
        .quitToken = CANCEL_PROMPT_TOKEN,
        .tuneId = TUNE_TAP_CASUAL};

    nbgl_pageContent_t content = {
        .type = INFO_LONG_PRESS,
        .infoLongPress.icon = &C_cardano_64,
        .infoLongPress.text = uiContext.pageText[0],
        .infoLongPress.longPressText = (char*)"Hold to approve",
        .infoLongPress.longPressToken = CONFIRMATION_MESSAGE_TOKEN,
        .infoLongPress.tuneId = TUNE_TAP_NEXT};
    releaseContext();
#ifndef HEADLESS
    pageContext = nbgl_pageDrawGenericContent(&display_callback, &info, &content);
#else
    nbgl_screenTickerConfiguration_t ticker = {
        .tickerCallback = &headless_cb,
        .tickerIntervale = 0,
        .tickerValue = 100};
    pageContext = nbgl_pageDrawLedgerInfo(NULL, &ticker, NULL, 0);
#endif
    nbgl_refresh();
}

static void _display_page(void) {
    TRACE("_page");
    saved_token = _PAGE_TOKEN;

    for (uint8_t i = 0; i < uiContext.currentElementCount; i++) {
        tagValues[i].item = uiContext.tagTitle[i];
        tagValues[i].value = uiContext.tagContent[i];
    }

    nbgl_pageNavigationInfo_t info = {
        .activePage = 0,
        .nbPages = 0,
        .navType = NAV_WITH_TAP,
        .progressIndicator = true,
        .navWithTap.backButton = false,
        .navWithTap.nextPageText = (char*)"Tap to continue",
        .navWithTap.nextPageToken = ACCEPT_PAGE_TOKEN,
        .navWithTap.quitText = (char*)"Cancel",
        .quitToken = CANCEL_PROMPT_TOKEN,
        .tuneId = TUNE_TAP_CASUAL};

    nbgl_pageContent_t content = {
        .type = TAG_VALUE_LIST,
        .tagValueList.nbPairs = uiContext.currentElementCount,
        .tagValueList.pairs = (nbgl_layoutTagValue_t *)tagValues};

    releaseContext();
#ifndef HEADLESS
    pageContext = nbgl_pageDrawGenericContent(&display_callback, &info, &content);
#else
    uiContext.currentElementCount = 0;
    uiContext.currentLineCount = 0;
    nbgl_screenTickerConfiguration_t ticker = {
        .tickerCallback = &headless_cb,
        .tickerIntervale = 0,
        .tickerValue = 100};
    pageContext = nbgl_pageDrawLedgerInfo(NULL, &ticker, NULL, 0);
#endif
    nbgl_refresh();
}

static void _display_prompt(void) {
    TRACE("_prompt");
    if (uiContext.pendingCb) {
        uiContext.approved_cb = uiContext.pendingCb;
        uiContext.pendingCb = NULL;
    }

    saved_token = _PROMPT_TOKEN;

    nbgl_pageConfirmationDescription_t info = {
        .centeredInfo.text1 = uiContext.pageText[0],
        .centeredInfo.text2 = uiContext.pageText[1],
        .centeredInfo.text3 = NULL,
        .centeredInfo.style = LARGE_CASE_INFO,
        .centeredInfo.icon = &C_cardano_64,
        .centeredInfo.offsetY = -64,
        .confirmationText = "Continue",
        .cancelText = "Reject if not sure",
        .confirmationToken = ACCEPT_TOKEN,
        .cancelToken = CANCEL_PROMPT_TOKEN,
        .tuneId = TUNE_TAP_CASUAL};

    releaseContext();
#ifndef HEADLESS
    pageContext = nbgl_pageDrawConfirmation(&display_callback, &info);
#else
    nbgl_screenTickerConfiguration_t ticker = {
        .tickerCallback = &headless_cb,
        .tickerIntervale = 0,
        .tickerValue = 100};
    pageContext = nbgl_pageDrawLedgerInfo(NULL, &ticker, NULL, 0);
#endif
    nbgl_refresh();
}

static void _display_warning(void) {
    TRACE("_warning");
    if (uiContext.pendingCb) {
        uiContext.approved_cb = uiContext.pendingCb;
        uiContext.pendingCb = NULL;
    }
    saved_token = _WARNING_TOKEN;

    nbgl_pageConfirmationDescription_t info = {
        .centeredInfo.text1 = (char*) "WARNING",
        .centeredInfo.text2 = uiContext.pageText[0],
        .centeredInfo.text3 = NULL,
        .centeredInfo.style = LARGE_CASE_INFO,
        .centeredInfo.icon = &C_cardano_64,
        .centeredInfo.offsetY = -64,
        .confirmationText = "Continue",
        .cancelText = "Reject if not sure",
        .confirmationToken = ACCEPT_TOKEN,
        .cancelToken = CANCEL_PROMPT_TOKEN,
        .tuneId = TUNE_TAP_CASUAL};

    releaseContext();
#ifndef HEADLESS
    pageContext = nbgl_pageDrawConfirmation(&display_callback, &info);
#else
    nbgl_screenTickerConfiguration_t ticker = {
        .tickerCallback = &headless_cb,
        .tickerIntervale = 0,
        .tickerValue = 100};
    pageContext = nbgl_pageDrawLedgerInfo(NULL, &ticker, NULL, 0);
#endif
    nbgl_refresh();
}

static void display_page(callback_t user_accept_cb, callback_t user_reject_cb) {
    TRACE("Displaying page");
    uiContext.approved_cb = user_accept_cb;
    uiContext.abandon_cb = user_reject_cb;

    _display_page();
}

static void display_confirmation_message(void) {
  nbgl_screenTickerConfiguration_t ticker = {.tickerCallback = uiContext.approved_cb,
                                             .tickerIntervale = 0,
                                             .tickerValue = 100};
  releaseContext();
  pageContext = nbgl_pageDrawLedgerInfo(NULL, &ticker, uiContext.confirmed, 0);
  nbgl_refresh();
}

static void display_cancel_message(void) {
  nbgl_screenTickerConfiguration_t ticker = {.tickerCallback = uiContext.abandon_cb,
                                             .tickerIntervale = 0,
                                             .tickerValue = 100};
  releaseContext();
  pageContext = nbgl_pageDrawLedgerInfo(NULL, &ticker, uiContext.rejected, 0);
  nbgl_refresh();
}

static void display_cancel(void) {
  nbgl_pageConfirmationDescription_t info = {
      .cancelToken = saved_token,
      .centeredInfo.text1 = (char *) "Cancel",
      .centeredInfo.text2 = NULL,
      .centeredInfo.text3 = NULL,
      .centeredInfo.style = LARGE_CASE_INFO,
      .centeredInfo.icon = &C_cardano_64,
      .centeredInfo.offsetY = -64,
      .confirmationText = "Yes",
      .confirmationToken = CANCEL_MESSAGE_TOKEN,
      .tuneId = TUNE_TAP_NEXT};

  releaseContext();
  pageContext = nbgl_pageDrawConfirmation(&display_callback, &info);
  nbgl_refresh();
}

void fill_and_display_if_required(const char* line1, const char* line2, callback_t user_accept_cb, callback_t user_reject_cb) {

    ASSERT(strlen(line1) <= MAX_TAG_TITLE_LINE_LENGTH);
    ASSERT(strlen(line2) <= MAX_TAG_CONTENT_LENGTH);

    if (uiContext.pendingElement) {
        TRACE("Has pending element");
        ASSERT(uiContext.currentElementCount == 0);
        ASSERT(uiContext.currentLineCount == 0);

        snprintf(uiContext.tagTitle[0], MAX_TAG_TITLE_LINE_LENGTH, "%s", uiContext.tagTitle[MAX_TAG_PER_PAGE_COUNT]);
        snprintf(uiContext.tagContent[0], MAX_TAG_CONTENT_LENGTH, "%s", uiContext.tagContent[MAX_TAG_PER_PAGE_COUNT]);
        uiContext.currentElementCount++;
        uiContext.pendingElement = false;
        uiContext.currentLineCount = getElementLineCount(uiContext.tagContent[0]);
    }

    if (uiContext.currentLineCount + getElementLineCount(line2) >= MAX_LINE_PER_PAGE_COUNT) {
        TRACE("Display page and add pending element");
        snprintf(uiContext.tagTitle[MAX_TAG_PER_PAGE_COUNT], MAX_TAG_TITLE_LINE_LENGTH, "%s", line1);
        snprintf(uiContext.tagContent[MAX_TAG_PER_PAGE_COUNT], MAX_TAG_CONTENT_LENGTH, "%s", line2);
        uiContext.pendingElement = true;

        display_page(user_accept_cb, user_reject_cb);
    }
    else {
        TRACE("Add element to page");
        snprintf(uiContext.tagTitle[uiContext.currentElementCount], MAX_TAG_TITLE_LINE_LENGTH, "%s", line1);
        snprintf(uiContext.tagContent[uiContext.currentElementCount], MAX_TAG_CONTENT_LENGTH, "%s", line2);
        uiContext.currentElementCount++;
        uiContext.currentLineCount += getElementLineCount(line2);
        display_continue(user_accept_cb);
    }
}

void fill_and_display_new_page(const char* line1, const char* line2, callback_t user_accept_cb, callback_t user_reject_cb) {

    ASSERT(strlen(line1) <= MAX_TAG_TITLE_LINE_LENGTH);
    ASSERT(strlen(line2) <= MAX_TAG_CONTENT_LENGTH);

    if (uiContext.pendingElement) {
        TRACE("Has pending element");
        ASSERT(uiContext.currentElementCount == 0);
        ASSERT(uiContext.currentLineCount == 0);

        snprintf(uiContext.tagTitle[0], MAX_TAG_TITLE_LINE_LENGTH, "%s", uiContext.tagTitle[MAX_TAG_PER_PAGE_COUNT]);
        snprintf(uiContext.tagContent[0], MAX_TAG_CONTENT_LENGTH, "%s", uiContext.tagContent[MAX_TAG_PER_PAGE_COUNT]);
        uiContext.currentElementCount++;
        uiContext.pendingElement = false;
        uiContext.currentLineCount = getElementLineCount(uiContext.tagContent[0]);
    }

    if (uiContext.currentLineCount > 0) {
        TRACE("Display page and add pending element");
        snprintf(uiContext.tagTitle[MAX_TAG_PER_PAGE_COUNT], MAX_TAG_TITLE_LINE_LENGTH, "%s", line1);
        snprintf(uiContext.tagContent[MAX_TAG_PER_PAGE_COUNT], MAX_TAG_CONTENT_LENGTH, "%s", line2);
        uiContext.pendingElement = true;

        display_page(user_accept_cb, user_reject_cb);
    }
    else {
        TRACE("Add element to page");
        snprintf(uiContext.tagTitle[uiContext.currentElementCount], MAX_TAG_TITLE_LINE_LENGTH, "%s", line1);
        snprintf(uiContext.tagContent[uiContext.currentElementCount], MAX_TAG_CONTENT_LENGTH, "%s", line2);
        uiContext.currentElementCount++;
        uiContext.currentLineCount += getElementLineCount(line2);
        display_continue(user_accept_cb);
    }
}

void finish_display(callback_t user_accept_cb, callback_t user_reject_cb) {
    if (uiContext.currentLineCount > 0) {
        TRACE("Finish page display");
        display_page(user_accept_cb, user_reject_cb);
    }
    else {
        TRACE("Nothing to do");
        display_continue(user_accept_cb);
    }
}

void display_confirmation(const char* text1, const char* text2, const char* confirmText, const char* rejectText, callback_t user_accept_cb, callback_t user_reject_cb) {
    TRACE("Displaying confirmation");
    uiContext.confirmed = (char*)confirmText;
    uiContext.rejected = (char*)rejectText;

    uiContext.approved_cb = user_accept_cb;
    uiContext.abandon_cb = user_reject_cb;

    snprintf(uiContext.pageText[0], MAX_TEXT_STRING, "%s", text1);
    snprintf(uiContext.pageText[1], MAX_TEXT_STRING, "%s", text2);

    if (uiContext.pendingElement) {
        TRACE("Has pending element");
        ASSERT(uiContext.currentElementCount == 0);
        ASSERT(uiContext.currentLineCount == 0);

        snprintf(uiContext.tagTitle[0], MAX_TAG_TITLE_LINE_LENGTH, "%s", uiContext.tagTitle[MAX_TAG_PER_PAGE_COUNT]);
        snprintf(uiContext.tagContent[0], MAX_TAG_CONTENT_LENGTH, "%s", uiContext.tagContent[MAX_TAG_PER_PAGE_COUNT]);
        uiContext.currentElementCount++;
        uiContext.pendingElement = false;
        uiContext.currentLineCount = getElementLineCount(uiContext.tagContent[0]);
    }

    if (uiContext.currentElementCount > 0) {
        uiContext.pendingCb = user_accept_cb;
        uiContext.approved_cb = &_display_confirmation;
        _display_page();
    }
    else {
        _display_confirmation();
    }

}

void display_prompt(const char* text1, const char* text2, callback_t user_accept_cb, callback_t user_reject_cb) {
    TRACE("Displaying Prompt");
    uiContext.approved_cb = user_accept_cb;
    uiContext.abandon_cb = user_reject_cb;

    snprintf(uiContext.pageText[0], MAX_TEXT_STRING, "%s", text1);
    snprintf(uiContext.pageText[1], MAX_TEXT_STRING, "%s", text2);

    if (uiContext.pendingElement) {
        ASSERT(uiContext.currentElementCount == 0);
        ASSERT(uiContext.currentLineCount == 0);

        snprintf(uiContext.tagTitle[0], MAX_TAG_TITLE_LINE_LENGTH, "%s", uiContext.tagTitle[MAX_TAG_PER_PAGE_COUNT]);
        snprintf(uiContext.tagContent[0], MAX_TAG_CONTENT_LENGTH, "%s", uiContext.tagContent[MAX_TAG_PER_PAGE_COUNT]);
        uiContext.currentElementCount++;
        uiContext.pendingElement = false;
        uiContext.currentLineCount = getElementLineCount(uiContext.tagContent[0]);
    }

    if (uiContext.currentElementCount > 0) {
        uiContext.pendingCb = user_accept_cb;
        uiContext.approved_cb = &_display_prompt;
        _display_page();
    }
    else {
        _display_prompt();
    }
}

void display_warning(const char* text, callback_t user_accept_cb, callback_t user_reject_cb) {
    TRACE("Displaying Warning");
    uiContext.approved_cb = user_accept_cb;
    uiContext.abandon_cb = user_reject_cb;
    snprintf(uiContext.pageText[0], MAX_TEXT_STRING, "%s", text);

    if (uiContext.pendingElement) {
        TRACE("Has pending element");
        ASSERT(uiContext.currentElementCount == 0);
        ASSERT(uiContext.currentLineCount == 0);

        snprintf(uiContext.tagTitle[0], MAX_TAG_TITLE_LINE_LENGTH, "%s", uiContext.tagTitle[MAX_TAG_PER_PAGE_COUNT]);
        snprintf(uiContext.tagContent[0], MAX_TAG_CONTENT_LENGTH, "%s", uiContext.tagContent[MAX_TAG_PER_PAGE_COUNT]);
        uiContext.currentElementCount++;
        uiContext.pendingElement = false;
        uiContext.currentLineCount = getElementLineCount(uiContext.tagContent[0]);
    }

    if (uiContext.currentElementCount > 0) {
        uiContext.pendingCb = user_accept_cb;
        uiContext.approved_cb = &_display_warning;
        _display_page();
    }
    else {
        _display_warning();
    }
}

void display_continue(callback_t user_accept_cb) {
  nbgl_screenTickerConfiguration_t ticker = {.tickerCallback = user_accept_cb,
                                             .tickerIntervale = 0,
                                             .tickerValue = 100};
  releaseContext();
  pageContext = nbgl_pageDrawLedgerInfo(NULL, &ticker, NULL, 0);
  nbgl_refresh();
}

void ui_idle(void) {
  currentInstruction = INS_NONE;
  ui_idle_flow();
}

#endif // HAVE_NBGL
