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
#include "nbgl_use_case.h"

#define MAX_LINE_PER_PAGE_COUNT 9
#define MAX_TAG_PER_PAGE_COUNT 5
#define MAX_TAG_TITLE_LINE_LENGTH 30
#define MAX_TAG_CONTENT_LENGTH 200
#define MAX_TAG_CONTENT_CHAR_PER_LINE 22
#define MAX_TEXT_STRING 50

#define PAGE_START 0
#define NB_PAGE_SETTING 2
#define IS_TOUCHABLE false
#define NB_INFO_FIELDS 3
#define NB_SETTINGS_SWITCHES 1

enum {
  SWITCH_APP_MODE_TOKEN = FIRST_USER_TOKEN,
};

enum {
  CANCEL_PROMPT_TOKEN = 1,
  ACCEPT_PAGE_TOKEN,
  CONFIRMATION_MESSAGE_TOKEN,
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
  bool lightConfirmation;
} UiContext_t;

static const int INS_NONE = -1;

static nbgl_layoutSwitch_t switches[NB_SETTINGS_SWITCHES];

static const char* const infoTypes[] = {"Version", "Developer", "Copyright"};
static const char* const infoContents[] = {APPVERSION, "Ledger", "(c) 2022 Ledger"};
static nbgl_page_t *pageContext;
static nbgl_layoutTagValue_t tagValues[5];
static UiContext_t uiContext = {
    .rejected = NULL,
    .confirmed = NULL,
    .currentLineCount = 0,
    .currentElementCount = 0,
    .lightConfirmation = 0,
};

// Forward declaration
static void _display_warning(void);
static void _display_page(void);
static void _display_confirmation(void);
static void _display_light_confirmation(void);
static void _display_prompt(void);
static void display_cancel(void);
static void display_confirmation_message(void);
static void display_cancel_message(void);
static void ui_idle_flow(void);

static void releaseContext(void) {
  if (pageContext != NULL) {
    nbgl_pageRelease(pageContext);
    pageContext = NULL;
  }
}

static void exit(void) {
    os_sched_exit(-1);
}

static bool settings_navigation_cb(uint8_t page, nbgl_pageContent_t *content) {
    if (page == 0) {
        switches[0].text = (char*)"Enable expert mode";
        switches[0].subText = (char*)"Select application mode";
        switches[0].token = SWITCH_APP_MODE_TOKEN;
        switches[0].tuneId = TUNE_TAP_CASUAL;
        switches[0].initState = app_mode_expert();

        content->type = SWITCHES_LIST;
        content->switchesList.nbSwitches = NB_SETTINGS_SWITCHES;
        content->switchesList.switches = (nbgl_layoutSwitch_t*) switches;
    }
    else if (page == 1) {
        content->type = INFOS_LIST;
        content->infosList.nbInfos = NB_INFO_FIELDS;
        content->infosList.infoTypes = (const char**) infoTypes;
        content->infosList.infoContents = (const char**) infoContents;
    }
    else {
        return false;
    }
    return true;
}

static void settings_control_cb(int token, uint8_t index) {
    UNUSED(index);
    switch(token)
    {
        case SWITCH_APP_MODE_TOKEN:
            app_mode_set_expert(index);
            break;

        default:
            PRINTF("Should not happen !");
            break;
    }
}

static void ui_menu_settings(void) {
  nbgl_useCaseSettings((char*)"Cardano settings", PAGE_START, NB_PAGE_SETTING, IS_TOUCHABLE, ui_idle_flow, 
          settings_navigation_cb, settings_control_cb);
}

static void ui_idle_flow(void) {
  nbgl_useCaseHome((char*)"Cardano", &C_cardano_64, NULL, true, ui_menu_settings, exit);
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
        case ACCEPT_PAGE_TOKEN:
            uiContext.currentElementCount = 0;
            uiContext.currentLineCount = 0;
            uiContext.approved_cb();
            break;
        case CONFIRMATION_MESSAGE_TOKEN:
            display_confirmation_message();
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
    pageContext = nbgl_pageDrawGenericContent(&display_callback, &info, &content);
    nbgl_refresh();

#ifdef HEADLESS
    nbgl_screenTickerConfiguration_t ticker = {
        .tickerCallback = &headless_cb,
        .tickerIntervale = 0,
        .tickerValue = 100};
    pageContext = nbgl_pageDrawLedgerInfo(NULL, &ticker, NULL, 0);
#endif
}

static void light_confirm_cb(bool confirm) {
    if (confirm) {
        display_confirmation_message();
    }
    else {
        display_cancel_message();
    }
}

static void _display_light_confirmation(void) {
    TRACE("_light_confirmation");
    if (uiContext.pendingCb) {
        uiContext.approved_cb = uiContext.pendingCb;
        uiContext.pendingCb = NULL;
    }

    nbgl_useCaseChoice(&C_cardano_64, uiContext.pageText[0], (char*)"", (char*)"Confirm", (char*)"Cancel", light_confirm_cb);

#ifdef HEADLESS
    nbgl_screenTickerConfiguration_t ticker = {
        .tickerCallback = &headless_cb,
        .tickerIntervale = 0,
        .tickerValue = 100};
    pageContext = nbgl_pageDrawLedgerInfo(NULL, &ticker, NULL, 0);
#endif
}

static void _display_page(void) {
    TRACE("_page");

    for (uint8_t i = 0; i < uiContext.currentElementCount; i++) {
        tagValues[i].item = uiContext.tagTitle[i];
        tagValues[i].value = uiContext.tagContent[i];
    }

    releaseContext();
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

    pageContext = nbgl_pageDrawGenericContent(&display_callback, &info, &content);

#ifdef HEADLESS
    uiContext.currentElementCount = 0;
    uiContext.currentLineCount = 0;
    nbgl_refresh();
    nbgl_screenTickerConfiguration_t ticker = {
        .tickerCallback = &display_callback,
        .tickerIntervale = 0,
        .tickerValue = 100};
    pageContext = nbgl_pageDrawLedgerInfo(NULL, &ticker, NULL, 0);
#endif
}

static void _display_prompt(void) {
    TRACE("_prompt");
    if (uiContext.pendingCb) {
        uiContext.approved_cb = uiContext.pendingCb;
        uiContext.pendingCb = NULL;
    }

    nbgl_useCaseReviewStart(&C_cardano_64, uiContext.pageText[0], uiContext.pageText[1], 
           (char*) "Reject if not sure", uiContext.approved_cb, &display_cancel);
#ifdef HEADLESS
    nbgl_screenTickerConfiguration_t ticker = {
        .tickerCallback = uiContext.approved_cb,
        .tickerIntervale = 0,
        .tickerValue = 100};
    pageContext = nbgl_pageDrawLedgerInfo(NULL, &ticker, NULL, 0);
#endif
}

static void _display_warning(void) {
    TRACE("_warning");
    if (uiContext.pendingCb) {
        uiContext.approved_cb = uiContext.pendingCb;
        uiContext.pendingCb = NULL;
    }

    nbgl_useCaseReviewStart(&C_warning64px, (char*)"WARNING", uiContext.pageText[0], 
            (char*)"Reject if not sure", uiContext.approved_cb, &display_cancel);
#ifdef HEADLESS
    nbgl_screenTickerConfiguration_t ticker = {
        .tickerCallback = uiContext.approved_cb,
        .tickerIntervale = 0,
        .tickerValue = 100};
    pageContext = nbgl_pageDrawLedgerInfo(NULL, &ticker, NULL, 0);
#endif
}

static void display_page(callback_t user_accept_cb, callback_t user_reject_cb) {
    TRACE("Displaying page");
    uiContext.approved_cb = user_accept_cb;
    uiContext.abandon_cb = user_reject_cb;

    _display_page();
}

static void display_confirmation_message(void) {
    if (uiContext.approved_cb) {
        uiContext.approved_cb();
    }
    
    if (uiContext.confirmed) {
        nbgl_useCaseStatus(uiContext.confirmed, true, ui_home);
    }
    else {
        nbgl_useCaseStatus((char*)"ACTION\nCONFIRMED", true, ui_home);
    }

    uiContext.lightConfirmation = false;
    uiContext.rejected = NULL;
    uiContext.confirmed = NULL;
    uiContext.currentElementCount = 0;
    uiContext.currentLineCount = 0;
}

static void display_cancel_message(void) {
    if (uiContext.abandon_cb) {
        uiContext.abandon_cb();
    }

    ui_idle();

    if (uiContext.rejected) {
        nbgl_useCaseStatus(uiContext.rejected, false, ui_home);
    }
    else {
        nbgl_useCaseStatus((char*)"Action rejected", false, ui_home);
    }

    uiContext.lightConfirmation = false;
    uiContext.rejected = NULL;
    uiContext.confirmed = NULL;
    uiContext.currentElementCount = 0;
    uiContext.currentLineCount = 0;
}


static void display_cancel(void) {
    if (uiContext.lightConfirmation) {
        display_cancel_message();
    }
    else {
        nbgl_useCaseConfirm((char*)"Reject ?", NULL, (char*)"Yes, Reject", (char*)"Go back", display_cancel_message);
    }
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
        if (uiContext.lightConfirmation) {
            uiContext.approved_cb = &_display_light_confirmation;
        }
        else {
            uiContext.approved_cb = &_display_confirmation;
        }
        _display_page();
    }
    else {
        if (uiContext.lightConfirmation) {
            _display_light_confirmation();
        }
        else {
            _display_confirmation();
        }
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

void set_light_confirmation(bool needed) {
    uiContext.lightConfirmation = needed;
}

void ui_idle(void) {
  currentInstruction = INS_NONE;
  ui_idle_flow();
}

#endif // HAVE_NBGL
