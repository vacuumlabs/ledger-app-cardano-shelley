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
#include "nbgl_page.h"
#include "nbgl_touch.h"
#include "nbgl_use_case.h"
#include "state.h"
#include "ui.h"
#include "uiHelpers.h"
#include "uiScreens_nbgl.h"

#define PAGE_START           0
#define NB_PAGE_SETTING      2
#define IS_TOUCHABLE         false
#define NB_INFO_FIELDS       3
#define NB_SETTINGS_SWITCHES 1

enum {
    SWITCH_APP_MODE_TOKEN = FIRST_USER_TOKEN,
};

static nbgl_layoutSwitch_t switches[NB_SETTINGS_SWITCHES];

static const char* const infoTypes[NB_INFO_FIELDS] = {"Version", "Developer", "Copyright"};
static const char* const infoContents[NB_INFO_FIELDS] = {APPVERSION,
                                                         "Vacuumlabs",
                                                         "(c) 2022 Ledger"};

static const nbgl_contentInfoList_t infoList = {
    .nbInfos = NB_INFO_FIELDS,
    .infoTypes = infoTypes,
    .infoContents = infoContents,
};

// settings menu definition
static void settings_control_callback(int token, uint8_t index, int page);
#define SETTING_CONTENTS_NB 1
static const nbgl_content_t contents[SETTING_CONTENTS_NB] = {
    {.type = SWITCHES_LIST,
     .content.switchesList.nbSwitches = NB_SETTINGS_SWITCHES,
     .content.switchesList.switches = switches,
     .contentActionCallback = settings_control_callback}};

static const nbgl_genericContents_t settingContents = {.callbackCallNeeded = false,
                                                       .contentsList = contents,
                                                       .nbContents = SETTING_CONTENTS_NB};

static const int INS_NONE = -1;

// Settings
static void exit(void) {
    os_sched_exit(-1);
}

static void settings_control_callback(int token, uint8_t index, int page) {
    UNUSED(page);
    switch (token) {
        case SWITCH_APP_MODE_TOKEN:
            app_mode_set_expert(index);
            switches[0].initState = app_mode_expert();
            break;

        default:
            PRINTF("Should not happen !");
            break;
    }
}

void ui_idle_flow(void) {
    // We need to make sure the ui context is reset even if the app restarts
    nbgl_reset_transaction_full_context();

    switches[0].text = "Expert mode";
    switches[0].subText = "Enable expert mode";
    switches[0].token = SWITCH_APP_MODE_TOKEN;
    switches[0].tuneId = TUNE_TAP_CASUAL;
    switches[0].initState = app_mode_expert();

    nbgl_useCaseHomeAndSettings("Cardano",
                                &C_cardano_64,
                                NULL,
                                INIT_HOME_PAGE,
                                &settingContents,
                                &infoList,
                                NULL,
                                exit);
}

void ui_idle(void) {
    currentInstruction = INS_NONE;
}
#endif  // HAVE_NBGL
