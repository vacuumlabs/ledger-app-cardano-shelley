#ifndef H_CARDANO_APP_SIGN_MSG_UI
#define H_CARDANO_APP_SIGN_MSG_UI

#include "uiHelpers.h"

// ============================== INIT ==============================

enum {
    HANDLE_INIT_HASH_PAYLOAD = 100,
    HANDLE_INIT_WITNESS_PATH,
    HANDLE_INIT_ADDRESS_FIELD,
    HANDLE_INIT_RESPOND,
    HANDLE_INIT_INVALID,
};

void signMsg_handleInit_ui_runStep();

// ============================== CHUNK ==============================

enum {
    HANDLE_CHUNK_STEP_INTRO = 200,
    HANDLE_CHUNK_STEP_DISPLAY,
    HANDLE_CHUNK_STEP_RESPOND,
    HANDLE_CHUNK_STEP_INVALID,
};

void signMsg_handleChunk_ui_runStep();

// ============================== CONFIRM ==============================

enum {
    HANDLE_CONFIRM_STEP_MSG_HASH = 300,
    HANDLE_CONFIRM_STEP_FINAL_CONFIRM,
    HANDLE_CONFIRM_STEP_RESPOND,
    HANDLE_CONFIRM_STEP_INVALID,
};

void signMsg_handleConfirm_ui_runStep();

#endif  // H_CARDANO_APP_SIGN_MSG_UI
