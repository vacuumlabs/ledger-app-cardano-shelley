#ifndef H_CARDANO_APP_SIGN_CVOTE_UI
#define H_CARDANO_APP_SIGN_CVOTE_UI

#include "uiHelpers.h"
// ============================== INIT ==============================

enum {
	HANDLE_INIT_CONFIRM_START = 100,
	HANDLE_INIT_VOTE_PLAN_ID,
	HANDLE_INIT_PROPOSAL_INDEX,
	HANDLE_INIT_PAYLOAD_TYPE_TAG,
	HANDLE_INIT_RESPOND,
	HANDLE_INIT_INVALID,
};

void handleInit_ui_runStep();

// ============================== CONFIRM ==============================

enum {
	HANDLE_CONFIRM_STEP_FINAL_CONFIRM = 200,
	HANDLE_CONFIRM_STEP_RESPOND,
	HANDLE_CONFIRM_STEP_INVALID,
};

void handleConfirm_ui_runStep();

// ============================== WITNESS ==============================

enum {
	HANDLE_WITNESS_STEP_WARNING = 300,
	HANDLE_WITNESS_STEP_PROMPT,
	HANDLE_WITNESS_STEP_DISPLAY,
	HANDLE_WITNESS_STEP_CONFIRM,
	HANDLE_WITNESS_STEP_RESPOND,
	HANDLE_WITNESS_STEP_INVALID,
};

void handleWitness_ui_runStep();
#endif // H_CARDANO_APP_SIGN_CVOTE_UI
