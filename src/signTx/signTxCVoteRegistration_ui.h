#ifndef H_CARDANO_APP_SIGN_CVOTE_REGISTRATION_UI
#define H_CARDANO_APP_SIGN_CVOTE_REGISTRATION_UI

#ifdef HAVE_BAGL
#include "uiScreens_bagl.h"
#elif defined(HAVE_NBGL)
#include "uiScreens_nbgl.h"
#endif

// ============================== VOTING KEY ==============================

enum {
    HANDLE_VOTE_KEY_STEP_WARNING = 8200,
    HANDLE_VOTE_KEY_STEP_DISPLAY,
    HANDLE_VOTE_KEY_STEP_RESPOND,
    HANDLE_VOTE_KEY_STEP_INVALID,
};

void signTxCVoteRegistration_handleVoteKey_ui_runStep();

// ============================== DELEGATION ==============================

enum {
    HANDLE_DELEGATION_STEP_WARNING = 8300,
    HANDLE_DELEGATION_STEP_VOTE_KEY,
    HANDLE_DELEGATION_STEP_WEIGHT,
    HANDLE_DELEGATION_STEP_RESPOND,
    HANDLE_DELEGATION_STEP_INVALID,
};

void signTxCVoteRegistration_handleDelegation_ui_runStep();

// ============================== STAKE KEY ==============================

enum {
    HANDLE_STAKING_KEY_STEP_WARNING = 8400,
    HANDLE_STAKING_KEY_STEP_DISPLAY,
    HANDLE_STAKING_KEY_STEP_RESPOND,
    HANDLE_STAKING_KEY_STEP_INVALID,
};

void signTxCVoteRegistration_handleStakingKey_ui_runStep();

// ============================== VOTING REWARDS ADDRESS ==============================

enum {
    HANDLE_PAYMENT_ADDRESS_PARAMS_STEP_WARNING = 8500,
    HANDLE_PAYMENT_ADDRESS_PARAMS_STEP_DISPLAY_ADDRESS,
    HANDLE_PAYMENT_ADDRESS_PARAMS_STEP_RESPOND,
    HANDLE_PAYMENT_ADDRESS_PARAMS_STEP_INVALID
};

__noinline_due_to_stack__ void signTxCVoteRegistration_handlePaymentAddress_ui_runStep();

// ============================== NONCE ==============================

enum {
    HANDLE_NONCE_STEP_DISPLAY = 8600,
    HANDLE_NONCE_STEP_RESPOND,
    HANDLE_NONCE_STEP_INVALID,
};

void signTxCVoteRegistration_handleNonce_ui_runStep();

// ============================== VOTING PURPOSE ==============================

enum {
    HANDLE_VOTING_PURPOSE_STEP_DISPLAY = 8700,
    HANDLE_VOTING_PURPOSE_STEP_RESPOND,
    HANDLE_VOTING_PURPOSE_STEP_INVALID,
};

void signTxCVoteRegistration_handleVotingPurpose_ui_runStep();

// ============================== CONFIRM ==============================

enum {
    HANDLE_CONFIRM_STEP_FINAL_CONFIRM = 8800,
    HANDLE_CONFIRM_STEP_DISPLAY_HASH,
    HANDLE_CONFIRM_STEP_RESPOND,
    HANDLE_CONFIRM_STEP_INVALID,
};

void signTxCVoteRegistration_handleConfirm_ui_runStep();
#endif  // H_CARDANO_APP_SIGN_CVOTE_REGISTRATION_UI
