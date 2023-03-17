#ifndef H_CARDANO_APP_SIGN_TX_UI
#define H_CARDANO_APP_SIGN_TX_UI

// ============================== INIT ==============================

enum {
	HANDLE_INIT_STEP_PROMPT_SIGNINGMODE = 100,
	HANDLE_INIT_STEP_DISPLAY_NETWORK_DETAILS,
	HANDLE_INIT_STEP_SCRIPT_RUNNING_WARNING,
	HANDLE_INIT_STEP_NO_COLLATERAL_WARNING,
	HANDLE_INIT_STEP_UNKNOWN_COLLATERAL_WARNING,
	HANDLE_INIT_STEP_NO_SCRIPT_DATA_HASH_WARNING,
	HANDLE_INIT_STEP_RESPOND,
	HANDLE_INIT_STEP_INVALID,
} ;

void signTx_handleInit_ui_runStep();

// ============================== AUXILIARY DATA ==============================

enum {
	HANDLE_AUX_DATA_ARBITRARY_HASH_STEP_DISPLAY = 800,
	HANDLE_AUX_DATA_ARBITRARY_HASH_STEP_RESPOND,
	HANDLE_AUX_DATA_ARBITRARY_HASH_STEP_INVALID,
};

void signTx_handleAuxDataArbitraryHash_ui_runStep();

enum {
	HANDLE_AUX_DATA_CVOTE_REGISTRATION_STEP_DISPLAY = 850,
	HANDLE_AUX_DATA_CVOTE_REGISTRATION_STEP_RESPOND,
	HANDLE_AUX_DATA_CVOTE_REGISTRATION_STEP_INVALID,
};

void signTx_handleAuxDataCVoteRegistration_ui_runStep();

// ============================== INPUTS ==============================

enum {
	HANDLE_INPUT_STEP_DISPLAY = 200,
	HANDLE_INPUT_STEP_RESPOND,
	HANDLE_INPUT_STEP_INVALID,
};

void signTx_handleInput_ui_runStep();

// ============================== FEE ==============================

enum {
	HANDLE_FEE_STEP_DISPLAY = 400,
	HANDLE_FEE_STEP_RESPOND,
	HANDLE_FEE_STEP_INVALID,
};

void signTx_handleFee_ui_runStep();

// ============================== TTL ==============================

enum {
	HANDLE_TTL_STEP_DISPLAY = 500,
	HANDLE_TTL_STEP_RESPOND,
	HANDLE_TTL_STEP_INVALID,
};

void signTx_handleTtl_ui_runStep();

// ============================== CERTIFICATES ==============================

enum {
	HANDLE_CERTIFICATE_STEP_DISPLAY_OPERATION = 600,
	HANDLE_CERTIFICATE_STEP_DISPLAY_STAKING_KEY,
	HANDLE_CERTIFICATE_STEP_CONFIRM,
	HANDLE_CERTIFICATE_STEP_RESPOND,
	HANDLE_CERTIFICATE_STEP_INVALID,
};

void signTx_handleCertificate_ui_runStep();

enum {
	HANDLE_CERTIFICATE_POOL_RETIREMENT_STEP_DISPLAY_OPERATION = 650,
	HANDLE_CERTIFICATE_POOL_RETIREMENT_STEP_DISPLAY_EPOCH,
	HANDLE_CERTIFICATE_POOL_RETIREMENT_STEP_CONFIRM,
	HANDLE_CERTIFICATE_POOL_RETIREMENT_STEP_RESPOND,
	HANDLE_CERTIFICATE_POOL_RETIREMENT_STEP_INVALID,
};

void signTx_handleCertificatePoolRetirement_ui_runStep();

// ============================== WITHDRAWALS ==============================

enum {
	HANDLE_WITHDRAWAL_STEP_DISPLAY_AMOUNT = 700,
	HANDLE_WITHDRAWAL_STEP_DISPLAY_PATH,
	HANDLE_WITHDRAWAL_STEP_RESPOND,
	HANDLE_WITHDRAWAL_STEP_INVALID,
};

void signTx_handleWithdrawal_ui_runStep();

// ============================== VALIDITY INTERVAL START ==============================

enum {
	HANDLE_VALIDITY_INTERVAL_START_STEP_DISPLAY = 900,
	HANDLE_VALIDITY_INTERVAL_START_STEP_RESPOND,
	HANDLE_VALIDITY_INTERVAL_START_STEP_INVALID,
};

void signTx_handleValidityInterval_ui_runStep();

// ========================= SCRIPT DATA HASH ==========================


enum {
	HANDLE_SCRIPT_DATA_HASH_STEP_DISPLAY = 1200,
	HANDLE_SCRIPT_DATA_HASH_STEP_RESPOND,
	HANDLE_SCRIPT_DATA_HASH_STEP_INVALID,
};

void signTx_handleScriptDataHash_ui_runStep();

// ========================= REQUIRED SIGNERS ===========================

enum {
	HANDLE_REQUIRED_SIGNERS_STEP_DISPLAY = 1400,
	HANDLE_REQUIRED_SIGNERS_STEP_RESPOND,
	HANDLE_REQUIRED_SIGNERS_STEP_INVALID,
};

void signTx_handleRequiredSigner_ui_runStep();

// ========================= TOTAL COLLATERAL ===========================

enum {
	HANDLE_TOTAL_COLLATERAL_STEP_DISPLAY = 400,
	HANDLE_TOTAL_COLLATERAL_STEP_RESPOND,
	HANDLE_TOTAL_COLLATERAL_STEP_INVALID,
};

void signTx_handleTotalCollateral_ui_runStep();

// ============================== CONFIRM ==============================

enum {
	HANDLE_CONFIRM_STEP_TXID = 1000,
	HANDLE_CONFIRM_STEP_FINAL_CONFIRM,
	HANDLE_CONFIRM_STEP_RESPOND,
	HANDLE_CONFIRM_STEP_INVALID,
};

void signTx_handleConfirm_ui_runStep();

// ============================== WITNESS ==============================

enum {
	HANDLE_WITNESS_STEP_WARNING = 1100,
	HANDLE_WITNESS_STEP_DISPLAY,
	HANDLE_WITNESS_STEP_CONFIRM,
	HANDLE_WITNESS_STEP_RESPOND,
	HANDLE_WITNESS_STEP_INVALID,
};

void signTx_handleWitness_ui_runStep();
#endif // H_CARDANO_APP_SIGN_TX_UI
