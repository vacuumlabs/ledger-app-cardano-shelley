#ifndef H_CARDANO_APP_SIGN_TX_POOL_REGISATRATION_UI
#define H_CARDANO_APP_SIGN_TX_POOL_REGISATRATION_UI

// ============================== INIT ==============================

enum {
	HANDLE_POOL_INIT_STEP_DISPLAY = 6100,
	HANDLE_POOL_INIT_STEP_RESPOND,
	HANDLE_POOL_INIT_STEP_INVALID,
} ;

void handlePoolInit_ui_runStep();

// ============================== POOL KEY HASH / ID ==============================

enum {
	HANDLE_POOL_KEY_STEP_DISPLAY_POOL_PATH = 6200,
	HANDLE_POOL_KEY_STEP_DISPLAY_POOL_ID,
	HANDLE_POOL_KEY_STEP_RESPOND,
	HANDLE_POOL_KEY_STEP_INVALID,
} ;

void handlePoolKey_ui_runStep();

// ============================== VRF KEY HASH ==============================

enum {
	HANDLE_POOL_VRF_KEY_STEP_DISPLAY = 6300,
	HANDLE_POOL_VRF_KEY_STEP_RESPOND,
	HANDLE_POOL_VRF_KEY_STEP_INVALID,
} ;

void handlePoolVrfKey_ui_runStep();


// ============================== POOL FINANCIALS ==============================

enum {
	HANDLE_POOL_FINANCIALS_STEP_DISPLAY_PLEDGE = 6400,
	HANDLE_POOL_FINANCIALS_STEP_DISPLAY_COST,
	HANDLE_POOL_FINANCIALS_STEP_DISPLAY_MARGIN,
	HANDLE_POOL_FINANCIALS_STEP_RESPOND,
	HANDLE_POOL_FINANCIALS_STEP_INVALID,
} ;

void handlePoolFinancials_ui_runStep();


// ============================== POOL REWARD ACCOUNT ==============================

enum {
	HANDLE_POOL_REWARD_ACCOUNT_STEP_DISPLAY = 6500,
	HANDLE_POOL_REWARD_ACCOUNT_STEP_RESPOND,
	HANDLE_POOL_REWARD_ACCOUNT_STEP_INVALID,
};

void handlePoolRewardAccount_ui_runStep();


// ============================== OWNER ==============================

enum {
	HANDLE_OWNER_STEP_DISPLAY = 6600,
	HANDLE_OWNER_STEP_RESPOND,
	HANDLE_OWNER_STEP_INVALID,
};

void handleOwner_ui_runStep();


// ============================== RELAY ==============================

enum {
	HANDLE_RELAY_IP_STEP_DISPLAY_NUMBER = 6700,
	HANDLE_RELAY_IP_STEP_DISPLAY_IPV4,
	HANDLE_RELAY_IP_STEP_DISPLAY_IPV6,
	HANDLE_RELAY_IP_STEP_DISPLAY_PORT,
	HANDLE_RELAY_IP_STEP_RESPOND,
	HANDLE_RELAY_IP_STEP_INVALID,
};

void handleRelay_ip_ui_runStep();

enum {
	HANDLE_RELAY_DNS_STEP_DISPLAY_NUMBER = 6800,
	HANDLE_RELAY_DNS_STEP_DISPLAY_DNSNAME,
	HANDLE_RELAY_DNS_STEP_DISPLAY_PORT,
	HANDLE_RELAY_DNS_STEP_RESPOND,
	HANDLE_RELAY_DNS_STEP_INVALID,
};

void handleRelay_dns_ui_runStep();


// ============================== METADATA ==============================

enum {
	HANDLE_NULL_METADATA_STEP_DISPLAY = 6900,
	HANDLE_NULL_METADATA_STEP_RESPOND,
	HANDLE_NULL_METADATA_STEP_INVALID,
};

void handleNullMetadata_ui_runStep();

enum {
	HANDLE_METADATA_STEP_DISPLAY_URL = 7000,
	HANDLE_METADATA_STEP_DISPLAY_HASH,
	HANDLE_METADATA_STEP_RESPOND,
	HANDLE_METADATA_STEP_INVALID,
};

void handleMetadata_ui_runStep();

// ============================== CONFIRM ==============================

enum {
	HANDLE_CONFIRM_STEP_FINAL_NO_OWNERS = 7100,
	HANDLE_CONFIRM_STEP_FINAL_NO_RELAYS,
	HANDLE_CONFIRM_STEP_FINAL_CONFIRM,
	HANDLE_CONFIRM_STEP_RESPOND,
	HANDLE_CONFIRM_STEP_INVALID,
};

void signTxPoolRegistration_handleConfirm_ui_runStep();
#endif // H_CARDANO_APP_SIGN_TX_POOL_REGISATRATION_UI
