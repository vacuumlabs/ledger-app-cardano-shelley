#ifndef H_CARDANO_APP_DERIVE_NATIVE_SCRIPT_HASH_UI
#define H_CARDANO_APP_DERIVE_NATIVE_SCRIPT_HASH_UI
enum {
	DISPLAY_UI_STEP_POSITION = 200,
	DISPLAY_UI_STEP_TITLE,
#ifdef HAVE_NBGL
	DISPLAY_UI_STEP_SCRIPT_TYPE,
#endif // HAVE_NBGL
	DISPLAY_UI_STEP_SCRIPT_CONTENT,
	DISPLAY_UI_STEP_RESPOND,
	DISPLAY_UI_STEP_INVALID
};

void deriveScriptHash_display_ui_runStep();

void deriveNativeScriptHash_displayNativeScriptHash_callback();

void deriveNativeScriptHash_displayNativeScriptHash_bech32();

void deriveNativeScriptHash_displayNativeScriptHash_policyId();
#endif // H_CARDANO_APP_DERIVE_NATIVE_SCRIPT_HASH_UI
