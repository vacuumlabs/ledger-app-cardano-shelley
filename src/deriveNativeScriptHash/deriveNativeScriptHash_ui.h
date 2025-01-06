#ifndef H_CARDANO_APP_DERIVE_NATIVE_SCRIPT_HASH_UI
#define H_CARDANO_APP_DERIVE_NATIVE_SCRIPT_HASH_UI

#ifdef APP_FEATURE_NATIVE_SCRIPT_HASH

enum {
    DISPLAY_UI_STEP_POSITION = 200,
#ifdef HAVE_NBGL
    DISPLAY_UI_STEP_SCRIPT_TYPE,
#endif  // HAVE_NBGL
    DISPLAY_UI_STEP_SCRIPT_CONTENT,
    DISPLAY_UI_STEP_RESPOND,
    DISPLAY_UI_STEP_INVALID
};

void deriveScriptHash_display_ui_runStep();

void deriveNativeScriptHash_displayNativeScriptHash_callback();

void deriveNativeScriptHash_displayNativeScriptHash_bech32();

void deriveNativeScriptHash_displayNativeScriptHash_policyId();

#endif  // APP_FEATURE_NATIVE_SCRIPT_HASH

#endif  // H_CARDANO_APP_DERIVE_NATIVE_SCRIPT_HASH_UI
