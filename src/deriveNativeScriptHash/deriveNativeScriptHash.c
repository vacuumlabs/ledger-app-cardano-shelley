#ifdef APP_FEATURE_NATIVE_SCRIPT_HASH

#include "deriveNativeScriptHash.h"
#include "deriveNativeScriptHash_ui.h"
#include "state.h"
#include "textUtils.h"

#ifdef HAVE_BAGL
#include "uiScreens_bagl.h"
#elif defined(HAVE_NBGL)
#include "uiScreens_nbgl.h"
#endif

static ins_derive_native_script_hash_context_t* ctx =
    &(instructionState.deriveNativeScriptHashContext);

// Helper functions

#define TRACE_WITH_CTX(message, ...)                    \
    TRACE(message "level = %u, remaining scripts = %u", \
          ##__VA_ARGS__,                                \
          ctx->level,                                   \
          ctx->complexScripts[ctx->level].remainingScripts)

static inline bool areMoreScriptsExpected() {
    // if the number of remaining scripts is not bigger than 0, then this request
    // is invalid in the current context, as Ledger was not expecting another
    // script to be parsed
    ASSERT(ctx->level < MAX_SCRIPT_DEPTH);
    return ctx->complexScripts[ctx->level].remainingScripts > 0;
}

static inline bool isComplexScriptFinished() {
    ASSERT(ctx->level < MAX_SCRIPT_DEPTH);
    return ctx->level > 0 && ctx->complexScripts[ctx->level].remainingScripts == 0;
}

static inline void complexScriptFinished() {
    while (isComplexScriptFinished()) {
        ASSERT(ctx->level > 0);
        ctx->level--;

        ASSERT(ctx->level < MAX_SCRIPT_DEPTH);
        ASSERT(ctx->complexScripts[ctx->level].remainingScripts > 0);
        ctx->complexScripts[ctx->level].remainingScripts--;

        TRACE_WITH_CTX("complex script finished, ");
    }
}

static inline void simpleScriptFinished() {
    ASSERT(ctx->level < MAX_SCRIPT_DEPTH);
    ASSERT(ctx->complexScripts[ctx->level].remainingScripts > 0);
    ctx->complexScripts[ctx->level].remainingScripts--;

    TRACE_WITH_CTX("simple script finished, ");

    if (isComplexScriptFinished()) {
        complexScriptFinished();
    }
}

// UI
#define UI_DISPLAY_SCRIPT(UI_TYPE)               \
    {                                            \
        ctx->ui_scriptType = UI_TYPE;            \
        ctx->ui_step = DISPLAY_UI_STEP_POSITION; \
        deriveScriptHash_display_ui_runStep();   \
    }

// Start complex native script

static void deriveNativeScriptHash_handleAll(read_view_t* view) {
    TRACE_WITH_CTX("");
    VALIDATE(view_remainingSize(view) == 0, ERR_INVALID_DATA);

    ASSERT(ctx->level < MAX_SCRIPT_DEPTH);
    nativeScriptHashBuilder_startComplexScript_all(
        &ctx->hashBuilder,
        ctx->complexScripts[ctx->level].remainingScripts);

    UI_DISPLAY_SCRIPT(UI_SCRIPT_ALL);
}

static void deriveNativeScriptHash_handleAny(read_view_t* view) {
    TRACE_WITH_CTX("");
    VALIDATE(view_remainingSize(view) == 0, ERR_INVALID_DATA);

    ASSERT(ctx->level < MAX_SCRIPT_DEPTH);
    nativeScriptHashBuilder_startComplexScript_any(
        &ctx->hashBuilder,
        ctx->complexScripts[ctx->level].remainingScripts);

    UI_DISPLAY_SCRIPT(UI_SCRIPT_ANY);
}

static void deriveNativeScriptHash_handleNofK(read_view_t* view) {
    // parse data
    ctx->scriptContent.requiredScripts = parse_u4be(view);
    TRACE_WITH_CTX("required scripts = %u, ", ctx->scriptContent.requiredScripts);

    VALIDATE(view_remainingSize(view) == 0, ERR_INVALID_DATA);

    // validate that the received requiredScripts count makes sense
    ASSERT(ctx->level < MAX_SCRIPT_DEPTH);
    VALIDATE(ctx->complexScripts[ctx->level].remainingScripts >= ctx->scriptContent.requiredScripts,
             ERR_INVALID_DATA);

    nativeScriptHashBuilder_startComplexScript_n_of_k(
        &ctx->hashBuilder,
        ctx->scriptContent.requiredScripts,
        ctx->complexScripts[ctx->level].remainingScripts);

    UI_DISPLAY_SCRIPT(UI_SCRIPT_N_OF_K);
}

static void deriveNativeScriptHash_handleComplexScriptStart(read_view_t* view) {
    VALIDATE(areMoreScriptsExpected(), ERR_INVALID_STATE);

    // check if we can increase the level without breaking the MAX_SCRIPT_DEPTH constraint
    VALIDATE(ctx->level + 1 < MAX_SCRIPT_DEPTH, ERR_INVALID_DATA);
    ctx->level++;

    // the nativeScriptType is validated below, in the switch statement
    uint8_t nativeScriptType = parse_u1be(view);
    TRACE("native complex script type = %u", nativeScriptType);

    ASSERT(ctx->level < MAX_SCRIPT_DEPTH);
    ctx->complexScripts[ctx->level].remainingScripts = parse_u4be(view);
    ctx->complexScripts[ctx->level].totalScripts = ctx->complexScripts[ctx->level].remainingScripts;

    // these handlers might read additional data from the view
    switch (nativeScriptType) {
#define CASE(TYPE, HANDLER) \
    case TYPE:              \
        HANDLER(view);      \
        break;
        CASE(NATIVE_SCRIPT_ALL, deriveNativeScriptHash_handleAll);
        CASE(NATIVE_SCRIPT_ANY, deriveNativeScriptHash_handleAny);
        CASE(NATIVE_SCRIPT_N_OF_K, deriveNativeScriptHash_handleNofK);
#undef CASE
        default:
            THROW(ERR_INVALID_DATA);
    }

    if (isComplexScriptFinished()) {
        complexScriptFinished();
    }
}

// Simple native scripts

static void deriveNativeScriptHash_handleDeviceOwnedPubkey(read_view_t* view) {
    view_skipBytes(view,
                   bip44_parseFromWire(&ctx->scriptContent.pubkeyPath,
                                       VIEW_REMAINING_TO_TUPLE_BUF_SIZE(view)));
    TRACE("pubkey given by path:");
    BIP44_PRINTF(&ctx->scriptContent.pubkeyPath);
    PRINTF("\n");

    VALIDATE(view_remainingSize(view) == 0, ERR_INVALID_DATA);

    uint8_t pubkeyHash[ADDRESS_KEY_HASH_LENGTH] = {0};
    bip44_pathToKeyHash(&ctx->scriptContent.pubkeyPath, pubkeyHash, ADDRESS_KEY_HASH_LENGTH);
    nativeScriptHashBuilder_addScript_pubkey(&ctx->hashBuilder, pubkeyHash, SIZEOF(pubkeyHash));

    UI_DISPLAY_SCRIPT(UI_SCRIPT_PUBKEY_PATH);
}

static void deriveNativeScriptHash_handleThirdPartyPubkey(read_view_t* view) {
    STATIC_ASSERT(SIZEOF(ctx->scriptContent.pubkeyHash) == ADDRESS_KEY_HASH_LENGTH,
                  "incorrect key hash size in script");
    view_parseBuffer(ctx->scriptContent.pubkeyHash, view, ADDRESS_KEY_HASH_LENGTH);
    TRACE_BUFFER(ctx->scriptContent.pubkeyHash, ADDRESS_KEY_HASH_LENGTH);

    VALIDATE(view_remainingSize(view) == 0, ERR_INVALID_DATA);

    nativeScriptHashBuilder_addScript_pubkey(&ctx->hashBuilder,
                                             ctx->scriptContent.pubkeyHash,
                                             SIZEOF(ctx->scriptContent.pubkeyHash));

    UI_DISPLAY_SCRIPT(UI_SCRIPT_PUBKEY_HASH);
}

static void deriveNativeScriptHash_handlePubkey(read_view_t* view) {
    uint8_t pubkeyType = parse_u1be(view);
    TRACE("pubkey type = %u", pubkeyType);

    switch (pubkeyType) {
        case KEY_REFERENCE_PATH:
            deriveNativeScriptHash_handleDeviceOwnedPubkey(view);
            return;
        case KEY_REFERENCE_HASH:
            deriveNativeScriptHash_handleThirdPartyPubkey(view);
            return;
        // any other value for the pubkey type is invalid
        default:
            THROW(ERR_INVALID_DATA);
    }
}

static void deriveNativeScriptHash_handleInvalidBefore(read_view_t* view) {
    ctx->scriptContent.timelock = parse_u8be(view);
    TRACE("invalid_before timelock");
    TRACE_UINT64(ctx->scriptContent.timelock);

    VALIDATE(view_remainingSize(view) == 0, ERR_INVALID_DATA);

    nativeScriptHashBuilder_addScript_invalidBefore(&ctx->hashBuilder, ctx->scriptContent.timelock);

    UI_DISPLAY_SCRIPT(UI_SCRIPT_INVALID_BEFORE);
}

static void deriveNativeScriptHash_handleInvalidHereafter(read_view_t* view) {
    ctx->scriptContent.timelock = parse_u8be(view);
    TRACE("invalid_hereafter timelock");
    TRACE_UINT64(ctx->scriptContent.timelock);

    VALIDATE(view_remainingSize(view) == 0, ERR_INVALID_DATA);

    nativeScriptHashBuilder_addScript_invalidHereafter(&ctx->hashBuilder,
                                                       ctx->scriptContent.timelock);

    UI_DISPLAY_SCRIPT(UI_SCRIPT_INVALID_HEREAFTER);
}

#undef UI_DISPLAY_SCRIPT

static void deriveNativeScriptHash_handleSimpleScript(read_view_t* view) {
    VALIDATE(areMoreScriptsExpected(), ERR_INVALID_STATE);

    uint8_t nativeScriptType = parse_u1be(view);
    TRACE("native simple script type = %u", nativeScriptType);

    // parse data
    switch (nativeScriptType) {
#define CASE(TYPE, HANDLER) \
    case TYPE:              \
        HANDLER(view);      \
        break;
        CASE(NATIVE_SCRIPT_PUBKEY, deriveNativeScriptHash_handlePubkey);
        CASE(NATIVE_SCRIPT_INVALID_BEFORE, deriveNativeScriptHash_handleInvalidBefore);
        CASE(NATIVE_SCRIPT_INVALID_HEREAFTER, deriveNativeScriptHash_handleInvalidHereafter);
#undef CASE
        default:
            THROW(ERR_INVALID_DATA);
    }

    simpleScriptFinished();
}

// Whole native script finish

typedef enum {
    DISPLAY_NATIVE_SCRIPT_HASH_BECH32 = 1,
    DISPLAY_NATIVE_SCRIPT_HASH_POLICY_ID = 2,
} display_format;

static void deriveNativeScriptHash_handleWholeNativeScriptFinish(read_view_t* view) {
    // we finish only if there are no more scripts to be processed
    VALIDATE(ctx->level == 0 && ctx->complexScripts[0].remainingScripts == 0, ERR_INVALID_STATE);

    uint8_t displayFormat = parse_u1be(view);
    TRACE("whole native script received, display format = %u", displayFormat);

    VALIDATE(view_remainingSize(view) == 0, ERR_INVALID_DATA);

    switch (displayFormat) {
#define CASE(FORMAT, DISPLAY_FN)                                \
    case FORMAT:                                                \
        nativeScriptHashBuilder_finalize(&ctx->hashBuilder,     \
                                         ctx->scriptHashBuffer, \
                                         SCRIPT_HASH_LENGTH);   \
        DISPLAY_FN();                                           \
        break;
        CASE(DISPLAY_NATIVE_SCRIPT_HASH_BECH32,
             deriveNativeScriptHash_displayNativeScriptHash_bech32);
        CASE(DISPLAY_NATIVE_SCRIPT_HASH_POLICY_ID,
             deriveNativeScriptHash_displayNativeScriptHash_policyId);
#undef CASE
        default:
            THROW(ERR_INVALID_DATA);
    }
}

typedef void subhandler_fn_t(read_view_t* view);

enum {
    STAGE_COMPLEX_SCRIPT_START = 0x01,
    STAGE_ADD_SIMPLE_SCRIPT = 0x02,
    STAGE_WHOLE_NATIVE_SCRIPT_FINISH = 0x03,
};

static subhandler_fn_t* lookup_subhandler(uint8_t p1) {
    switch (p1) {
#define CASE(P1, HANDLER) \
    case P1:              \
        return HANDLER;
#define DEFAULT(HANDLER) \
    default:             \
        return HANDLER;
        CASE(STAGE_COMPLEX_SCRIPT_START, deriveNativeScriptHash_handleComplexScriptStart);
        CASE(STAGE_ADD_SIMPLE_SCRIPT, deriveNativeScriptHash_handleSimpleScript);
        CASE(STAGE_WHOLE_NATIVE_SCRIPT_FINISH, deriveNativeScriptHash_handleWholeNativeScriptFinish)
        DEFAULT(NULL);
#undef CASE
#undef DEFAULT
    }
}

uint16_t deriveNativeScriptHash_handleAPDU(uint8_t p1,
                                           uint8_t p2,
                                           const uint8_t* wireDataBuffer,
                                           size_t wireDataSize,
                                           bool isNewCall) {
    TRACE("P1 = 0x%x, P2 = 0x%x, isNewCall = %u", p1, p2, isNewCall);
    VALIDATE(p2 == P2_UNUSED, ERR_INVALID_REQUEST_PARAMETERS);
    TRACE_BUFFER(wireDataBuffer, wireDataSize);

    // initialize state
    if (isNewCall) {
        explicit_bzero(ctx, SIZEOF(*ctx));
        ctx->level = 0;
        ctx->complexScripts[ctx->level].remainingScripts = 1;
        nativeScriptHashBuilder_init(&ctx->hashBuilder);
    }

    read_view_t view = make_read_view(wireDataBuffer, wireDataBuffer + wireDataSize);

    subhandler_fn_t* subhandler = lookup_subhandler(p1);
    VALIDATE(subhandler != NULL, ERR_INVALID_REQUEST_PARAMETERS);
    subhandler(&view);
    return ERR_NO_RESPONSE;
}

#undef TRACE_WITH_CTX

#endif  // APP_FEATURE_NATIVE_SCRIPT_HASH
