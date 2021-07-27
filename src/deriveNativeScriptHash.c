#include "deriveNativeScriptHash.h"
#include "state.h"
#include "textUtils.h"
#include "uiScreens.h"

static ins_derive_native_script_hash_context_t* ctx = &(instructionState.deriveNativeScriptHashContext);

// Helper functions

#define TRACE_WITH_CTX(message, ...) TRACE(message "level = %u, remaining scripts = %u", ##__VA_ARGS__, ctx->level, ctx->complexScripts[ctx->level].remainingScripts)

static inline bool areMoreScriptsExpected()
{
	// if the number of remaining scripts is not bigger than 0, then this request
	// is invalid in the current context, as Ledger was not expecting another
	// script to be parsed
	return ctx->complexScripts[ctx->level].remainingScripts > 0;
}

static inline bool isComplexScriptFinished()
{
	return ctx->level > 0 && ctx->complexScripts[ctx->level].remainingScripts == 0;
}

static inline void complexScriptFinished()
{
	while (isComplexScriptFinished()) {
		ASSERT(ctx->level > 0);
		ctx->level--;

		ASSERT(ctx->complexScripts[ctx->level].remainingScripts > 0);
		ctx->complexScripts[ctx->level].remainingScripts--;

		TRACE_WITH_CTX("complex script finished, ");
	}
}

static inline void simpleScriptFinished()
{
	ASSERT(ctx->complexScripts[ctx->level].remainingScripts > 0);
	ctx->complexScripts[ctx->level].remainingScripts--;

	TRACE_WITH_CTX("simple script finished, ");

	if (isComplexScriptFinished()) {
		complexScriptFinished();
	}
}

// UI

static void deriveScriptHash_display_ui_callback()
{
	io_send_buf(SUCCESS, NULL, 0);
	ui_displayBusy();
}

// Start complex native script

static void deriveNativeScriptHash_handleAll(read_view_t* view)
{
	VALIDATE(view_remainingSize(view) == 0, ERR_INVALID_DATA);
	TRACE_WITH_CTX("");

	nativeScriptHashBuilder_startComplexScript_all(&ctx->hashBuilder, ctx->complexScripts[ctx->level].remainingScripts);

	// max possible length 34: "Contains x nested scripts"
	// where x is 2^32-1
	char text[35];
	snprintf(text, SIZEOF(text), "Contains %d nested scripts", ctx->complexScripts[ctx->level].remainingScripts);

	ui_displayPaginatedText(
	        // TODO: proper UI screen headers with numbered sections
	        "Script - ALL",
	        text,
	        deriveScriptHash_display_ui_callback
	);
}

static void deriveNativeScriptHash_handleAny(read_view_t* view)
{
	VALIDATE(view_remainingSize(view) == 0, ERR_INVALID_DATA);
	TRACE_WITH_CTX("");

	nativeScriptHashBuilder_startComplexScript_any(&ctx->hashBuilder, ctx->complexScripts[ctx->level].remainingScripts);

	// max possible length 34: "Contains x nested scripts"
	// where x is 2^32-1
	char text[35];
	snprintf(text, SIZEOF(text), "Contains %u nested scripts", ctx->complexScripts[ctx->level].remainingScripts);

	ui_displayPaginatedText(
	        "Script - ANY",
	        text,
	        deriveScriptHash_display_ui_callback
	);
}

static void deriveNativeScriptHash_handleNofK(read_view_t* view)
{
	// parse data
	uint32_t requiredScripts = parse_u4be(view);

	VALIDATE(view_remainingSize(view) == 0, ERR_INVALID_DATA);
	TRACE_WITH_CTX("required scripts = %u, ", requiredScripts);

	// validate that the received requiredScripts count makes sense
	VALIDATE(ctx->complexScripts[ctx->level].remainingScripts >= requiredScripts, ERR_INVALID_DATA);

	nativeScriptHashBuilder_startComplexScript_n_of_k(&ctx->hashBuilder, requiredScripts, ctx->complexScripts[ctx->level].remainingScripts);

	// max possible length 67: "Reuqired signatures: x. Contains x nested scripts"
	// where x is 2^32-1
	char text[68];
	snprintf(text, SIZEOF(text), "Required signatures: %u. Contains %u nested scripts", requiredScripts, ctx->complexScripts[ctx->level].remainingScripts);

	ui_displayPaginatedText(
	        "Script - N of K",
	        text,
	        deriveScriptHash_display_ui_callback
	);
}

static void deriveNativeScriptHash_handleComplexScriptStart(read_view_t* view)
{
	VALIDATE(areMoreScriptsExpected(), ERR_INVALID_STATE);

	// check if we can increase the level without breaking the MAX_SCRIPT_DEPTH constraint
	VALIDATE(ctx->level + 1 < MAX_SCRIPT_DEPTH, ERR_INVALID_DATA);
	ctx->level++;

	// the nativeScriptType is validated below, in the switch statement
	uint8_t nativeScriptType = parse_u1be(view);
	TRACE("native complex script type = %u", nativeScriptType);

	ctx->complexScripts[ctx->level].remainingScripts = parse_u4be(view);

	switch(nativeScriptType) {
#	define  CASE(TYPE, HANDLER) case TYPE: HANDLER(view); break;
		CASE(NATIVE_SCRIPT_ALL, deriveNativeScriptHash_handleAll);
		CASE(NATIVE_SCRIPT_ANY, deriveNativeScriptHash_handleAny);
		CASE(NATIVE_SCRIPT_N_OF_K, deriveNativeScriptHash_handleNofK);
#	undef   CASE
	default:
		THROW(ERR_INVALID_DATA);
	}

	if (isComplexScriptFinished()) {
		complexScriptFinished();
	}
}

// Simple native scripts

static void deriveNativeScriptHash_handleDeviceOwnedPubkey(read_view_t* view)
{
	bip44_path_t path;
	view_skipBytes(view, bip44_parseFromWire(&path, VIEW_REMAINING_TO_TUPLE_BUF_SIZE(view)));

	VALIDATE(view_remainingSize(view) == 0, ERR_INVALID_DATA);
	TRACE("pubkey given by path:");
	BIP44_PRINTF(&path);
	PRINTF("\n");

	uint8_t pubkeyHash[ADDRESS_KEY_HASH_LENGTH];
	bip44_pathToKeyHash(&path, pubkeyHash, ADDRESS_KEY_HASH_LENGTH);
	nativeScriptHashBuilder_addScript_pubkey(&ctx->hashBuilder, pubkeyHash, SIZEOF(pubkeyHash));

	ui_displayPathScreen(
	        "Script - key path",
	        &path,
	        deriveScriptHash_display_ui_callback
	);
}

static void deriveNativeScriptHash_handleThirdPartyPubkey(read_view_t* view)
{
	uint8_t pubkeyHash[ADDRESS_KEY_HASH_LENGTH];
	VALIDATE(view_remainingSize(view) == ADDRESS_KEY_HASH_LENGTH, ERR_INVALID_DATA);
	view_memmove(pubkeyHash, view, ADDRESS_KEY_HASH_LENGTH);

	TRACE_BUFFER(pubkeyHash, ADDRESS_KEY_HASH_LENGTH);

	nativeScriptHashBuilder_addScript_pubkey(&ctx->hashBuilder, pubkeyHash, SIZEOF(pubkeyHash));

	ui_displayBech32Screen(
	        "Script - key",
	        "addr_vkh",
	        pubkeyHash,
	        ADDRESS_KEY_HASH_LENGTH,
	        deriveScriptHash_display_ui_callback
	);
}

static void deriveNativeScriptHash_handlePubkey(read_view_t* view)
{
	uint8_t pubkeyType = parse_u1be(view);
	TRACE("pubkey type = %u", pubkeyType);

	switch(pubkeyType) {
	case KEY_REFERENCE_PATH:
		deriveNativeScriptHash_handleDeviceOwnedPubkey(view);
		break;
	case KEY_REFERENCE_HASH:
		deriveNativeScriptHash_handleThirdPartyPubkey(view);
		break;
	// any other value for the pubkey type is invalid
	default:
		THROW(ERR_INVALID_DATA);
	}
}

static void deriveNativeScriptHash_handleInvalidBefore(read_view_t* view)
{
	uint64_t timelock = parse_u8be(view);

	VALIDATE(view_remainingSize(view) == 0, ERR_INVALID_DATA);
	TRACE("invalid_before timelock");
	TRACE_UINT64(timelock);

	nativeScriptHashBuilder_addScript_invalidBefore(&ctx->hashBuilder, timelock);

	ui_displayUint64Screen(
	        "Script - invalid before",
	        timelock,
	        deriveScriptHash_display_ui_callback
	);
}

static void deriveNativeScriptHash_handleInvalidHereafter(read_view_t* view)
{
	uint64_t timelock = parse_u8be(view);

	VALIDATE(view_remainingSize(view) == 0, ERR_INVALID_DATA);
	TRACE("invalid_hereafter timelock");
	TRACE_UINT64(timelock);

	nativeScriptHashBuilder_addScript_invalidHereafter(&ctx->hashBuilder, timelock);

	ui_displayUint64Screen(
	        "Script - invalid hereafter",
	        timelock,
	        deriveScriptHash_display_ui_callback
	);
}

static void deriveNativeScriptHash_handleSimpleScript(read_view_t* view)
{
	VALIDATE(areMoreScriptsExpected(), ERR_INVALID_STATE);

	uint8_t nativeScriptType = parse_u1be(view);
	TRACE("native simple script type = %u", nativeScriptType);

	// parse data
	switch(nativeScriptType) {
#	define  CASE(TYPE, HANDLER) case TYPE: HANDLER(view); break;
		CASE(NATIVE_SCRIPT_PUBKEY, deriveNativeScriptHash_handlePubkey);
		CASE(NATIVE_SCRIPT_INVALID_BEFORE, deriveNativeScriptHash_handleInvalidBefore);
		CASE(NATIVE_SCRIPT_INVALID_HEREAFTER, deriveNativeScriptHash_handleInvalidHereafter);
#	undef   CASE
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

static void deriveNativeScriptHash_displayNativeScriptHash_callback()
{
	io_send_buf(SUCCESS, ctx->scriptHashBuffer, SCRIPT_HASH_LENGTH);
	ui_idle();
}

static void deriveNativeScriptHash_displayNativeScriptHash_bech32()
{
	ui_displayBech32Screen(
	        "Script hash",
	        "script",
	        ctx->scriptHashBuffer,
	        SCRIPT_HASH_LENGTH,
	        deriveNativeScriptHash_displayNativeScriptHash_callback
	);
}

static void deriveNativeScriptHash_displayNativeScriptHash_policyId()
{
	ui_displayHexBufferScreen(
	        "Policy ID",
	        ctx->scriptHashBuffer,
	        SCRIPT_HASH_LENGTH,
	        deriveNativeScriptHash_displayNativeScriptHash_callback
	);
}

static void deriveNativeScriptHash_handleWholeNativeScriptFinish(read_view_t* view)
{
	// we finish only if there are no more scripts to be processed
	VALIDATE(ctx->level == 0 && ctx->complexScripts[0].remainingScripts == 0, ERR_INVALID_STATE);

	uint8_t displayFormat = parse_u1be(view);
	VALIDATE(view_remainingSize(view) == 0, ERR_INVALID_DATA);
	TRACE("whole native script received, display format = %u", displayFormat);

	switch (displayFormat) {
#	define  CASE(FORMAT, DISPLAY_FN) case FORMAT: nativeScriptHashBuilder_finalize(&ctx->hashBuilder, ctx->scriptHashBuffer, SCRIPT_HASH_LENGTH); DISPLAY_FN(); break;
		CASE(DISPLAY_NATIVE_SCRIPT_HASH_BECH32, deriveNativeScriptHash_displayNativeScriptHash_bech32);
		CASE(DISPLAY_NATIVE_SCRIPT_HASH_POLICY_ID, deriveNativeScriptHash_displayNativeScriptHash_policyId);
#	undef	CASE
	default:
		THROW(ERR_INVALID_DATA);
	}
}

typedef void subhandler_fn_t(read_view_t* view);

static subhandler_fn_t* lookup_subhandler(uint8_t p1)
{
	switch (p1) {
#	define  CASE(P1, HANDLER) case P1: return HANDLER;
#	define  DEFAULT(HANDLER)  default: return HANDLER;
		CASE(0x01, deriveNativeScriptHash_handleComplexScriptStart);
		CASE(0x02, deriveNativeScriptHash_handleSimpleScript);
		CASE(0x03, deriveNativeScriptHash_handleWholeNativeScriptFinish)
		DEFAULT(NULL);
#	undef   CASE
#	undef   DEFAULT
	}
}

void deriveNativeScriptHash_handleAPDU(
        uint8_t p1,
        uint8_t p2,
        uint8_t *wireDataBuffer,
        size_t wireDataSize,
        bool isNewCall
)
{
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
}

#undef TRACE_WITH_CTX
