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
typedef const char* charPtr;
const charPtr ui_native_script_header[7] = {"Script - key path", "Script - key", "Script - ALL", "Script - ANY", "Script - N of K", "Script - invalid before", "Script - invalid hereafter"};

#define ASSERT_UI_SCRIPT_TYPE_SANITY() ASSERT(ctx->ui_scriptType >= UI_SCRIPT_PUBKEY_PATH && ctx->ui_scriptType <= UI_SCRIPT_INVALID_HEREAFTER)
#define HEADER ((const char*)PIC(ui_native_script_header[ctx->ui_scriptType]))

static uint8_t _getScriptLevelForPosition()
{
	// For complex scripts we reduce the current level by 1
	// Because they already have the level increased by 1
	uint8_t levelOffset = ctx->ui_scriptType == UI_SCRIPT_ALL
	                      || ctx->ui_scriptType == UI_SCRIPT_ANY
	                      || ctx->ui_scriptType == UI_SCRIPT_N_OF_K
	                      ? 1 : 0;
	ASSERT(levelOffset == 0 || ctx->level > 0);
	return ctx->level - levelOffset;
}

static void deriveScriptHash_display_ui_position(uint8_t level, ui_callback_fn_t* callback)
{
	ASSERT_UI_SCRIPT_TYPE_SANITY();
	ASSERT(level > 0);
	TRACE();

	// 10 - length of the leading prefix: "Position: "
	// 11 - max length for the position information for one level: "x."
	//      where x is 2^32-1
	// 2  - the ending null byte + 1B for checking if all text has been printed
	char positionDescription[10 + 11 * (MAX_SCRIPT_DEPTH - 1) + 2] = {0};
	explicit_bzero(positionDescription, SIZEOF(positionDescription));
	char* ptr = BEGIN(positionDescription);
	char* end = END(positionDescription);

	snprintf(ptr, (end - ptr), "Position: ");
	// snprintf returns 0, https://github.com/LedgerHQ/nanos-secure-sdk/issues/28
	// so we need to check the number of written characters by `strlen`
	ptr += strlen(ptr);

	for (size_t i = 1; i <= level; i++) {
		ASSERT(i < MAX_SCRIPT_DEPTH);
		uint32_t position = ctx->complexScripts[i].totalScripts - ctx->complexScripts[i].remainingScripts + 1;
		STATIC_ASSERT(sizeof(position) <= sizeof(unsigned), "oversized type for %u");
		STATIC_ASSERT(!IS_SIGNED(position), "signed type for %u");
		snprintf(ptr, (end - ptr), "%u.", position);
		ASSERT(strlen(positionDescription) + 1 < SIZEOF(positionDescription));
		ptr += strlen(ptr);
	}

	// remove any trailing '.'
	ASSERT(ptr > BEGIN(positionDescription));
	*(ptr - 1) = '\0';

	ASSERT(strlen(positionDescription) + 1 < SIZEOF(positionDescription));

	VALIDATE(uiPaginatedText_canFitStringIntoFullText(positionDescription), ERR_INVALID_DATA);

	ui_displayPaginatedText(
	        HEADER,
	        positionDescription,
	        callback
	);
}

enum {
	DISPLAY_UI_STEP_POSITION = 200,
	DISPLAY_UI_STEP_SCRIPT_CONTENT,
	DISPLAY_UI_STEP_RESPOND,
	DISPLAY_UI_STEP_INVALID
};

static void deriveScriptHash_display_ui_runStep()
{
	TRACE("ui_step = %d", ctx->ui_step);
	ASSERT_UI_SCRIPT_TYPE_SANITY();

	ui_callback_fn_t* this_fn = deriveScriptHash_display_ui_runStep;
	UI_STEP_BEGIN(ctx->ui_step, this_fn);

	UI_STEP(DISPLAY_UI_STEP_POSITION) {
		uint8_t level = _getScriptLevelForPosition();
		if (level == 0) {
			TRACE("Skip showing position");
			UI_STEP_JUMP(DISPLAY_UI_STEP_SCRIPT_CONTENT);
		}
		deriveScriptHash_display_ui_position(level, this_fn);
	}

	UI_STEP(DISPLAY_UI_STEP_SCRIPT_CONTENT) {
		TRACE("ui_scriptType = %d", ctx->ui_scriptType);
		switch (ctx->ui_scriptType) {
		case UI_SCRIPT_PUBKEY_PATH: {
			ui_displayPathScreen(
			        HEADER,
			        &ctx->scriptContent.pubkeyPath,
			        this_fn
			);
			break;
		}
		case UI_SCRIPT_PUBKEY_HASH: {
			ui_displayBech32Screen(
			        HEADER,
			        "addr_shared_vkh",
			        ctx->scriptContent.pubkeyHash,
			        ADDRESS_KEY_HASH_LENGTH,
			        this_fn
			);
			break;
		}
		case UI_SCRIPT_ALL:
		case UI_SCRIPT_ANY: {
			// max possible length 35: "Contains n nested scripts."
			// where n is 2^32-1
			char text[37] = {0};
			explicit_bzero(text, SIZEOF(text));
			STATIC_ASSERT(sizeof(ctx->complexScripts[ctx->level].remainingScripts) <= sizeof(unsigned), "oversized type for %u");
			STATIC_ASSERT(!IS_SIGNED(ctx->complexScripts[ctx->level].remainingScripts), "signed type for %u");
			snprintf(text, SIZEOF(text), "Contains %u nested scripts.", ctx->complexScripts[ctx->level].remainingScripts);
			// make sure all the information is displayed to the user
			ASSERT(strlen(text) + 1 < SIZEOF(text));

			ui_displayPaginatedText(
			        HEADER,
			        text,
			        this_fn
			);
			break;
		}
		case UI_SCRIPT_N_OF_K: {
			// max possible length 85: "Requires n out of k signatures. Contains k nested scripts."
			// where n and k is 2^32-1
			char text[87] = {0};
			explicit_bzero(text, SIZEOF(text));
			STATIC_ASSERT(sizeof(ctx->scriptContent.requiredScripts) <= sizeof(unsigned), "oversized type for %u");
			STATIC_ASSERT(!IS_SIGNED(ctx->scriptContent.requiredScripts), "signed type for %u");
			STATIC_ASSERT(sizeof(ctx->complexScripts[ctx->level].remainingScripts) <= sizeof(unsigned), "oversized type for %u");
			STATIC_ASSERT(!IS_SIGNED(ctx->complexScripts[ctx->level].remainingScripts), "signed type for %u");
			snprintf(text, SIZEOF(text), "Requires %u out of %u signatures. Contains %u nested scripts", ctx->scriptContent.requiredScripts, ctx->complexScripts[ctx->level].remainingScripts, ctx->complexScripts[ctx->level].remainingScripts);
			// make sure all the information is displayed to the user
			ASSERT(strlen(text) + 1 < SIZEOF(text));

			ui_displayPaginatedText(
			        HEADER,
			        text,
			        this_fn
			);
			break;
		}
		case UI_SCRIPT_INVALID_BEFORE:
		case UI_SCRIPT_INVALID_HEREAFTER: {
			ui_displayUint64Screen(
			        HEADER,
			        ctx->scriptContent.timelock,
			        this_fn
			);
			break;
		}
		default:
			THROW(ERR_INVALID_STATE);
		}
	}

	UI_STEP(DISPLAY_UI_STEP_RESPOND) {
		io_send_buf(SUCCESS, NULL, 0);
		ui_displayBusy(); // displays dots, called only after I/O to avoid freezing
	}

	UI_STEP_END(DISPLAY_UI_STEP_INVALID);
}
#undef HEADER
#undef ASSERT_UI_SCRIPT_TYPE_SANITY

#define UI_DISPLAY_SCRIPT(UI_TYPE) {\
		ctx->ui_scriptType = UI_TYPE;\
		ctx->ui_step = DISPLAY_UI_STEP_POSITION;\
		deriveScriptHash_display_ui_runStep();\
	}

// Start complex native script

static void deriveNativeScriptHash_handleAll(read_view_t* view)
{
	TRACE_WITH_CTX("");
	VALIDATE(view_remainingSize(view) == 0, ERR_INVALID_DATA);

	nativeScriptHashBuilder_startComplexScript_all(&ctx->hashBuilder, ctx->complexScripts[ctx->level].remainingScripts);

	UI_DISPLAY_SCRIPT(UI_SCRIPT_ALL);
}

static void deriveNativeScriptHash_handleAny(read_view_t* view)
{
	TRACE_WITH_CTX("");
	VALIDATE(view_remainingSize(view) == 0, ERR_INVALID_DATA);

	nativeScriptHashBuilder_startComplexScript_any(&ctx->hashBuilder, ctx->complexScripts[ctx->level].remainingScripts);

	UI_DISPLAY_SCRIPT(UI_SCRIPT_ANY);
}

static void deriveNativeScriptHash_handleNofK(read_view_t* view)
{
	// parse data
	ctx->scriptContent.requiredScripts = parse_u4be(view);
	TRACE_WITH_CTX("required scripts = %u, ", ctx->scriptContent.requiredScripts);

	VALIDATE(view_remainingSize(view) == 0, ERR_INVALID_DATA);

	// validate that the received requiredScripts count makes sense
	VALIDATE(ctx->complexScripts[ctx->level].remainingScripts >= ctx->scriptContent.requiredScripts, ERR_INVALID_DATA);

	nativeScriptHashBuilder_startComplexScript_n_of_k(&ctx->hashBuilder, ctx->scriptContent.requiredScripts, ctx->complexScripts[ctx->level].remainingScripts);

	UI_DISPLAY_SCRIPT(UI_SCRIPT_N_OF_K);
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
	ctx->complexScripts[ctx->level].totalScripts = ctx->complexScripts[ctx->level].remainingScripts;

	// these handlers might read additional data from the view
	switch (nativeScriptType) {
#define  CASE(TYPE, HANDLER) case TYPE: HANDLER(view); break;
		CASE(NATIVE_SCRIPT_ALL, deriveNativeScriptHash_handleAll);
		CASE(NATIVE_SCRIPT_ANY, deriveNativeScriptHash_handleAny);
		CASE(NATIVE_SCRIPT_N_OF_K, deriveNativeScriptHash_handleNofK);
#undef   CASE
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
	view_skipBytes(view, bip44_parseFromWire(&ctx->scriptContent.pubkeyPath, VIEW_REMAINING_TO_TUPLE_BUF_SIZE(view)));
	TRACE("pubkey given by path:");
	BIP44_PRINTF(&ctx->scriptContent.pubkeyPath);
	PRINTF("\n");

	VALIDATE(view_remainingSize(view) == 0, ERR_INVALID_DATA);

	uint8_t pubkeyHash[ADDRESS_KEY_HASH_LENGTH] = {0};
	bip44_pathToKeyHash(&ctx->scriptContent.pubkeyPath, pubkeyHash, ADDRESS_KEY_HASH_LENGTH);
	nativeScriptHashBuilder_addScript_pubkey(&ctx->hashBuilder, pubkeyHash, SIZEOF(pubkeyHash));

	UI_DISPLAY_SCRIPT(UI_SCRIPT_PUBKEY_PATH);
}

static void deriveNativeScriptHash_handleThirdPartyPubkey(read_view_t* view)
{
	STATIC_ASSERT(SIZEOF(ctx->scriptContent.pubkeyHash) == ADDRESS_KEY_HASH_LENGTH, "incorrect key hash size in script");
	view_parseBuffer(ctx->scriptContent.pubkeyHash, view, ADDRESS_KEY_HASH_LENGTH);
	TRACE_BUFFER(ctx->scriptContent.pubkeyHash, ADDRESS_KEY_HASH_LENGTH);

	VALIDATE(view_remainingSize(view) == 0, ERR_INVALID_DATA);

	nativeScriptHashBuilder_addScript_pubkey(&ctx->hashBuilder, ctx->scriptContent.pubkeyHash, SIZEOF(ctx->scriptContent.pubkeyHash));

	UI_DISPLAY_SCRIPT(UI_SCRIPT_PUBKEY_HASH);
}

static void deriveNativeScriptHash_handlePubkey(read_view_t* view)
{
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

static void deriveNativeScriptHash_handleInvalidBefore(read_view_t* view)
{
	ctx->scriptContent.timelock = parse_u8be(view);
	TRACE("invalid_before timelock");
	TRACE_UINT64(ctx->scriptContent.timelock);

	VALIDATE(view_remainingSize(view) == 0, ERR_INVALID_DATA);

	nativeScriptHashBuilder_addScript_invalidBefore(&ctx->hashBuilder, ctx->scriptContent.timelock);

	UI_DISPLAY_SCRIPT(UI_SCRIPT_INVALID_BEFORE);
}

static void deriveNativeScriptHash_handleInvalidHereafter(read_view_t* view)
{
	ctx->scriptContent.timelock = parse_u8be(view);
	TRACE("invalid_hereafter timelock");
	TRACE_UINT64(ctx->scriptContent.timelock);

	VALIDATE(view_remainingSize(view) == 0, ERR_INVALID_DATA);

	nativeScriptHashBuilder_addScript_invalidHereafter(&ctx->hashBuilder, ctx->scriptContent.timelock);

	UI_DISPLAY_SCRIPT(UI_SCRIPT_INVALID_HEREAFTER);
}

#undef UI_DISPLAY_SCRIPT

static void deriveNativeScriptHash_handleSimpleScript(read_view_t* view)
{
	VALIDATE(areMoreScriptsExpected(), ERR_INVALID_STATE);

	uint8_t nativeScriptType = parse_u1be(view);
	TRACE("native simple script type = %u", nativeScriptType);

	// parse data
	switch (nativeScriptType) {
#define  CASE(TYPE, HANDLER) case TYPE: HANDLER(view); break;
		CASE(NATIVE_SCRIPT_PUBKEY, deriveNativeScriptHash_handlePubkey);
		CASE(NATIVE_SCRIPT_INVALID_BEFORE, deriveNativeScriptHash_handleInvalidBefore);
		CASE(NATIVE_SCRIPT_INVALID_HEREAFTER, deriveNativeScriptHash_handleInvalidHereafter);
#undef   CASE
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
	TRACE("whole native script received, display format = %u", displayFormat);

	VALIDATE(view_remainingSize(view) == 0, ERR_INVALID_DATA);

	switch (displayFormat) {
#define  CASE(FORMAT, DISPLAY_FN) case FORMAT: nativeScriptHashBuilder_finalize(&ctx->hashBuilder, ctx->scriptHashBuffer, SCRIPT_HASH_LENGTH); DISPLAY_FN(); break;
		CASE(DISPLAY_NATIVE_SCRIPT_HASH_BECH32, deriveNativeScriptHash_displayNativeScriptHash_bech32);
		CASE(DISPLAY_NATIVE_SCRIPT_HASH_POLICY_ID, deriveNativeScriptHash_displayNativeScriptHash_policyId);
#undef	CASE
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

static subhandler_fn_t* lookup_subhandler(uint8_t p1)
{
	switch (p1) {
#define  CASE(P1, HANDLER) case P1: return HANDLER;
#define  DEFAULT(HANDLER)  default: return HANDLER;
		CASE(STAGE_COMPLEX_SCRIPT_START, deriveNativeScriptHash_handleComplexScriptStart);
		CASE(STAGE_ADD_SIMPLE_SCRIPT, deriveNativeScriptHash_handleSimpleScript);
		CASE(STAGE_WHOLE_NATIVE_SCRIPT_FINISH, deriveNativeScriptHash_handleWholeNativeScriptFinish)
		DEFAULT(NULL);
#undef   CASE
#undef   DEFAULT
	}
}

void deriveNativeScriptHash_handleAPDU(
        uint8_t p1,
        uint8_t p2,
        const uint8_t* wireDataBuffer,
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
