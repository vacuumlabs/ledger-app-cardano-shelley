#include "deriveNativeScriptHash.h"
#include "state.h"
#include "uiScreens.h"

enum nativeScriptType {
	NATIVE_SCRIPT_PUBKEY = 0,
	NATIVE_SCRIPT_ALL = 1,
	NATIVE_SCRIPT_ANY = 2,
	NATIVE_SCRIPT_N_OF_K = 3,
	NATIVE_SCRIPT_INVALID_BEFORE = 4,
	NATIVE_SCRIPT_INVALID_HEREAFTER = 5,
};

// distinguish between the types of PUBKEY
// DEVICE_OWNED is specified by a path
// THIRD_PARTY is specified by a pubkey hash
enum {
	PUBKEY_DEVICE_OWNED = 0,
	PUBKEY_THIRD_PARTY = 1,
};

static ins_derive_native_script_hash_context_t* ctx = &(instructionState.deriveNativeScriptHashContext);

// Helper functions

bool expectsRequest()
{
	// if the number of remaining scripts is not bigger than 0, then this request
	// is invalid in the current context, as Ledger was not expecting another
	// script to be parsed
	return ctx->remainingScripts[ctx->level] > 0;
}

bool shouldFinish()
{
	// we finish if there are no more scripts to be processed
	return ctx->level == 0 && ctx->remainingScripts[0] == 0;
}

static inline void scriptFinished()
{
	--ctx->remainingScripts[ctx->level];
	TRACE("native script finished, level = %u, remainingScripts = %u", ctx->level, ctx->remainingScripts[ctx->level]);
}

static inline void complexScriptFinished()
{
	--ctx->level;
	scriptFinished();
}

// UI

static void deriveScriptHash_display_ui_callback()
{
	if (shouldFinish()) {
		TRACE("whole native script received");
		ui_idle();
		// TODO: hashing, this is just a mock response
		uint8_t buffer[28] = {0};
		io_send_buf(SUCCESS, buffer, 28);
	} else {
		io_send_buf(SUCCESS, NULL, 0);
	}
}

// Start complex native script

void deriveNativeScriptHash_handleAll(read_view_t* view)
{
	// Parse data
	ctx->remainingScripts[ctx->level] = parse_u4be(view);
	ctx->type[ctx->level] = NATIVE_COMPLEX_SCRIPT_ALL;

	VALIDATE(view_remainingSize(view) == 0, ERR_INVALID_DATA);
	TRACE("level = %u, remaining scripts = %u", ctx->level, ctx->remainingScripts[ctx->level]);

	// max possible length 26: "Confirm x scripts"
	// where x is 2^32-1
	char text[27];
	explicit_bzero(text, SIZEOF(text));
	snprintf(text, SIZEOF(text), "Confirm %d scripts", ctx->remainingScripts[ctx->level]);
	ASSERT(strlen(text) + 1 < SIZEOF(text));

	ui_displayPaginatedText(
		// TODO: proper UI screen headers with numbered sections
		"Script - ALL",
		text,
		&deriveScriptHash_display_ui_callback
	);
}

void deriveNativeScriptHash_handleAny(read_view_t* view)
{
	// Parse data
	ctx->remainingScripts[ctx->level] = parse_u4be(view);
	ctx->type[ctx->level] = NATIVE_COMPLEX_SCRIPT_ANY;

	VALIDATE(view_remainingSize(view) == 0, ERR_INVALID_DATA);
	TRACE("level = %u, remaining scripts = %u", ctx->level, ctx->remainingScripts[ctx->level]);

	// max possible length 26: "Confirm x scripts"
	// where x is 2^32-1
	char text[27];
	explicit_bzero(text, SIZEOF(text));
	snprintf(text, SIZEOF(text), "Confirm %d scripts", ctx->remainingScripts[ctx->level]);
	ASSERT(strlen(text) + 1 < SIZEOF(text));

	ui_displayPaginatedText(
		"Script - ANY",
		text,
		&deriveScriptHash_display_ui_callback
	);
}

void deriveNativeScriptHash_handleNofK(read_view_t* view)
{
	// parse data
	ctx->nativeScript.nOfK.n = parse_u4be(view);
	ctx->remainingScripts[ctx->level] = parse_u4be(view);
	ctx->type[ctx->level] = NATIVE_COMPLEX_SCRIPT_N_OF_K;

	VALIDATE(view_remainingSize(view) == 0, ERR_INVALID_DATA);
	TRACE("level = %u, required scripts = %u, remaining scripts = %u", ctx->level, ctx->nativeScript.nOfK.n, ctx->remainingScripts[ctx->level]);
	
	// validate that the received requiredScripts count makes sense
	VALIDATE(ctx->remainingScripts[ctx->level] >= ctx->nativeScript.nOfK.n, ERR_INVALID_DATA);

	// max possible length 32: "Confirm x of x"
	// where x is 2^32-1
	char text[33];
	explicit_bzero(text, SIZEOF(text));
	snprintf(text, SIZEOF(text), "Confirm %d of %d", ctx->nativeScript.nOfK.n, ctx->remainingScripts[ctx->level]);
	ASSERT(strlen(text) + 1 < SIZEOF(text));

	ui_displayPaginatedText(
		"Script - N of K",
		text,
		&deriveScriptHash_display_ui_callback
	);
}

void deriveNativeScriptHash_handleComplexScriptStart(read_view_t* view)
{
	TRACE_BUFFER(view->begin, (size_t) (view->end - view->begin));

	VALIDATE(expectsRequest(), ERR_INVALID_STATE);

	// check if we can increase the level without breaking the MAX_SCRIPT_DEPTH constraint
	VALIDATE(ctx->level + 1 < MAX_SCRIPT_DEPTH, ERR_DATA_TOO_LARGE);
	ctx->level++;

	uint8_t nativeScriptType = parse_u1be(view);
	TRACE("native complex script type = %u", nativeScriptType);

	switch(nativeScriptType) {
#	define  CASE(TYPE, HANDLER) case TYPE: HANDLER(view); break;
		CASE(NATIVE_SCRIPT_ALL, deriveNativeScriptHash_handleAll);
		CASE(NATIVE_SCRIPT_ANY, deriveNativeScriptHash_handleAny);
		CASE(NATIVE_SCRIPT_N_OF_K, deriveNativeScriptHash_handleNofK);
		default: THROW(ERR_INVALID_DATA);
#	undef   CASE
	}
}

// Simple native scripts

void deriveNativeScriptHash_handleDeviceOwnedPubkey(read_view_t* view)
{
	bip44_path_t *path = &ctx->nativeScript.pubkeyDeviceOwned.path;
	view_skipBytes(view, bip44_parseFromWire(path, VIEW_REMAINING_TO_TUPLE_BUF_SIZE(view)));

	VALIDATE(view_remainingSize(view) == 0, ERR_INVALID_DATA);
	TRACE("Pubkey given by path:");
	BIP44_PRINTF(path);
	PRINTF("\n");

	ui_displayPathScreen(
		"Script - key path",
		&ctx->nativeScript.pubkeyDeviceOwned.path,
		&deriveScriptHash_display_ui_callback
	);
}

void deriveNativeScriptHash_handleThirdPartyPubkey(read_view_t* view)
{
	uint8_t *hash = ctx->nativeScript.pubkeyThirdParty.hash;
	VALIDATE(view_remainingSize(view) == ADDRESS_KEY_HASH_LENGTH, ERR_INVALID_DATA);
	view_memmove(hash, view, ADDRESS_KEY_HASH_LENGTH);

#	ifdef DEVEL
	TRACE("Pubkey given by hash:");
	for (int i = 0; i < ADDRESS_KEY_HASH_LENGTH; i++) {
		PRINTF("%x", hash[i]);
	}
	PRINTF("\n");
#	endif

	ui_displayHexBufferScreen(
		"Script - key",
		ctx->nativeScript.pubkeyThirdParty.hash,
		ADDRESS_KEY_HASH_LENGTH,
		&deriveScriptHash_display_ui_callback
	);
}

void deriveNativeScriptHash_handlePubkey(read_view_t* view)
{
	uint8_t pubkeyType = parse_u1be(view);
	TRACE("pubkey type = %u", pubkeyType);

	switch(pubkeyType) {
#	define  CASE(TYPE, HANDLER) case TYPE: HANDLER(view); break;
		CASE(PUBKEY_DEVICE_OWNED, deriveNativeScriptHash_handleDeviceOwnedPubkey);
		CASE(PUBKEY_THIRD_PARTY, deriveNativeScriptHash_handleThirdPartyPubkey);
		// any other value for the pubkey type is invalid
		default: THROW(ERR_INVALID_DATA);
#	undef   CASE
	}
}

#define SPLIT_UINT64(n) (uint32_t) (n >> 32), (uint32_t) n

void deriveNativeScriptHash_handleInvalidBefore(read_view_t* view)
{
	ctx->nativeScript.invalidBefore.timelock = parse_u8be(view);

	VALIDATE(view_remainingSize(view) == 0, ERR_INVALID_DATA);
	// PRINTF doesn't handle uint64_t so we split it into two uint32_t
	TRACE("invalid_before timelock = 0x%x%x", SPLIT_UINT64(ctx->nativeScript.invalidBefore.timelock));

	ui_displayUint64Screen(
		"Script - invalid before",
		ctx->nativeScript.invalidBefore.timelock,
		&deriveScriptHash_display_ui_callback
	);
}

void deriveNativeScriptHash_handleInvalidHereafter(read_view_t* view)
{
	ctx->nativeScript.invalidHereafter.timelock = parse_u8be(view);

	VALIDATE(view_remainingSize(view) == 0, ERR_INVALID_DATA);
	TRACE("invalid_hereafter timelock = 0x%x%x", SPLIT_UINT64(ctx->nativeScript.invalidHereafter.timelock));

	ui_displayUint64Screen(
		"Script - invalid hereafter",
		ctx->nativeScript.invalidHereafter.timelock,
		&deriveScriptHash_display_ui_callback
	);
}

#undef SPLIT_UINT64

void deriveNativeScriptHash_handleSimpleScript(read_view_t* view)
{
	TRACE_BUFFER(view->begin, (size_t) (view->end - view->begin));

	VALIDATE(expectsRequest(), ERR_INVALID_STATE);

	uint8_t nativeScriptType = parse_u1be(view);
	TRACE("native simple script type = %u", nativeScriptType);

	// parse data
	switch(nativeScriptType) {
#	define  CASE(TYPE, HANDLER) case TYPE: HANDLER(view); break;
		CASE(NATIVE_SCRIPT_PUBKEY, deriveNativeScriptHash_handlePubkey);
		CASE(NATIVE_SCRIPT_INVALID_BEFORE, deriveNativeScriptHash_handleInvalidBefore);
		CASE(NATIVE_SCRIPT_INVALID_HEREAFTER, deriveNativeScriptHash_handleInvalidHereafter);
		default: THROW(ERR_INVALID_DATA);
#	undef   CASE
	}
	scriptFinished();
}

// Complex script finish

void deriveNativeScriptHash_handleComplexScriptFinish(read_view_t* view)
{
	// expect no data
	VALIDATE(read_view_remaining_size(view) == 0, ERR_INVALID_DATA);

	// if the number of remaining scripts for the current complex script is not 0
	// then this request is invalid in the current context
	VALIDATE(ctx->remainingScripts[ctx->level] == 0, ERR_INVALID_STATE);

	switch(ctx->type[ctx->level]) {
#	define  CASE(TYPE, HEADER) case TYPE: ui_displayPaginatedText(HEADER, "Finished", &deriveScriptHash_display_ui_callback); break;
	CASE(NATIVE_COMPLEX_SCRIPT_ALL, "Script - ALL");
	CASE(NATIVE_COMPLEX_SCRIPT_ANY, "Script - ANY");
	CASE(NATIVE_COMPLEX_SCRIPT_N_OF_K, "Script - N of K");
	default: THROW(ERR_INVALID_STATE);
#	undef CASE
	}

	complexScriptFinished();
}

typedef void subhandler_fn_t(read_view_t* view);

static subhandler_fn_t* lookup_subhandler(uint8_t p1)
{
	switch (p1) {
#	define  CASE(P1, HANDLER) case P1: return HANDLER;
#	define  DEFAULT(HANDLER)  default: return HANDLER;
		CASE(0x01, deriveNativeScriptHash_handleComplexScriptStart);
		CASE(0x02, deriveNativeScriptHash_handleSimpleScript);
		CASE(0x03, deriveNativeScriptHash_handleComplexScriptFinish);
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

	// initialize state
	if (isNewCall) {
		explicit_bzero(ctx, SIZEOF(*ctx));
		ctx->level = 0;
		ctx->remainingScripts[ctx->level] = 1;
	}

	// reset the native script object
	explicit_bzero(&ctx->nativeScript, SIZEOF(ctx->nativeScript));

	read_view_t view = make_read_view(wireDataBuffer, wireDataBuffer + wireDataSize);

	subhandler_fn_t* subhandler = lookup_subhandler(p1);
	VALIDATE(subhandler != NULL, ERR_INVALID_REQUEST_PARAMETERS);
	subhandler(&view);
}
