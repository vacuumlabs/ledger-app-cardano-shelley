#include "deriveNativeScriptHash.h"
#include "state.h"

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

bool shouldFinish()
{
	// we finish if there are no more scripts to be processed
	return ctx->level == 0 && ctx->remainingScripts[0] == 0;
}

static inline void scriptFinished()
{
	--ctx->remainingScripts[ctx->level];
}

static inline void complexScriptFinished()
{
	--ctx->level;
	scriptFinished();
}

// Start complex native script

void deriveNativeScriptHash_handleAllOrAny(read_view_t* view)
{
	// Parse data
	ctx->remainingScripts[ctx->level] = parse_u4be(view);

	VALIDATE(view_remainingSize(view) == 0, ERR_INVALID_DATA);
	TRACE("level = %u, remaining scripts = %u", ctx->level, ctx->remainingScripts[ctx->level]);
}

void deriveNativeScriptHash_handleNofK(read_view_t* view)
{
	// parse data
	uint32_t requiredScripts = parse_u4be(view);
	ctx->remainingScripts[ctx->level] = parse_u4be(view);

	VALIDATE(view_remainingSize(view) == 0, ERR_INVALID_DATA);
	TRACE("level = %u, required scripts = %u, remaining scripts = %u", ctx->level, requiredScripts, ctx->remainingScripts[ctx->level]);
	
	// validate that the received requiredScripts count makes sense
	VALIDATE(ctx->remainingScripts[ctx->level] >= requiredScripts, ERR_INVALID_DATA);
}

void deriveNativeScriptHash_handleComplexScriptStart(read_view_t* view)
{
	TRACE_BUFFER(view->begin, (size_t) (view->end - view->begin));

	// if the number of remaining scripts is not bigger than 0, then this request
	// is invalid in the current context, as Ledger was not expecting another
	// script to be parsed
	VALIDATE(ctx->remainingScripts[ctx->level] > 0, ERR_INVALID_STATE);

	// check if we can increase the level without breaking the MAX_SCRIPT_DEPTH constraint
	VALIDATE(ctx->level + 1 < MAX_SCRIPT_DEPTH, ERR_DATA_TOO_LARGE);
	ctx->level++;

	uint8_t nativeScriptType = parse_u1be(view);
	TRACE("native complex script type = %u", nativeScriptType);

	switch(nativeScriptType) {
#	define  CASE(TYPE, HANDLER) case TYPE: HANDLER(view); break;
		CASE(NATIVE_SCRIPT_ALL, deriveNativeScriptHash_handleAllOrAny);
		CASE(NATIVE_SCRIPT_ANY, deriveNativeScriptHash_handleAllOrAny);
		CASE(NATIVE_SCRIPT_N_OF_K, deriveNativeScriptHash_handleNofK);
		default: THROW(ERR_INVALID_DATA);
#	undef   CASE
	}
}

// Simple native scripts

void deriveNativeScriptHash_handleDeviceOwnedPubkey(read_view_t* view)
{
	bip44_path_t path;
	view_skipBytes(view, bip44_parseFromWire(&path, VIEW_REMAINING_TO_TUPLE_BUF_SIZE(view)));

	VALIDATE(view_remainingSize(view) == 0, ERR_INVALID_DATA);
	TRACE("Pubkey given by path:");
	BIP44_PRINTF(&path);
	PRINTF("\n");
}

void deriveNativeScriptHash_handleThirdPartyPubkey(read_view_t* view)
{
	uint8_t pubkeyHash[ADDRESS_KEY_HASH_LENGTH];
	VALIDATE(view_remainingSize(view) == ADDRESS_KEY_HASH_LENGTH, ERR_INVALID_DATA);
	view_memmove(pubkeyHash, view, ADDRESS_KEY_HASH_LENGTH);

#	ifdef DEVEL
	TRACE("Pubkey given by hash:");
	for (int i = 0; i < ADDRESS_KEY_HASH_LENGTH; i++) {
		PRINTF("%x", pubkeyHash[i]);
	}
	PRINTF("\n");
#	endif
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

void deriveNativeScriptHash_handleInvalidBefore(read_view_t* view)
{
	uint64_t timelock = parse_u8be(view);

	VALIDATE(view_remainingSize(view) == 0, ERR_INVALID_DATA);
	// PRINTF doesn't handle uint64_t so we split it into two uint32_t
	TRACE("invalid_before timelock = 0x%x%x", (uint32_t) (timelock >> 32), (uint32_t) timelock);
	UNUSED(timelock);
}

void deriveNativeScriptHash_handleInvalidHereafter(read_view_t* view)
{
	uint64_t timelock = parse_u8be(view);

	VALIDATE(view_remainingSize(view) == 0, ERR_INVALID_DATA);
	TRACE("invalid_hereafter timelock = 0x%x%x", (uint32_t) (timelock >> 32), (uint32_t) timelock);
	UNUSED(timelock);
}

void deriveNativeScriptHash_handleSimpleScript(read_view_t* view)
{
	TRACE_BUFFER(view->begin, (size_t) (view->end - view->begin));

	// if the number of remaining scripts is not bigger than 0, then this request
	// is invalid in the current context, as Ledger was not expecting another
	// script to be parsed
	VALIDATE(ctx->remainingScripts[ctx->level] > 0, ERR_INVALID_STATE);

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

	read_view_t view = make_read_view(wireDataBuffer, wireDataBuffer + wireDataSize);

	subhandler_fn_t* subhandler = lookup_subhandler(p1);
	VALIDATE(subhandler != NULL, ERR_INVALID_REQUEST_PARAMETERS);
	subhandler(&view);

	if (shouldFinish()) {
		TRACE("whole native script received");
	}

	// TODO: temporary solution for response
	io_send_buf(SUCCESS, NULL, 0);
}
