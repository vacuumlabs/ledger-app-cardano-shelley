#include "deriveNativeScriptHash.h"
#include "deriveNativeScriptHash_ui.h"
#include "state.h"
#include "textUtils.h"

#ifdef HAVE_BAGL
#include "uiScreens_bagl.h"
#elif defined(HAVE_NBGL)
#include "uiScreens_nbgl.h"
#include "nbgl_use_case.h"
#endif

static ins_derive_native_script_hash_context_t* ctx = &(instructionState.deriveNativeScriptHashContext);

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

	#ifdef HAVE_BAGL
	ui_displayPaginatedText(
	        HEADER,
	        positionDescription,
	        callback
	);
	#elif defined(HAVE_NBGL)
	set_light_confirmation(true);
	fill_and_display_new_page(HEADER, positionDescription, callback, respond_with_user_reject);
	#endif // HAVE_BAGL
}

#ifdef HAVE_NBGL
static void deriveScriptHash_display_ui_runStep_cb(void)
{
	// max possible length 85: "Requires n out of k signatures. Contains k nested scripts."
	// where n and k is 2^32-1
	char text[87] = {0};
	explicit_bzero(text, SIZEOF(text));
	snprintf(text, SIZEOF(text), "%u nested scripts", ctx->complexScripts[ctx->level].remainingScripts);
	// make sure all the information is displayed to the user
	ASSERT(strlen(text) + 1 < SIZEOF(text));
	fill_and_display_if_required("Script contents", text, deriveScriptHash_display_ui_runStep, respond_with_user_reject);
}
#endif // HAVE_NBGL

void deriveScriptHash_display_ui_runStep()
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
        else {
			deriveScriptHash_display_ui_position(level, this_fn);
		}
	}

	UI_STEP(DISPLAY_UI_STEP_TITLE) {
		#ifdef HAVE_BAGL
		UI_STEP_JUMP(DISPLAY_UI_STEP_SCRIPT_CONTENT);
		#elif defined(HAVE_NBGL)
		display_prompt("Review Script", "", this_fn, respond_with_user_reject);
		#endif // HAVE_NBGL
	}
	#ifdef HAVE_NBGL
	UI_STEP(DISPLAY_UI_STEP_SCRIPT_TYPE) {
		set_light_confirmation(true);
		switch (ctx->ui_scriptType) {
		case UI_SCRIPT_PUBKEY_PATH:
			fill_and_display_if_required("Script type", "Pubkey path", this_fn, respond_with_user_reject);
			break;
		case UI_SCRIPT_PUBKEY_HASH:
			fill_and_display_if_required("Script type", "Pubkey hash", this_fn, respond_with_user_reject);
			break;
		case UI_SCRIPT_ALL:
			fill_and_display_if_required("Script type", "ALL", this_fn, respond_with_user_reject);
			break;
		case UI_SCRIPT_ANY:
			fill_and_display_if_required("Script type", "ANY", this_fn, respond_with_user_reject);
			break;
		case UI_SCRIPT_N_OF_K:
			fill_and_display_if_required("Script type", "N out K", this_fn, respond_with_user_reject);
			break;
		case UI_SCRIPT_INVALID_BEFORE:
			fill_and_display_if_required("Script type", "Invalid before", this_fn, respond_with_user_reject);
			break;
		case UI_SCRIPT_INVALID_HEREAFTER:
			fill_and_display_if_required("Script type", "Invalid hereafter", this_fn, respond_with_user_reject);
			break;
		default:
			THROW(ERR_INVALID_STATE);
		}
	}
	#endif // HAVE_NBGL

	UI_STEP(DISPLAY_UI_STEP_SCRIPT_CONTENT) {
		TRACE("ui_scriptType = %d", ctx->ui_scriptType);
		switch (ctx->ui_scriptType) {
		case UI_SCRIPT_PUBKEY_PATH: {
			#ifdef HAVE_BAGL
			ui_displayPathScreen(
			        HEADER,
			        &ctx->scriptContent.pubkeyPath,
			        this_fn
			);
			#elif defined(HAVE_NBGL)
			char pathStr[BIP44_PATH_STRING_SIZE_MAX + 1] = {0};
			ui_getPathScreen(pathStr, SIZEOF(pathStr), &ctx->scriptContent.pubkeyPath);
			fill_and_display_if_required("Pubkey path", pathStr, this_fn, respond_with_user_reject);
			#endif // HAVE_BAGL
			break;
		}
		case UI_SCRIPT_PUBKEY_HASH: {
			#ifdef HAVE_BAGL
			ui_displayBech32Screen(
			        HEADER,
			        "addr_shared_vkh",
			        ctx->scriptContent.pubkeyHash,
			        ADDRESS_KEY_HASH_LENGTH,
			        this_fn
			);
			#elif defined(HAVE_NBGL)
			char encodedStr[BECH32_STRING_SIZE_MAX] = {0};
			ui_getBech32Screen(encodedStr, SIZEOF(encodedStr), "addr_shared_vkh", ctx->scriptContent.pubkeyHash, ADDRESS_KEY_HASH_LENGTH);
			fill_and_display_if_required("Pubkey hash", encodedStr, this_fn, respond_with_user_reject);
			#endif // HAVE_BAGL
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
			#ifdef HAVE_BAGL
			snprintf(text, SIZEOF(text), "Contains %u nested scripts.", ctx->complexScripts[ctx->level].remainingScripts);
			// make sure all the information is displayed to the user
			ASSERT(strlen(text) + 1 < SIZEOF(text));

			ui_displayPaginatedText(
			        HEADER,
			        text,
			        this_fn
			);
			#elif defined(HAVE_NBGL)
			snprintf(text, SIZEOF(text), "%u nested scripts", ctx->complexScripts[ctx->level].remainingScripts);
			// make sure all the information is displayed to the user
			ASSERT(strlen(text) + 1 < SIZEOF(text));
			fill_and_display_if_required("Content", text, this_fn, respond_with_user_reject);
			#endif // HAVE_BAGL
			break;
		}
		case UI_SCRIPT_N_OF_K: {
			STATIC_ASSERT(sizeof(ctx->scriptContent.requiredScripts) <= sizeof(unsigned), "oversized type for %u");
			STATIC_ASSERT(!IS_SIGNED(ctx->scriptContent.requiredScripts), "signed type for %u");
			STATIC_ASSERT(sizeof(ctx->complexScripts[ctx->level].remainingScripts) <= sizeof(unsigned), "oversized type for %u");
			STATIC_ASSERT(!IS_SIGNED(ctx->complexScripts[ctx->level].remainingScripts), "signed type for %u");
			// max possible length 85: "Requires n out of k signatures. Contains k nested scripts."
			// where n and k is 2^32-1
			char text[87] = {0};
			#ifdef HAVE_BAGL
			explicit_bzero(text, SIZEOF(text));
			snprintf(text, SIZEOF(text), "Requires %u out of %u signatures. Contains %u nested scripts", ctx->scriptContent.requiredScripts, ctx->complexScripts[ctx->level].remainingScripts, ctx->complexScripts[ctx->level].remainingScripts);
			// make sure all the information is displayed to the user
			ASSERT(strlen(text) + 1 < SIZEOF(text));

			ui_displayPaginatedText(
			        HEADER,
			        text,
			        this_fn
			);
			#elif defined(HAVE_NBGL)
			explicit_bzero(text, SIZEOF(text));
			snprintf(text, SIZEOF(text), "%u out of %u signatures", ctx->scriptContent.requiredScripts, ctx->complexScripts[ctx->level].remainingScripts);
			// make sure all the information is displayed to the user
			ASSERT(strlen(text) + 1 < SIZEOF(text));
			fill_and_display_if_required("Requirement", text, deriveScriptHash_display_ui_runStep_cb, respond_with_user_reject);
			#endif // HAVE_BAGL
			break;
		}
		case UI_SCRIPT_INVALID_BEFORE: {
			#ifdef HAVE_BAGL
			ui_displayUint64Screen(
			        HEADER,
			        ctx->scriptContent.timelock,
			        this_fn
			);
			#elif defined(HAVE_NBGL)
			char line[30];
			ui_getUint64Screen(
			        line,
			        SIZEOF(line),
			        ctx->scriptContent.timelock
			);
			fill_and_display_if_required("Invalid before", line, this_fn, respond_with_user_reject);
			#endif // HAVE_BAGL
			break;
		}

		case UI_SCRIPT_INVALID_HEREAFTER: {
			#ifdef HAVE_BAGL
			ui_displayUint64Screen(
			        HEADER,
			        ctx->scriptContent.timelock,
			        this_fn
			);
			#elif defined(HAVE_NBGL)
			char line[30];
			ui_getUint64Screen(
			        line,
			        SIZEOF(line),
			        ctx->scriptContent.timelock
			);
			fill_and_display_if_required("Invalid hereafter", line, this_fn, respond_with_user_reject);
			#endif // HAVE_BAGL
			break;
		}
		default:
			THROW(ERR_INVALID_STATE);
		}
	}

	UI_STEP(DISPLAY_UI_STEP_RESPOND) {
		io_send_buf(SUCCESS, NULL, 0);
		#ifdef HAVE_BAGL
		ui_displayBusy(); // displays dots, called only after I/O to avoid freezing
		#endif // HAVE_BAGL
	}

	UI_STEP_END(DISPLAY_UI_STEP_INVALID);
}
// Whole native script finish

void deriveNativeScriptHash_displayNativeScriptHash_callback()
{
	io_send_buf(SUCCESS, ctx->scriptHashBuffer, SCRIPT_HASH_LENGTH);
	ui_idle();
}

#ifdef HAVE_NBGL
static void deriveNativeScriptHash_displayNativeScriptHash_finish(void)
{
	display_confirmation("Confirm script", "", "SCRIPT\nCONFIRMED", "Script\nrejected", deriveNativeScriptHash_displayNativeScriptHash_callback, respond_with_user_reject);
}
#endif // HAVE_NBGL

void deriveNativeScriptHash_displayNativeScriptHash_bech32()
{
	#ifdef HAVE_BAGL
	ui_displayBech32Screen(
	        "Script hash",
	        "script",
	        ctx->scriptHashBuffer,
	        SCRIPT_HASH_LENGTH,
	        deriveNativeScriptHash_displayNativeScriptHash_callback
	);
	#elif defined(HAVE_NBGL)
	char encodedStr[BECH32_STRING_SIZE_MAX] = {0};
	ui_getBech32Screen(encodedStr, SIZEOF(encodedStr), "script", ctx->scriptHashBuffer, SCRIPT_HASH_LENGTH);
	fill_and_display_if_required("Script hash", encodedStr, deriveNativeScriptHash_displayNativeScriptHash_finish, respond_with_user_reject);
	#endif // HAVE_BAGL
}

void deriveNativeScriptHash_displayNativeScriptHash_policyId()
{
	#ifdef HAVE_BAGL
	ui_displayHexBufferScreen(
	        "Policy ID",
	        ctx->scriptHashBuffer,
	        SCRIPT_HASH_LENGTH,
	        deriveNativeScriptHash_displayNativeScriptHash_callback
	);
	#elif defined(HAVE_NBGL)
	char bufferHex[2 * 32 + 1] = {0};
	ui_getHexBufferScreen(bufferHex, SIZEOF(bufferHex), ctx->scriptHashBuffer, SCRIPT_HASH_LENGTH);
	fill_and_display_if_required("Policy ID", bufferHex, deriveNativeScriptHash_displayNativeScriptHash_finish, respond_with_user_reject);
	#endif // HAVE_BAGL
}
