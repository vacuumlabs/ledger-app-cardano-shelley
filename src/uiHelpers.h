#ifndef H_CARDANO_APP_UI_HELPERS
#define H_CARDANO_APP_UI_HELPERS

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <ux.h>

#include "utils.h"

typedef void ui_callback_fn_t();

// *INDENT-OFF*

// Warning: Following macros are *NOT* brace-balanced by design!
// The macros simplify writing resumable logic that needs to happen over
// multiple calls.

// Example usage:
// UI_STEP_BEGIN(ctx->ui_step, this_fn);
// UI_STEP(1) {do something & setup callback}
// UI_STEP(2) {do something & setup callback}
// UI_STEP_END(-1); // invalid state

#define UI_STEP_BEGIN(STEP_VAR, THIS_FN) \
	{ \
		int* __ui_step_ptr = &(STEP_VAR); \
		__attribute__((unused)) ui_callback_fn_t* __this_fn = (THIS_FN); \
		switch(*__ui_step_ptr) { \
			default: { \
				ASSERT(false);

#define UI_STEP(NEXT_STEP) \
				*__ui_step_ptr = NEXT_STEP; \
				break; \
			} \
			case NEXT_STEP: {

#define UI_STEP_END(INVALID_STEP) \
				*__ui_step_ptr = INVALID_STEP; \
				break; \
			} \
		} \
	}

// Early exit to another state, should be used inside UI_STEP
#define UI_STEP_JUMP(NEXT_STEP) \
		{ \
			*__ui_step_ptr = NEXT_STEP; \
			__this_fn(); \
			return; \
		}

// *INDENT-ON*


typedef enum {
	CALLBACK_NOT_RUN,
	CALLBACK_RUN,
} ui_callback_state_t;

typedef struct {
	ui_callback_state_t state;
	ui_callback_fn_t* confirm;
	ui_callback_fn_t* reject;
} ui_callback_t;


typedef struct {
	uint16_t initMagic;
	char header[30];
	char currentText[18];
	char fullText[200];
	size_t scrollIndex;
	ui_callback_t callback;
	#ifdef HEADLESS
	bool headlessShouldRespond;
	#endif
} paginatedTextState_t;

typedef struct {
	uint16_t initMagic;
	char header[30];
	char text[30];
	ui_callback_t callback;
	#ifdef HEADLESS
	bool headlessShouldRespond;
	#endif
} promptState_t;

typedef union {
	paginatedTextState_t paginatedText;
	promptState_t prompt;
} displayState_t;


// ui_idle displays the main menu screen. Command handlers should call ui_idle
// when they finish.
void ui_idle(void);

void ui_displayPaginatedText(
        const char* headerStr,
        const char* bodyStr,
        ui_callback_fn_t* callback);

void ui_displayPrompt(
        const char* headerStr,
        const char* bodyStr,
        ui_callback_fn_t* confirm,
        ui_callback_fn_t* reject
);

void ui_displayBusy();
void ui_displayPrompt_run();
void ui_displayPaginatedText_run();

void uiCallback_confirm(ui_callback_t* cb);
void uiCallback_reject(ui_callback_t* cb);

void assert_uiPaginatedText_magic();
void assert_uiPrompt_magic();

// responds to the host and resets
// processing
void respond_with_user_reject();

extern displayState_t displayState;

// WARNING(ppershing): Following two references MUST be declared `static`
// otherwise the Ledger will crash. I am really not sure why is this
// but it might be related to position-independent-code compilation.
static paginatedTextState_t* paginatedTextState = &(displayState.paginatedText);
static promptState_t* promptState = &(displayState.prompt);

enum {
	INIT_MAGIC_PAGINATED_TEXT = 2345,
	INIT_MAGIC_PROMPT = 5432,
};

static inline void ui_crash_handler()
{
	#ifdef RESET_ON_CRASH
	io_seproxyhal_se_reset();
	#else
	#endif
}

#define TRY_CATCH_UI(ui_call) \
	BEGIN_TRY { \
		TRY { \
			ui_call; \
		} \
		CATCH(EXCEPTION_IO_RESET) \
		{ \
			THROW(EXCEPTION_IO_RESET); \
		} \
		CATCH_OTHER(e) \
		{ \
			TRACE("Error %d\n", (int) e); \
			ui_crash_handler(); \
		} \
		FINALLY { \
		} \
	} \
	END_TRY;

#endif // H_CARDANO_APP_UI_HELPERS
