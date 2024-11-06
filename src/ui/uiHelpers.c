#include "os_io_seproxyhal.h"

#include "uiHelpers.h"
#include "uiElements.h"
#include "assert.h"
#include "utils.h"
#include "securityPolicy.h"
#include "ui.h"

io_state_t io_state;

displayState_t displayState;

STATIC_ASSERT(SIZEOF(uint8_t) == SIZEOF(char), "bad char size");

#ifdef HAVE_BAGL
void assert_uiPaginatedText_magic() {
    ASSERT(paginatedTextState->initMagic == INIT_MAGIC_PAGINATED_TEXT);
}

void assert_uiPrompt_magic() {
    ASSERT(promptState->initMagic == INIT_MAGIC_PROMPT);
}

void uiCallback_confirm(ui_callback_t* cb) {
    if (!cb->confirm) return;

    switch (cb->state) {
        case CALLBACK_NOT_RUN:
            // Note: needs to be done before resolving in case it throws
            cb->state = CALLBACK_RUN;
            cb->confirm();
            break;
        case CALLBACK_RUN:
            // Ignore
            break;
        default:
            ASSERT(false);
    }
}

void uiCallback_reject(ui_callback_t* cb) {
    if (!cb->reject) return;

    switch (cb->state) {
        case CALLBACK_NOT_RUN:
            // Note: needs to be done before resolving in case it throws
            cb->state = CALLBACK_RUN;
            cb->reject();
            break;
        case CALLBACK_RUN:
            // Ignore
            break;
        default:
            ASSERT(false);
    }
}

#ifdef HEADLESS
static int HEADLESS_DELAY = 20;

void ui_displayPrompt_headless_cb(bool ux_allowed) {
    TRACE("HEADLESS response");
    if (!ux_allowed) {
        TRACE("No UX allowed, ignoring headless cb!");
        return;
    }
    TRY_CATCH_UI({
        assert_uiPrompt_magic();
        ASSERT(io_state == IO_EXPECT_UI);
        ASSERT(device_is_unlocked() == true);
        uiCallback_confirm(&promptState->callback);
    })
}

void autoconfirmPrompt() {
    set_timer(HEADLESS_DELAY, ui_displayPrompt_headless_cb);
}

void ui_displayPaginatedText_headless_cb(bool ux_allowed) {
    TRACE("HEADLESS response");
    if (!ux_allowed) {
        TRACE("No UX allowed, ignoring headless cb!");
        return;
    }
    TRY_CATCH_UI({
        assert_uiPaginatedText_magic();
        ASSERT(io_state == IO_EXPECT_UI);
        ASSERT(device_is_unlocked() == true);
        uiCallback_confirm(&paginatedTextState->callback);
    });
}

void autoconfirmPaginatedText() {
    set_timer(HEADLESS_DELAY, ui_displayPaginatedText_headless_cb);
}

#endif  // HEADLESS

static void uiCallback_init(ui_callback_t* cb,
                            ui_callback_fn_t* confirm,
                            ui_callback_fn_t* reject) {
    cb->state = CALLBACK_NOT_RUN;
    cb->confirm = confirm;
    cb->reject = reject;
}

void ui_displayPrompt(const char* headerStr,
                      const char* bodyStr,
                      ui_callback_fn_t* confirm,
                      ui_callback_fn_t* reject) {
    TRACE_STACK_USAGE();
    TRACE("%s", headerStr);
    TRACE("%s", bodyStr);

    size_t header_len = strlen(headerStr);
    size_t text_len = strlen(bodyStr);
    // sanity checks, keep 1 byte for null terminator
    ASSERT(header_len < SIZEOF(promptState->header));
    ASSERT(text_len < SIZEOF(promptState->text));

    // clear all memory
    explicit_bzero(&displayState, SIZEOF(displayState));
    promptState_t* ctx = promptState;

    // Copy data
    memmove(ctx->header, headerStr, header_len + 1);
    memmove(ctx->text, bodyStr, text_len + 1);

    uiCallback_init(&ctx->callback, confirm, reject);
    ctx->initMagic = INIT_MAGIC_PROMPT;
    ASSERT(io_state == IO_EXPECT_NONE || io_state == IO_EXPECT_UI);
    io_state = IO_EXPECT_UI;

    ui_displayPrompt_run();

#ifdef HEADLESS
    if (confirm) {
        autoconfirmPrompt();
    }
#endif  // HEADLESS
}

void ui_displayPaginatedText(const char* headerStr,
                             const char* bodyStr,
                             ui_callback_fn_t* callback) {
    TRACE_STACK_USAGE();
    TRACE("%s", headerStr);
    TRACE("%s", bodyStr);

    // sanity checks
    ASSERT(uiPaginatedText_canFitStringIntoHeader(headerStr));
    ASSERT(uiPaginatedText_canFitStringIntoFullText(bodyStr));

    paginatedTextState_t* ctx = paginatedTextState;
    size_t header_len = strlen(headerStr);
    size_t body_len = strlen(bodyStr);

    // clear all memory
    explicit_bzero(ctx, SIZEOF(*ctx));

    // Copy data
    memmove(ctx->header, headerStr, header_len);
    memmove(ctx->fullText, bodyStr, body_len);

    ctx->scrollIndex = 0;

    memmove(ctx->currentText, ctx->fullText, SIZEOF(ctx->currentText) - 1);

    uiCallback_init(&ctx->callback, callback, NULL);
    ctx->initMagic = INIT_MAGIC_PAGINATED_TEXT;
    TRACE("setting timeout");
    TRACE("done");
    ASSERT(io_state == IO_EXPECT_NONE || io_state == IO_EXPECT_UI);
    io_state = IO_EXPECT_UI;

    ui_displayPaginatedText_run();

#ifdef HEADLESS
    if (callback) {
        autoconfirmPaginatedText();
    }
#endif  // HEADLESS
}
#endif  // HAVE_BAGL

void ui_displayUnusualWarning(ui_callback_fn_t* cb) {
#ifdef HAVE_BAGL
    ui_displayPaginatedText("Unusual request", "Proceed with care", cb);
#elif defined(HAVE_NBGL)
    set_light_confirmation(true);
    display_warning("Unusual request\nProceed with care", cb, respond_with_user_reject);
#endif  // HAVE_BAGL
}

void respond_with_user_reject() {
    io_send_buf(ERR_REJECTED_BY_USER, NULL, 0);
    ui_idle();
}

bool uiPaginatedText_canFitStringIntoHeader(const char* str) {
    return strlen(str) < SIZEOF(paginatedTextState->header);
}

bool uiPaginatedText_canFitStringIntoFullText(const char* str) {
    return strlen(str) < SIZEOF(paginatedTextState->fullText);
}
