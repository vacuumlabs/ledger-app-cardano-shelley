#include "hexUtils.h"
#include "messageSigning.h"
#include "securityPolicy.h"
#include "signMsg.h"
#include "signTxUtils.h"
#include "state.h"
#include "signMsg_ui.h"

#ifdef HAVE_BAGL
#include "uiScreens_bagl.h"
#elif defined(HAVE_NBGL)
#include "uiScreens_nbgl.h"
#include "nbgl_use_case.h"
#endif

static ins_sign_msg_context_t* ctx = &(instructionState.signMsgContext);

// ============================== INIT ==============================

__noinline_due_to_stack__ static void _displayAddressField(ui_callback_fn_t* callback) {
    switch (ctx->addressFieldType) {
        case CIP8_ADDRESS_FIELD_ADDRESS: {
            uint8_t addressBuffer[MAX_ADDRESS_SIZE] = {0};
            size_t addressSize =
                deriveAddress(&ctx->addressParams, addressBuffer, SIZEOF(addressBuffer));
            ASSERT(addressSize > 0);
            ASSERT(addressSize <= MAX_ADDRESS_SIZE);

#ifdef HAVE_BAGL
            ui_displayAddressScreen("Address field", addressBuffer, addressSize, callback);
#elif defined(HAVE_NBGL)
            char humanAddress[MAX_HUMAN_ADDRESS_SIZE] = {0};
            ui_getAddressScreen(humanAddress, SIZEOF(humanAddress), addressBuffer, addressSize);
            fill_and_display_if_required("Address field",
                                         humanAddress,
                                         callback,
                                         respond_with_user_reject);
#endif  // HAVE_BAGL
            return;
        }

        case CIP8_ADDRESS_FIELD_KEYHASH: {
            uint8_t hash[28];
            blake2b_224_hash(ctx->witnessKey, SIZEOF(ctx->witnessKey), hash, SIZEOF(hash));

#ifdef HAVE_BAGL
            ui_displayHexBufferScreen("Address field (hex)", hash, SIZEOF(hash), callback);
#elif defined(HAVE_NBGL)
            char bufferHex[2 * SCRIPT_HASH_LENGTH + 1] = {0};
            ui_getHexBufferScreen(bufferHex, SIZEOF(bufferHex), hash, SIZEOF(hash));
            fill_and_display_if_required("Address field (hex)",
                                         bufferHex,
                                         callback,
                                         respond_with_user_reject);
#endif  // HAVE_BAGL
            return;
        }

        default:
            ASSERT(false);
            return;
    }
}

void signMsg_handleInit_ui_runStep() {
    TRACE("UI step %d", ctx->ui_step);
    TRACE_STACK_USAGE();
    ui_callback_fn_t* this_fn = signMsg_handleInit_ui_runStep;

    UI_STEP_BEGIN(ctx->ui_step, this_fn);

    UI_STEP(HANDLE_INIT_HASH_PAYLOAD) {
#ifdef HAVE_BAGL
        const char* firstLine = (ctx->hashPayload) ? "Sign hashed" : "Sign non-hashed";
        ui_displayPrompt(firstLine, "message? (CIP-8)", this_fn, respond_with_user_reject);
#elif defined(HAVE_NBGL)
        set_light_confirmation(true);
        const char* text = (ctx->hashPayload) ? "Sign hashed\nmessage? (CIP-8)"
                                              : "Sign non-hashed\nmessage? (CIP-8)";
        display_prompt(text, "", this_fn, respond_with_user_reject);
#endif  // HAVE_BAGL
    }
    UI_STEP(HANDLE_INIT_WITNESS_PATH) {
#ifdef HAVE_BAGL
        ui_displayPathScreen("Signing path", &ctx->signingPath, this_fn);
#elif defined(HAVE_NBGL)
        char pathStr[BIP44_PATH_STRING_SIZE_MAX + 1] = {0};
        ui_getPathScreen(pathStr, SIZEOF(pathStr), &ctx->signingPath);
        fill_and_display_if_required("Signing path", pathStr, this_fn, respond_with_user_reject);
#endif  // HAVE_BAGL
    }
    UI_STEP(HANDLE_INIT_ADDRESS_FIELD) {
        _displayAddressField(this_fn);
    }
    UI_STEP(HANDLE_INIT_RESPOND) {
        respondSuccessEmptyMsg();
        ctx->stage = SIGN_MSG_STAGE_CHUNKS;
    }
    UI_STEP_END(HANDLE_INIT_INVALID);
}

// ============================== CHUNK ==============================

void _displayMsgIntro(ui_callback_fn_t* callback) {
    char l1[30] = {0};
    if (ctx->isAscii) {
        snprintf(l1, SIZEOF(l1), "Message (ASCII)");
    } else {
        snprintf(l1, SIZEOF(l1), "Message (hex)");
    }
    ASSERT(strlen(l1) + 1 < SIZEOF(l1));

    char l2[30] = {0};
    ASSERT(ctx->msgLength < UINT32_MAX);
    snprintf(l2, SIZEOF(l2), "%u bytes", (uint32_t) ctx->msgLength);
    ASSERT(strlen(l2) + 1 < SIZEOF(l2));

#ifdef HAVE_BAGL
    ui_displayPaginatedText(l1, l2, callback);
#elif defined(HAVE_NBGL)
    fill_and_display_if_required(l1, l2, callback, respond_with_user_reject);
#endif  // HAVE_BAGL
}

__noinline_due_to_stack__ void _displayMsgFull(ui_callback_fn_t* callback) {
    char l1[30];
    if (ctx->isAscii) {
        snprintf(l1, SIZEOF(l1), "Message (ASCII)");
    } else {
        snprintf(l1, SIZEOF(l1), "Message (hex)");
    }
    ASSERT(strlen(l1) + 1 < SIZEOF(l1));

    char l2[200];
    if (ctx->isAscii) {
        ASSERT(ctx->chunkSize + 1 < SIZEOF(l2));
        memmove(l2, ctx->chunk, ctx->chunkSize);
        l2[ctx->chunkSize] = '\0';
    } else {
        encode_hex(ctx->chunk, ctx->chunkSize, l2, SIZEOF(l2));
    }
    ASSERT(strlen(l2) + 1 < SIZEOF(l2));

#ifdef HAVE_BAGL
    ui_displayPaginatedText(l1, l2, callback);
#elif defined(HAVE_NBGL)
    fill_and_display_if_required(l1, l2, callback, respond_with_user_reject);
#endif  // HAVE_BAGL
}

__noinline_due_to_stack__ void _displayMsgChunk(ui_callback_fn_t* callback) {
    const char* l1 = "Message starts with";

    char l2[200];
    if (ctx->isAscii) {
        ASSERT(ctx->chunkSize + 1 < SIZEOF(l2));
        memmove(l2, ctx->chunk, ctx->chunkSize);
        l2[ctx->chunkSize] = '\0';
    } else {
        encode_hex(ctx->chunk, ctx->chunkSize, l2, SIZEOF(l2));
    }
    ASSERT(strlen(l2) + 1 < SIZEOF(l2));

#ifdef HAVE_BAGL
    ui_displayPaginatedText(l1, l2, callback);
#elif defined(HAVE_NBGL)
    fill_and_display_if_required(l1, l2, callback, respond_with_user_reject);
#endif  // HAVE_BAGL
}

void signMsg_handleChunk_ui_runStep() {
    TRACE("UI step %d", ctx->ui_step);
    TRACE_STACK_USAGE();
    ui_callback_fn_t* this_fn = signMsg_handleChunk_ui_runStep;

    ASSERT(ctx->receivedChunks == 1);

    UI_STEP_BEGIN(ctx->ui_step, this_fn);

    UI_STEP(HANDLE_CHUNK_STEP_INTRO) {
        _displayMsgIntro(this_fn);
    }
    UI_STEP(HANDLE_CHUNK_STEP_DISPLAY) {
        if (ctx->msgLength == 0) {
            UI_STEP_JUMP(HANDLE_CHUNK_STEP_RESPOND);
        }
        if (ctx->remainingBytes == 0) {
            _displayMsgFull(this_fn);
        } else {
            _displayMsgChunk(this_fn);
        }
    }
    UI_STEP(HANDLE_CHUNK_STEP_RESPOND) {
        respondSuccessEmptyMsg();

        if (ctx->remainingBytes == 0) {
            ctx->stage = SIGN_MSG_STAGE_CONFIRM;
        }
    }
    UI_STEP_END(HANDLE_CHUNK_STEP_INVALID);
}

// ============================== CONFIRM ==============================

void signMsg_handleConfirm_ui_runStep() {
    TRACE("UI step %d", ctx->ui_step);
    TRACE_STACK_USAGE();
    ui_callback_fn_t* this_fn = signMsg_handleConfirm_ui_runStep;

    UI_STEP_BEGIN(ctx->ui_step, this_fn);

    UI_STEP(HANDLE_CONFIRM_STEP_MSG_HASH) {
#ifdef HAVE_BAGL
        ui_displayHexBufferScreen("Message hash", ctx->msgHash, SIZEOF(ctx->msgHash), this_fn);
#elif defined(HAVE_NBGL)
        char bufferHex[2 * CIP8_MSG_HASH_LENGTH + 1] = {0};
        ui_getHexBufferScreen(bufferHex, SIZEOF(bufferHex), ctx->msgHash, SIZEOF(ctx->msgHash));
        fill_and_display_if_required("Message hash", bufferHex, this_fn, respond_with_user_reject);
#endif  // HAVE_BAGL
    }
    UI_STEP(HANDLE_CONFIRM_STEP_FINAL_CONFIRM) {
#ifdef HAVE_BAGL
        ui_displayPrompt("Sign", "message?", this_fn, respond_with_user_reject);
#elif defined(HAVE_NBGL)
        display_confirmation("Sign\n message?",
                             "",
                             "MESSAGE\nSIGNED",
                             "Message\nrejected",
                             this_fn,
                             respond_with_user_reject);
#endif  // HAVE_BAGL
    }
    UI_STEP(HANDLE_CONFIRM_STEP_RESPOND) {
        struct {
            uint8_t signature[ED25519_SIGNATURE_LENGTH];
            uint8_t witnessKey[PUBLIC_KEY_SIZE];
            uint32_t addressFieldSize;
            uint8_t addressField[MAX_ADDRESS_SIZE];
        } wireResponse = {0};
        STATIC_ASSERT(SIZEOF(wireResponse) <= 255, "too large msg signing wire response");

        STATIC_ASSERT(SIZEOF(ctx->signature) == ED25519_SIGNATURE_LENGTH,
                      "wrong signature buffer size");
        memmove(wireResponse.signature, ctx->signature, ED25519_SIGNATURE_LENGTH);

        STATIC_ASSERT(SIZEOF(ctx->witnessKey) == PUBLIC_KEY_SIZE, "wrong key buffer size");
        memmove(wireResponse.witnessKey, ctx->witnessKey, PUBLIC_KEY_SIZE);

#ifndef FUZZING
        STATIC_ASSERT(sizeof(wireResponse.addressFieldSize) == 4, "wrong address field size type");
        STATIC_ASSERT(sizeof(ctx->addressFieldSize) == 4, "wrong address field size type");
        u4be_write((uint8_t*) &wireResponse.addressFieldSize, ctx->addressFieldSize);
#endif

        STATIC_ASSERT(SIZEOF(ctx->addressField) == SIZEOF(wireResponse.addressField),
                      "wrong address field size");
        memmove(wireResponse.addressField, ctx->addressField, ctx->addressFieldSize);

        io_send_buf(SUCCESS, (uint8_t*) &wireResponse, SIZEOF(wireResponse));
#ifdef HAVE_BAGL
        ui_displayBusy();  // displays dots, called only after I/O to avoid freezing
#endif                     // HAVE_BAGL

        ctx->stage = SIGN_MSG_STAGE_NONE;
        ui_idle();
    }
    UI_STEP_END(HANDLE_CONFIRM_STEP_INVALID);
}
