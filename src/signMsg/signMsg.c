#include "common.h"

#include "signMsg.h"
#include "signMsg_ui.h"
#include "keyDerivation.h"
#include "endian.h"
#include "state.h"
#include "uiHelpers.h"
#include "securityPolicy.h"
#include "messageSigning.h"
#include "textUtils.h"
#include "signTxUtils.h"

#ifdef HAVE_BAGL
#include "uiScreens_bagl.h"
#elif defined(HAVE_NBGL)
#include "uiScreens_nbgl.h"
#endif

static ins_sign_msg_context_t* ctx = &(instructionState.signMsgContext);

void signMsg_handleInitAPDU(const uint8_t* wireDataBuffer, size_t wireDataSize) {
    {
        TRACE_BUFFER(wireDataBuffer, wireDataSize);
        read_view_t view = make_read_view(wireDataBuffer, wireDataBuffer + wireDataSize);

        ctx->msgLength = parse_u4be(&view);
        TRACE("Msg length: %d", ctx->msgLength);
        ctx->remainingBytes = ctx->msgLength;

        view_skipBytes(
            &view,
            bip44_parseFromWire(&ctx->signingPath, VIEW_REMAINING_TO_TUPLE_BUF_SIZE(&view)));
        TRACE("Signing path:");
        BIP44_PRINTF(&ctx->signingPath);
        PRINTF("\n");

        ctx->hashPayload = parse_bool(&view);
        TRACE("Hash payload: %d", ctx->hashPayload);

        ctx->isAscii = parse_bool(&view);
        TRACE("Is ascii: %d", ctx->isAscii);

        ctx->addressFieldType = parse_u1be(&view);
        TRACE("Address field type: %d", ctx->addressFieldType);
        switch (ctx->addressFieldType) {
            case CIP8_ADDRESS_FIELD_ADDRESS:
                view_parseAddressParams(&view, &ctx->addressParams);
                break;
            case CIP8_ADDRESS_FIELD_KEYHASH:
                // no address field data to parse
                break;
            default:
                THROW(ERR_INVALID_DATA);
        }

        VALIDATE(view_remainingSize(&view) == 0, ERR_INVALID_DATA);
    }

    // Check security policy
    security_policy_t policy =
        policyForSignMsg(&ctx->signingPath, ctx->addressFieldType, &ctx->addressParams);
    ENSURE_NOT_DENIED(policy);

    // always compute message hash
    blake2b_224_init(&ctx->msgHashCtx);

    {
        // key is sent back at the end and possibly needed when displaying address field
        extendedPublicKey_t extPubKey;
        deriveExtendedPublicKey(&ctx->signingPath, &extPubKey);
        STATIC_ASSERT(SIZEOF(extPubKey.pubKey) == SIZEOF(ctx->witnessKey),
                      "wrong witness key size");
        memmove(ctx->witnessKey, extPubKey.pubKey, SIZEOF(extPubKey.pubKey));
    }

    // this must always be shown
    ASSERT(policy == POLICY_PROMPT_BEFORE_RESPONSE);
    ctx->ui_step = HANDLE_INIT_HASH_PAYLOAD;
    signMsg_handleInit_ui_runStep();
}

static void signMsg_handleMsgChunkAPDU(const uint8_t* wireDataBuffer, size_t wireDataSize) {
    {
        ASSERT(ctx->stage == SIGN_MSG_STAGE_CHUNKS);
        if (!ctx->hashPayload) {
            // only a single chunk is to be received
            ASSERT(ctx->receivedChunks == 0);
        }
    }
    {
        TRACE_BUFFER(wireDataBuffer, wireDataSize);

        ctx->receivedChunks += 1;

        read_view_t view = make_read_view(wireDataBuffer, wireDataBuffer + wireDataSize);

        const size_t chunkSize = parse_u4be(&view);
        TRACE("chunkSize = %u", chunkSize);

        VALIDATE(chunkSize <= ctx->remainingBytes, ERR_INVALID_DATA);

        // the current chunk should have maximum allowed size;
        // there is no point in allowing unnecessarily small chunks
        // and it is a security risk if the first chunk (possibly the only one displayed)
        // is artificially small
        if (ctx->receivedChunks == 1) {
            // the first chunk must be displayable
            // the check below works for empty message (with special UI) too
            if (ctx->isAscii) {
                VALIDATE(chunkSize == MIN(ctx->msgLength, MAX_CIP8_MSG_FIRST_CHUNK_ASCII_SIZE),
                         ERR_INVALID_DATA);
            } else {
                VALIDATE(chunkSize == MIN(ctx->msgLength, MAX_CIP8_MSG_FIRST_CHUNK_HEX_SIZE),
                         ERR_INVALID_DATA);
            }
        } else {
            // ctx->receivedChunks >= 2
            VALIDATE(chunkSize == MIN(ctx->remainingBytes, MAX_CIP8_MSG_HIDDEN_CHUNK_SIZE),
                     ERR_INVALID_DATA);
        }

        ASSERT(chunkSize <= ctx->remainingBytes);
        ctx->remainingBytes -= chunkSize;
        ctx->chunkSize = chunkSize;

        ASSERT(chunkSize <= SIZEOF(ctx->chunk));
        view_parseBuffer(ctx->chunk, &view, chunkSize);
        if (ctx->isAscii) {
            VALIDATE(str_isUnambiguousAscii(ctx->chunk, ctx->chunkSize), ERR_INVALID_DATA);
        }

        VALIDATE(view_remainingSize(&view) == 0, ERR_INVALID_DATA);
    }
    {
        TRACE("Adding msg chunk to msg hash");
        blake2b_224_append(&ctx->msgHashCtx, ctx->chunk, ctx->chunkSize);
    }

    if (ctx->receivedChunks == 1) {
        if (!ctx->hashPayload) {
            // for non-hashed payload, we expect only a single chunk
            VALIDATE(ctx->remainingBytes == 0, ERR_INVALID_DATA);
        }
        ctx->ui_step = HANDLE_CHUNK_STEP_INTRO;
        signMsg_handleChunk_ui_runStep();
    } else {
        // for non-hashed payload, we expect only a single chunk,
        // so the state should be SIGN_MSG_STAGE_CONFIRM already
        ASSERT(ctx->hashPayload);

        // the chunk has been added to msg hash, nothing more to do, and no UI
        respondSuccessEmptyMsg();

        if (ctx->remainingBytes == 0) {
            ctx->stage = SIGN_MSG_STAGE_CONFIRM;
        }
    }
}

static void _prepareAddressField() {
    switch (ctx->addressFieldType) {
        case CIP8_ADDRESS_FIELD_ADDRESS: {
            ctx->addressFieldSize =
                deriveAddress(&ctx->addressParams, ctx->addressField, SIZEOF(ctx->addressField));
            break;
        }

        case CIP8_ADDRESS_FIELD_KEYHASH: {
            STATIC_ASSERT(SIZEOF(ctx->addressField) >= ADDRESS_KEY_HASH_LENGTH,
                          "wrong address field size");
            bip44_pathToKeyHash(&ctx->signingPath, ctx->addressField, ADDRESS_KEY_HASH_LENGTH);
            ctx->addressFieldSize = ADDRESS_KEY_HASH_LENGTH;
            break;
        }

        default:
            ASSERT(false);
    }
}

__noinline_due_to_stack__ static size_t _createProtectedHeader(uint8_t* protectedHeaderBuffer,
                                                               size_t maxSize) {
    // protectedHeader = {
    //     1 : -8,                         // set algorithm to EdDSA
    //     “address” : address_bytes       // raw address given by the user, or key hash
    // }
    uint8_t* p = protectedHeaderBuffer;
    uint8_t* end = protectedHeaderBuffer + maxSize;

    {
        size_t len = cbor_writeToken(CBOR_TYPE_MAP, 2, p, end - p);
        p += len;
        ASSERT(p < end);
    }
    {
        size_t len = cbor_writeToken(CBOR_TYPE_UNSIGNED, 1, p, end - p);
        p += len;
        ASSERT(p < end);
    }
    {
        size_t len = cbor_writeToken(CBOR_TYPE_NEGATIVE, -8, p, end - p);
        p += len;
        ASSERT(p < end);
    }
    {
        size_t len = cbor_writeToken(CBOR_TYPE_TEXT, 7, p, end - p);
        p += len;
        ASSERT(p < end);
    }
    {
        const char* text = "address";
        const size_t len = strlen(text);
        ASSERT(p + len < end);
        memmove(p, text, len);
        p += len;
        ASSERT(p < end);
    }
    {
        _prepareAddressField();
        ASSERT(ctx->addressFieldSize > 0);

        size_t len = cbor_writeToken(CBOR_TYPE_BYTES, ctx->addressFieldSize, p, end - p);
        p += len;
        ASSERT(p + ctx->addressFieldSize < end);
        memmove(p, ctx->addressField, ctx->addressFieldSize);
        p += ctx->addressFieldSize;
        ASSERT(p < end);
    }

    const size_t protectedHeaderSize = p - protectedHeaderBuffer;
    ASSERT(protectedHeaderSize > 0);
    ASSERT(protectedHeaderSize < maxSize);

    return protectedHeaderSize;
}

static void signMsg_handleConfirmAPDU(const uint8_t* wireDataBuffer MARK_UNUSED,
                                      size_t wireDataSize) {
    VALIDATE(wireDataSize == 0, ERR_INVALID_DATA);

    // it seems Ledger can sign 400 B, more is not needed since non-hashed msg is capped at 200 B
    uint8_t sigStructure[400] = {0};
    explicit_bzero(sigStructure, SIZEOF(sigStructure));
    size_t written = 0;
    const size_t maxWritten = SIZEOF(sigStructure);

    // Sig_structure = [
    // 	   context : “Signature1”,
    //     body_protected : CBOR_encode(protectedHeader),
    //     external_aad : bstr,            // empty buffer here
    //     payload : bstr                  // message or its hash as bytes
    // ]

    written += cbor_writeToken(CBOR_TYPE_ARRAY, 4, sigStructure + written, maxWritten - written);
    ASSERT(written < maxWritten);

    {
        const char* firstElement = "Signature1";
        const size_t len = strlen(firstElement);
        written +=
            cbor_writeToken(CBOR_TYPE_TEXT, len, sigStructure + written, maxWritten - written);
        ASSERT(written + len < maxWritten);
        memmove(sigStructure + written, firstElement, len);
        written += len;
        ASSERT(written < maxWritten);
    }
    {
        uint8_t protectedHeaderBuffer[100] = {
            0};  // address of max 57 bytes plus a couple of small items
        const size_t len =
            _createProtectedHeader(protectedHeaderBuffer, SIZEOF(protectedHeaderBuffer));
        ASSERT(len < BUFFER_SIZE_PARANOIA);
        written +=
            cbor_writeToken(CBOR_TYPE_BYTES, len, sigStructure + written, maxWritten - written);
        ASSERT(written + len < maxWritten);
        memmove(sigStructure + written, protectedHeaderBuffer, len);
        written += len;
        ASSERT(written < maxWritten);
    }
    {
        written +=
            cbor_writeToken(CBOR_TYPE_BYTES, 0, sigStructure + written, maxWritten - written);
        ASSERT(written < maxWritten);
    }
    STATIC_ASSERT(SIZEOF(ctx->msgHash) * 8 == 224, "inconsistent message hash size");
    blake2b_224_finalize(&ctx->msgHashCtx, ctx->msgHash, SIZEOF(ctx->msgHash));
    {
        if (ctx->hashPayload) {
            written += cbor_writeToken(CBOR_TYPE_BYTES,
                                       SIZEOF(ctx->msgHash),
                                       sigStructure + written,
                                       maxWritten - written);
            ASSERT(written < maxWritten);

            ASSERT(SIZEOF(ctx->msgHash) < maxWritten - written);
            memmove(sigStructure + written, ctx->msgHash, SIZEOF(ctx->msgHash));
            written += SIZEOF(ctx->msgHash);
            ASSERT(written < maxWritten);
        } else {
            // for non-hashed payload, the chunk from the previous APDU is used
            ASSERT(ctx->receivedChunks == 1);

            written += cbor_writeToken(CBOR_TYPE_BYTES,
                                       ctx->chunkSize,
                                       sigStructure + written,
                                       maxWritten - written);
            ASSERT(written < maxWritten);

            ASSERT(ctx->chunkSize < maxWritten - written);
            memmove(sigStructure + written, ctx->chunk, ctx->chunkSize);
            written += ctx->chunkSize;
            ASSERT(written < maxWritten);
        }
    }

    const size_t sigStructureSize = written;
    TRACE_BUFFER(sigStructure, sigStructureSize);

    // we do not sign anything that could be a transaction hash
    // Note: in the v7.1 implementation Sig_structure has more than 40 bytes
    ASSERT(sigStructureSize != TX_HASH_LENGTH);

    signRawMessageWithPath(&ctx->signingPath,
                           sigStructure,
                           sigStructureSize,
                           ctx->signature,
                           SIZEOF(ctx->signature));

    ctx->ui_step = HANDLE_CONFIRM_STEP_MSG_HASH;
    signMsg_handleConfirm_ui_runStep();
}

// ============================== MAIN HANDLER ==============================

typedef void subhandler_fn_t(const uint8_t* dataBuffer, size_t dataSize);

static subhandler_fn_t* lookup_subhandler(uint8_t p1) {
    switch (p1) {
#define CASE(P1, HANDLER) \
    case P1:              \
        return HANDLER;
#define DEFAULT(HANDLER) \
    default:             \
        return HANDLER;
        CASE(0x01, signMsg_handleInitAPDU);
        CASE(0x02, signMsg_handleMsgChunkAPDU);
        CASE(0x03, signMsg_handleConfirmAPDU);
        DEFAULT(NULL)
#undef CASE
#undef DEFAULT
    }
}

uint16_t signMsg_handleAPDU(uint8_t p1,
                            uint8_t p2,
                            const uint8_t* wireDataBuffer,
                            size_t wireDataSize,
                            bool isNewCall) {
    TRACE("P1 = 0x%x, P2 = 0x%x, isNewCall = %d", p1, p2, isNewCall);
    if (p1 == 0x03) {
        ASSERT(wireDataBuffer == NULL);
        ASSERT(wireDataSize == 0);
    } else {
        ASSERT(wireDataBuffer != NULL);
    }
    ASSERT(wireDataSize < BUFFER_SIZE_PARANOIA);

    VALIDATE(p2 == P2_UNUSED, ERR_INVALID_REQUEST_PARAMETERS);

    if (isNewCall) {
        explicit_bzero(ctx, SIZEOF(*ctx));
        ctx->stage = SIGN_MSG_STAGE_INIT;
    }

    subhandler_fn_t* subhandler = lookup_subhandler(p1);
    VALIDATE(subhandler != NULL, ERR_INVALID_REQUEST_PARAMETERS);
    subhandler(wireDataBuffer, wireDataSize);
    return ERR_NO_RESPONSE;
}
