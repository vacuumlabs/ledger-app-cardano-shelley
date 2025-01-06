#ifndef H_CARDANO_APP_SIGN_MSG
#define H_CARDANO_APP_SIGN_MSG

#include "addressUtilsShelley.h"
#include "cardano.h"
#include "common.h"
#include "handlers.h"
#include "hash.h"
#include "bip44.h"
#include "keyDerivation.h"

uint16_t signMsg_handleAPDU(uint8_t p1,
                            uint8_t p2,
                            const uint8_t* wireDataBuffer,
                            size_t wireDataSize,
                            bool isNewCall);

#define CIP8_MSG_HASH_LENGTH 28

// Note: this cannot be increased, there is a limit of 200 chars in the UI
#define MAX_CIP8_MSG_FIRST_CHUNK_ASCII_SIZE 198
#define MAX_CIP8_MSG_FIRST_CHUNK_HEX_SIZE   99
#define MAX_CIP8_MSG_HIDDEN_CHUNK_SIZE      250

typedef enum {
    SIGN_MSG_STAGE_NONE = 0,
    SIGN_MSG_STAGE_INIT = 43,
    SIGN_MSG_STAGE_CHUNKS = 44,
    SIGN_MSG_STAGE_CONFIRM = 45,
} sign_msg_stage_t;

typedef struct {
    bip44_path_t signingPath;
    cip8_address_field_type_t addressFieldType;
    addressParams_t addressParams;

    bool isAscii;
    bool hashPayload;

    size_t msgLength;
    size_t remainingBytes;
    size_t receivedChunks;

    uint8_t chunk[MAX_CIP8_MSG_HIDDEN_CHUNK_SIZE];
    size_t chunkSize;

    blake2b_224_context_t msgHashCtx;
    uint8_t msgHash[CIP8_MSG_HASH_LENGTH];
    uint8_t signature[ED25519_SIGNATURE_LENGTH];
    uint8_t witnessKey[PUBLIC_KEY_SIZE];
    uint8_t addressField[MAX_ADDRESS_SIZE];
    size_t addressFieldSize;

    sign_msg_stage_t stage;
    int ui_step;
} ins_sign_msg_context_t;

#endif  // H_CARDANO_APP_SIGN_MSG
