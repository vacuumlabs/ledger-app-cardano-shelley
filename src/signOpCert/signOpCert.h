#ifndef H_CARDANO_APP_SIGN_OP_CERT
#define H_CARDANO_APP_SIGN_OP_CERT

#ifdef APP_FEATURE_OPCERT

#include "cardano.h"
#include "common.h"
#include "handlers.h"
#include "bip44.h"
#include "keyDerivation.h"

uint16_t signOpCert_handleAPDU(uint8_t p1,
                               uint8_t p2,
                               const uint8_t* wireDataBuffer,
                               size_t wireDataSize,
                               bool isNewCall);

#define KES_PUBLIC_KEY_LENGTH 32

typedef struct {
    int16_t responseReadyMagic;
    uint8_t kesPublicKey[KES_PUBLIC_KEY_LENGTH];
    uint64_t kesPeriod;
    uint64_t issueCounter;
    bip44_path_t poolColdKeyPathSpec;
    uint8_t signature[ED25519_SIGNATURE_LENGTH];
    int ui_step;
} ins_sign_op_cert_context_t;

#endif  // APP_FEATURE_OPCERT

#endif  // H_CARDANO_APP_SIGN_OP_CERT
