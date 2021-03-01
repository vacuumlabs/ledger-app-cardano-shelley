#ifndef H_CARDANO_APP_SIGN_OP_CERT
#define H_CARDANO_APP_SIGN_OP_CERT

#include "common.h"
#include "handlers.h"
#include "bip44.h"
#include "keyDerivation.h"

handler_fn_t signOpCert_handleAPDU;

#define KES_PUBLIC_KEY_LENGTH 32

typedef struct {
	int16_t responseReadyMagic;
	uint8_t kesPublicKey[KES_PUBLIC_KEY_LENGTH];
	uint64_t kesPeriod;
	uint64_t issueCounter;
	bip44_path_t poolColdKeyPathSpec;
	uint8_t signature[64];
	int ui_step;
} ins_sign_op_cert_context_t;

#endif // H_CARDANO_APP_SIGN_OP_CERT