#ifndef H_CARDANO_APP_SIGN_TX_TYPES
#define H_CARDANO_APP_SIGN_TX_TYPES

#include "bip44.h"
#include "cardanoCertificates.h"

// the use case significantly affects restrictions on tx being signed
typedef enum {
	SIGN_TX_USECASE_ORDINARY_TX = 3, // enum value 3 is needed for backwards compatibility
	SIGN_TX_USECASE_POOL_REGISTRATION_OWNER = 4,
	//SIGN_TX_USECASE_POOL_REGISTRATION_OPERATOR = 5, // TODO will be added later; only allow if compiled with the proper flag
} sign_tx_usecase_t;



typedef enum {
	SIGN_TX_POOL_OWNER_TYPE_PATH = 1,
	SIGN_TX_POOL_OWNER_TYPE_KEY_HASH = 2,
} sign_tx_pool_owner_type_t;


#endif
