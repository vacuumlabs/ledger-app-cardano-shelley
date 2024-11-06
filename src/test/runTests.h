#ifndef H_CARDANO_APP_RUN_TESTS
#define H_CARDANO_APP_RUN_TESTS

#ifdef DEVEL

#include "handlers.h"

uint16_t handleRunTests();

void run_hex_test();
void run_base58_test();
void run_bech32_test();
void run_crc32_test();
void run_endian_test();
void run_textUtils_test();
void run_tokens_test();
#if defined(APP_FEATURE_POOL_REGISTRATION)
void run_ipUtils_test();
#endif
void run_hash_test();
void run_cbor_test();
void run_bip44_test();
void run_key_derivation_test();
#if !defined(APP_XS)
void run_addressUtilsByron_test();
#endif
void run_addressUtilsShelley_test();
void run_auxDataHashBuilder_test();
#if defined(APP_FEATURE_NATIVE_SCRIPT_HASH)
void run_nativeScriptHashBuilder_test();
#endif

#endif  // DEVEL

#endif  // H_CARDANO_APP_RUN_TESTS
