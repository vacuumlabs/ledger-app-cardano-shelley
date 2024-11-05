#ifdef DEVEL

#include "runTests.h"
#include "cbor.h"
#include "base58.h"
#include "bech32.h"
#include "testUtils.h"
#include "hexUtils.h"
#include "hash.h"
#include "bip44.h"
#include "keyDerivation.h"
#include "addressUtilsByron.h"
#include "addressUtilsShelley.h"
#include "crc32.h"
#include "txHashBuilder.h"
#include "auxDataHashBuilder.h"
#include "textUtils.h"
#include "ipUtils.h"
#include "uiHelpers.h"
#include "tokens.h"
#include "deriveNativeScriptHash.h"

void handleRunTests(uint8_t p1 MARK_UNUSED,
                    uint8_t p2 MARK_UNUSED,
                    const uint8_t* wireBuffer MARK_UNUSED,
                    size_t wireSize MARK_UNUSED,
                    bool isNewCall MARK_UNUSED) {
    // Note: Make sure to have RESET_ON_CRASH flag disabled
    // as it interferes with tests verifying assertions
    BEGIN_ASSERT_NOEXCEPT {
        PRINTF("Running tests\n");
        run_hex_test();
        run_base58_test();
        run_bech32_test();
        run_crc32_test();
        run_endian_test();
        run_textUtils_test();
        run_tokens_test();
#if defined(APP_FEATURE_POOL_REGISTRATION)
        run_ipUtils_test();
#endif
        run_hash_test();
        run_cbor_test();
        run_bip44_test();
        run_key_derivation_test();
#if !defined(APP_XS)
        run_addressUtilsByron_test();
#endif
        run_addressUtilsShelley_test();
        run_auxDataHashBuilder_test();
#if defined(APP_FEATURE_NATIVE_SCRIPT_HASH)
        run_nativeScriptHashBuilder_test();
#endif
        PRINTF("All tests done\n");
    }
    END_ASSERT_NOEXCEPT;

    io_send_buf(SUCCESS, NULL, 0);
    ui_idle();
}

#endif  // DEVEL
