#ifdef DEVEL

#include "runTests.h"
#include "testUtils.h"
#include "hexUtils.h"
#include "ui.h"

uint16_t handleRunTests() {
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
    return ERR_NO_RESPONSE;
}

#endif  // DEVEL
