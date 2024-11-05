cmake_minimum_required(VERSION 3.22)

project(cardano_fuzzers C)

set(CMAKE_C_STANDARD 11)

if (NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "Fuzzer needs to be built with Clang")
endif()

# guard against in-source builds
if(${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_BINARY_DIR})
  message(FATAL_ERROR "In-source builds not allowed. Please make a new directory (called a build directory) and run CMake from there. You may need to remove CMakeCache.txt. ")
endif()


if (NOT DEFINED ENV{LIB_FUZZING_ENGINE})
    add_compile_options(-fsanitize=address,fuzzer-no-link)
    add_link_options(-fsanitize=address,fuzzer)
else()
    add_link_options($ENV{LIB_FUZZING_ENGINE})
endif()

add_compile_options(-g)


set(SDK_PATH ${BOLOS_SDK})
set(UX_PATH ${SDK_PATH}/lib_ux)
set(CARDANO_PATH ..)

set(UX_SOURCE
    ${UX_PATH}/src/ux_flow_engine.c
    ${UX_PATH}/src/ux_layout_bb.c
    ${UX_PATH}/src/ux_layout_bn.c
    ${UX_PATH}/src/ux_layout_bnn.c
    ${UX_PATH}/src/ux_layout_bnnn.c
    ${UX_PATH}/src/ux_layout_nn.c
    ${UX_PATH}/src/ux_layout_paging.c
    ${UX_PATH}/src/ux_layout_paging_compute.c
    ${UX_PATH}/src/ux_layout_pbb.c
    ${UX_PATH}/src/ux_layout_pb.c
    ${UX_PATH}/src/ux_layout_pn.c
    ${UX_PATH}/src/ux_layout_pnn.c
    ${UX_PATH}/src/ux_layout_utils.c
    ${UX_PATH}/src/ux_stack.c
)

set(CARDANO_SOURCE
    ${CARDANO_PATH}/src/addressUtils/addressUtilsByron.c
    ${CARDANO_PATH}/src/addressUtils/addressUtilsShelley.c
    ${CARDANO_PATH}/src/auxDataHashBuilder/auxDataHashBuilder.c
    ${CARDANO_PATH}/src/crypto/bech32.c
    ${CARDANO_PATH}/src/crypto/bip44.c
    ${CARDANO_PATH}/src/crypto/crypto.c
    ${CARDANO_PATH}/src/deriveAddress/deriveAddress.c
    ${CARDANO_PATH}/src/deriveNativeScriptHash/deriveNativeScriptHash.c
    ${CARDANO_PATH}/src/deriveNativeScriptHash/deriveNativeScriptHash_ui.c
    ${CARDANO_PATH}/src/getPublicKey/getPublicKeys.c
    ${CARDANO_PATH}/src/getPublicKey/getPublicKeys_ui.c
    ${CARDANO_PATH}/src/handlers/getSerial.c
    ${CARDANO_PATH}/src/handlers/getVersion.c
    ${CARDANO_PATH}/src/handlers/handlers.c
    ${CARDANO_PATH}/src/keyDerivation/keyDerivation.c
    ${CARDANO_PATH}/src/messageSigning/messageSigning.c
    ${CARDANO_PATH}/src/nativeScriptHashBuilder/nativeScriptHashBuilder.c
    ${CARDANO_PATH}/src/securityPolicy/securityPolicy.c
    ${CARDANO_PATH}/src/signCVote/signCVote.c
    ${CARDANO_PATH}/src/signCVote/signCVote_ui.c
    ${CARDANO_PATH}/src/signMsg/signMsg.c
    ${CARDANO_PATH}/src/signMsg/signMsg_ui.c
    ${CARDANO_PATH}/src/signOpCert/signOpCert.c
    ${CARDANO_PATH}/src/signTx/signTx.c
    ${CARDANO_PATH}/src/signTx/signTxCVoteRegistration.c
    ${CARDANO_PATH}/src/signTx/signTxCVoteRegistration_ui.c
    ${CARDANO_PATH}/src/signTx/signTxMint.c
    ${CARDANO_PATH}/src/signTx/signTxMint_ui.c
    ${CARDANO_PATH}/src/signTx/signTxOutput.c
    ${CARDANO_PATH}/src/signTx/signTxOutput_ui.c
    ${CARDANO_PATH}/src/signTx/signTxPoolRegistration.c
    ${CARDANO_PATH}/src/signTx/signTxPoolRegistration_ui.c
    ${CARDANO_PATH}/src/signTx/signTx_ui.c
    ${CARDANO_PATH}/src/signTx/signTxUtils.c
    ${CARDANO_PATH}/src/tokens/tokens.c
    ${CARDANO_PATH}/src/txHashBuilder/txHashBuilder.c
    ${CARDANO_PATH}/src/ui/ui_callback.c
    ${CARDANO_PATH}/src/ui/uiHelpers.c
    ${CARDANO_PATH}/src/ui/bagl/menu_nanox.c
    ${CARDANO_PATH}/src/ui/bagl/uiHelpers_nanos.c
    ${CARDANO_PATH}/src/ui/bagl/uiHelpers_nanox.c
    ${CARDANO_PATH}/src/ui/bagl/uiScreens_bagl.c
    ${CARDANO_PATH}/src/ui/nbgl/ui_menu_nbgl.c
    ${CARDANO_PATH}/src/ui/nbgl/ui_nbgl.c
    ${CARDANO_PATH}/src/ui/nbgl/uiScreens_nbgl.c
    ${CARDANO_PATH}/src/utils/cbor.c
    ${CARDANO_PATH}/src/utils/hexUtils.c
    ${CARDANO_PATH}/src/utils/ipUtils.c
    ${CARDANO_PATH}/src/utils/textUtils.c
    ${CARDANO_PATH}/src/votecastHashBuilder/votecastHashBuilder.c
    ${CARDANO_PATH}/src/test/runTests.c
    ${CARDANO_PATH}/src/app_mode.c
    ${CARDANO_PATH}/src/assert.c
    ${CARDANO_PATH}/src/cardano.c
    ${CARDANO_PATH}/src/state.c
    ${BOLOS_SDK}/lib_standard_app/base58.c
    ${BOLOS_SDK}/lib_standard_app/read.c
    ${BOLOS_SDK}/lib_standard_app/write.c
)

include_directories(
    ${BOLOS_SDK}/include
    ${BOLOS_SDK}/target/nanox/include
    ${BOLOS_SDK}/lib_cxng/include
    ${BOLOS_SDK}/lib_bagl/include
    ${BOLOS_SDK}/lib_ux/include
    ${BOLOS_SDK}/lib_standard_app

    ${CARDANO_PATH}/src
    ${CARDANO_PATH}/src/addressUtils
    ${CARDANO_PATH}/src/auxDataHashBuilder
    ${CARDANO_PATH}/src/crypto
    ${CARDANO_PATH}/src/deriveAddress
    ${CARDANO_PATH}/src/deriveNativeScriptHash
    ${CARDANO_PATH}/src/getPublicKey
    ${CARDANO_PATH}/src/handlers
    ${CARDANO_PATH}/src/keyDerivation
    ${CARDANO_PATH}/src/messageSigning
    ${CARDANO_PATH}/src/nativeScriptHashBuilder
    ${CARDANO_PATH}/src/securityPolicy
    ${CARDANO_PATH}/src/signCVote
    ${CARDANO_PATH}/src/signMsg
    ${CARDANO_PATH}/src/signOpCert
    ${CARDANO_PATH}/src/signTx
    ${CARDANO_PATH}/src/tokens
    ${CARDANO_PATH}/src/txHashBuilder
    ${CARDANO_PATH}/src/votecastHashBuilder
    ${CARDANO_PATH}/src/ui
    ${CARDANO_PATH}/src/ui/bagl
    ${CARDANO_PATH}/src/ui/nbgl
    ${CARDANO_PATH}/src/utils
    ${CARDANO_PATH}/src/swap
    ${CARDANO_PATH}/src/test
    ./include
)

add_compile_definitions(
    FUZZING
    HAVE_BAGL
    BAGL_WIDTH=128
    BAGL_HEIGHT=64
    HAVE_UX_FLOW

    MAJOR_VERSION=1
    MINOR_VERSION=1
    PATCH_VERSION=1
    APPVERSION=\"1.1.1\"

    IO_HID_EP_LENGTH=64
    IO_SEPROXYHAL_BUFFER_SIZE_B=300
    OS_IO_SEPROXYHAL

    HAVE_ECC
    HAVE_CRC
    HAVE_BLAKE2
    HAVE_ECC_WEIERSTRASS
    HAVE_SECP256K1_CURVE
    HAVE_SECP256R1_CURVE
    HAVE_ECC_TWISTED_EDWARDS
    HAVE_ED25519_CURVE
    HAVE_ECDSA
    HAVE_EDDSA
    HAVE_HASH
    HAVE_SHA224
    HAVE_SHA256
    HAVE_SHA3

    # include all app features, incl. those removed from Nano S
    APP_FEATURE_OPCERT
    APP_FEATURE_NATIVE_SCRIPT_HASH
    APP_FEATURE_POOL_REGISTRATION
    APP_FEATURE_POOL_RETIREMENT
    APP_FEATURE_BYRON_ADDRESS_DERIVATION
    APP_FEATURE_BYRON_PROTOCOL_MAGIC_CHECK
    )

add_compile_options(
    -Wno-format -Wno-pointer-to-int-cast -Wno-constant-conversion -Wno-tautological-constant-out-of-range-compare
)

set(SOURCE
    ${UX_SOURCE}
    ${CARDANO_SOURCE}
    ./src/os_mocks.c
    ./src/glyphs.c
    ./src/crc32.c
)


add_library(cardano ${SOURCE})

set(harnesses
    all_harness
    deriveAddress_harness
    deriveNativeScriptHash_harness
    getPublicKeys_harness
    signCVote_harness
    signMsg_harness
    signOpCert_harness
    signTx_harness
)

foreach(harness IN LISTS harnesses)
    add_executable(${harness}
        ./src/${harness}.c
    )
    target_link_libraries(${harness} PUBLIC cardano)
endforeach()
