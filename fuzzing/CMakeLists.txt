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
    ${CARDANO_PATH}/src/addressUtilsByron.c
    ${CARDANO_PATH}/src/addressUtilsShelley.c
    ${CARDANO_PATH}/src/app_mode.c
    ${CARDANO_PATH}/src/assert.c
    ${CARDANO_PATH}/src/auxDataHashBuilder.c
    ${CARDANO_PATH}/src/base58.c
    ${CARDANO_PATH}/src/bech32.c
    ${CARDANO_PATH}/src/bip44.c
    ${CARDANO_PATH}/src/cardano.c
    ${CARDANO_PATH}/src/cbor.c
    ${CARDANO_PATH}/src/crc32.c
    ${CARDANO_PATH}/src/crypto.c
    ${CARDANO_PATH}/src/deriveAddress.c
    ${CARDANO_PATH}/src/deriveNativeScriptHash.c
    ${CARDANO_PATH}/src/deriveNativeScriptHash_ui.c
    ${CARDANO_PATH}/src/getPublicKeys.c
    ${CARDANO_PATH}/src/getPublicKeys_ui.c
    ${CARDANO_PATH}/src/getSerial.c
    ${CARDANO_PATH}/src/getVersion.c
    ${CARDANO_PATH}/src/handlers.c
    ${CARDANO_PATH}/src/hexUtils.c
    ${CARDANO_PATH}/src/io.c
    ${CARDANO_PATH}/src/ipUtils.c
    ${CARDANO_PATH}/src/keyDerivation.c
    # ${CARDANO_PATH}/src/menu_nanos.c
    ${CARDANO_PATH}/src/menu_nanox.c
    ${CARDANO_PATH}/src/messageSigning.c
    ${CARDANO_PATH}/src/nativeScriptHashBuilder.c
    ${CARDANO_PATH}/src/runTests.c
    ${CARDANO_PATH}/src/securityPolicy.c
    ${CARDANO_PATH}/src/signCVote.c
    ${CARDANO_PATH}/src/signCVote_ui.c
    ${CARDANO_PATH}/src/signMsg.c
    ${CARDANO_PATH}/src/signMsg_ui.c
    ${CARDANO_PATH}/src/signOpCert.c
    ${CARDANO_PATH}/src/signTx.c
    ${CARDANO_PATH}/src/signTxCVoteRegistration.c
    ${CARDANO_PATH}/src/signTxCVoteRegistration_ui.c
    ${CARDANO_PATH}/src/signTxMint.c
    ${CARDANO_PATH}/src/signTxMint_ui.c
    ${CARDANO_PATH}/src/signTxOutput.c
    ${CARDANO_PATH}/src/signTxOutput_ui.c
    ${CARDANO_PATH}/src/signTxPoolRegistration.c
    ${CARDANO_PATH}/src/signTxPoolRegistration_ui.c
    ${CARDANO_PATH}/src/signTx_ui.c
    ${CARDANO_PATH}/src/signTxUtils.c
    ${CARDANO_PATH}/src/state.c
    ${CARDANO_PATH}/src/textUtils.c
    ${CARDANO_PATH}/src/tokens.c
    ${CARDANO_PATH}/src/txHashBuilder.c
    ${CARDANO_PATH}/src/uiHelpers.c
    ${CARDANO_PATH}/src/uiHelpers_nanos.c
    ${CARDANO_PATH}/src/uiHelpers_nanox.c
    ${CARDANO_PATH}/src/ui_menu_nbgl.c
    ${CARDANO_PATH}/src/ui_nbgl.c
    ${CARDANO_PATH}/src/uiScreens_bagl.c
    ${CARDANO_PATH}/src/uiScreens_nbgl.c
    ${CARDANO_PATH}/src/votecastHashBuilder.c
)

include_directories(
    ${BOLOS_SDK}/include
    ${BOLOS_SDK}/target/nanox/include
    ${BOLOS_SDK}/lib_cxng/include
    ${BOLOS_SDK}/lib_bagl/include
    ${BOLOS_SDK}/lib_ux/include

    ${CARDANO_PATH}/src
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

set(SOURCE
    ${UX_SOURCE}
    ${CARDANO_SOURCE}
    ./src/os_mocks.c
    ./src/glyphs.c
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
