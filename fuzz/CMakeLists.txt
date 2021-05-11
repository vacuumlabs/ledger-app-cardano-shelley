cmake_minimum_required(VERSION 3.10)

project(cardano_fuzzer C)

set(CMAKE_C_STANDARD 99)

set(SDK_PATH ../../../../z/nanos-secure-sdk)

include_directories(. ../src)
include_directories(
	${SDK_PATH}/include/
	${SDK_PATH}/lib_cxng/include/
	${SDK_PATH}/lib_cxng/src/
	${SDK_PATH}/lib_ux/include/
	)

add_compile_options(-g -ggdb2 -O3)
add_compile_options(-fsanitize=fuzzer,address)
add_link_options(-fsanitize=fuzzer,address)

add_compile_definitions(
		__GNUC__
		FUZZING
        OS_IO_SEPROXYHAL
        IO_SEPROXYHAL_BUFFER_SIZE_B=300
        IO_HID_EP_LENGTH=64
        HAVE_UX_FLOW
        APPVERSION="0.0.0"
)

add_compile_definitions(
    HAVE_ECC
    HAVE_ECC_WEIERSTRASS
    HAVE_SECP256K1_CURVE
    HAVE_SECP256R1_CURVE
    HAVE_ECC_TWISTED_EDWARDS
    HAVE_ED25519_CURVE
    HAVE_ECDSA
    HAVE_EDDSA
    HAVE_HASH
    HAVE_SHA256
    HAVE_SHA3
    HAVE_BLAKE2
)
# add_definitions(-DFUZZING -DHEADLESS -DAPPVERSION="0.0.0" -DHAVE_UX_FLOW)

set(SOURCES
        fuzztest.c
		../src/addressUtilsByron.c
		../src/addressUtilsShelley.c
		../src/assert.c
		../src/auxDataHashBuilder.c
		../src/base58.c
		../src/bech32.c
		../src/bip44.c
		../src/cbor.c
		../src/crc32.c
		../src/io.c
		../src/keyDerivation.c
		../src/hexUtils.c
		../src/messageSigning.c
		../src/securityPolicy.c
		../src/signTx.c
		../src/signTxOutput.c
		../src/state.c
		../src/signTxPoolRegistration.c
		../src/signTxCatalystRegistration.c
		../src/signTxUtils.c
		../src/textUtils.c
		../src/txHashBuilder.c
		../src/uiHelpers.c
		../src/uiHelpers_nanos.c
		../src/uiScreens.c
		)

add_executable(fuzzer ${SOURCES})
add_executable(fuzzer_coverage ${SOURCES})

target_compile_options(fuzzer PRIVATE)
target_compile_options(fuzzer_coverage PRIVATE -fprofile-instr-generate -fcoverage-mapping)

target_link_options(fuzzer PRIVATE)
target_link_options(fuzzer_coverage PRIVATE)