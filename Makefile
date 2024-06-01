#*******************************************************************************
#   Ledger Nano S
#   (c) 2016 Ledger
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#*******************************************************************************

# based on https://github.com/LedgerHQ/app-boilerplate/blob/master/Makefile

ifeq ($(BOLOS_SDK),)
$(error Environment variable BOLOS_SDK is not set)
endif

include $(BOLOS_SDK)/Makefile.defines

########################################
#        Mandatory configuration       #
########################################
# Application name
APPNAME = "Cardano ADA"

# Application version
APPVERSION_M = 6
APPVERSION_N = 1
APPVERSION_P = 2
APPVERSION = "$(APPVERSION_M).$(APPVERSION_N).$(APPVERSION_P)"

# Application source files
APP_SOURCE_PATH += src

# Application icons following guidelines:
# https://developers.ledger.com/docs/embedded-app/design-requirements/#device-icon
ICON_NANOS = icons/app_ada_16px.gif
ICON_NANOX = icons/app_ada_14px.gif
ICON_NANOSP = icons/app_ada_14px.gif
ICON_STAX = icons/app_ada_32px.gif

# Application allowed derivation curves.
# Possibles curves are: secp256k1, secp256r1, ed25519 and bls12381g1
# If your app needs it, you can specify multiple curves by using:
# `CURVE_APP_LOAD_PARAMS = <curve1> <curve2>`
CURVE_APP_LOAD_PARAMS = ed25519

# Application allowed derivation paths.
# You should request a specific path for your app.
# This serve as an isolation mechanism.
# Most application will have to request a path according to the BIP-0044
# and SLIP-0044 standards.
# If your app needs it, you can specify multiple path by using:
# `PATH_APP_LOAD_PARAMS = "44'/1'" "45'/1'"`
PATH_APP_LOAD_PARAMS = "44'/1815'" "1852'/1815'" "1853'/1815'" "1854'/1815'" "1855'/1815'" "1694'/1815'"

# Setting to allow building variant applications
# - <VARIANT_PARAM> is the name of the parameter which should be set
#   to specify the variant that should be build.
# - <VARIANT_VALUES> a list of variant that can be build using this app code.
#   * It must at least contains one value.
#   * Values can be the app ticker or anything else but should be unique.
VARIANT_PARAM = COIN
VARIANT_VALUES = cardano_ada

# Use developer build for testing (e.g. on Speculos)
#DEVEL = 1

ifeq ($(DEVEL), 1)
	DEFINES += DEVEL
	# Automatically confirm all prompts to avoid manually clicking through UI
	DEFINES += HEADLESS
	# Enabling DEBUG flag will enable PRINTF and disable optimizations
	DEBUG = 1
else
	DEFINES += RESET_ON_CRASH
endif

# restricted features for Nano S
# but not in DEVEL mode where we usually want to test all features with HEADLESS
ifeq ($(TARGET_NAME), TARGET_NANOS)
	ifneq ($(DEVEL), 1)
		APP_XS = 1
	else
		APP_XS = 0
	endif
else
	APP_XS = 0
endif

ifeq ($(APP_XS), 1)
	DEFINES += APP_XS
else
	# features not included in the Nano S app
	DEFINES += APP_FEATURE_OPCERT
	DEFINES += APP_FEATURE_NATIVE_SCRIPT_HASH
	DEFINES += APP_FEATURE_POOL_REGISTRATION
	DEFINES += APP_FEATURE_POOL_RETIREMENT
	DEFINES += APP_FEATURE_BYRON_ADDRESS_DERIVATION
	DEFINES += APP_FEATURE_BYRON_PROTOCOL_MAGIC_CHECK
endif
# always include this, it's important for Plutus users
DEFINES += APP_FEATURE_TOKEN_MINTING

########################################
#     Application custom permissions   #
########################################
# See SDK `include/appflags.h` for the purpose of each permission
#HAVE_APPLICATION_FLAG_DERIVE_MASTER = 1
#HAVE_APPLICATION_FLAG_GLOBAL_PIN = 1
HAVE_APPLICATION_FLAG_BOLOS_SETTINGS = 1
#HAVE_APPLICATION_FLAG_LIBRARY = 1

########################################
# Application communication interfaces #
########################################
ENABLE_BLUETOOTH = 1
#ENABLE_NFC = 1

########################################
#         NBGL custom features         #
########################################
ENABLE_NBGL_QRCODE = 1
#ENABLE_NBGL_KEYBOARD = 1
#ENABLE_NBGL_KEYPAD = 1

########################################
#          Features disablers          #
########################################
# These advanced settings allow to disable some feature that are by
# default enabled in the SDK `Makefile.standard_app`.
#DISABLE_STANDARD_APP_FILES = 1
#DISABLE_DEFAULT_IO_SEPROXY_BUFFER_SIZE = 1 # To allow custom size declaration
#DISABLE_STANDARD_APP_DEFINES = 1 # Will set all the following disablers
#DISABLE_STANDARD_SNPRINTF = 1
#DISABLE_STANDARD_USB = 1
#DISABLE_STANDARD_WEBUSB = 1

ifeq ($(TARGET_NAME), TARGET_NANOS)
    DISABLE_STANDARD_BAGL_UX_FLOW = 1
endif

########################################
#       Additional configuration       #
########################################

# USB U2F
DEFINES += HAVE_U2F HAVE_IO_U2F U2F_PROXY_MAGIC=\"ADA\"
SDK_SOURCE_PATH  += lib_u2f

# Protect against stack overflows
DEFINES += HAVE_BOLOS_APP_STACK_CANARY

# mnemonic and PIN for testing on a physical device / Speculos
WORDS = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
PIN = 5555

# based in part on https://interrupt.memfault.com/blog/best-and-worst-gcc-clang-compiler-flags
CFLAGS   += -Wuninitialized -Wreturn-type -Wparentheses -fno-common

########################################
#          Additional targets          #
########################################

# code style
format:
	astyle --options=.astylerc "src/*.h" "src/*.c"

# prints app size, max is about 140K
size: all
	$(GCCPATH)arm-none-eabi-size --format=gnu bin/app.elf

# device-specific builds
nanos: clean
	BOLOS_SDK=$(NANOS_SDK) make

nanosp: clean
	BOLOS_SDK=$(NANOSP_SDK) make

nanox: clean
	BOLOS_SDK=$(NANOX_SDK) make

stax: clean
	BOLOS_SDK=$(STAX_SDK) make

# part of CI
analyze: clean
	scan-build --use-cc=clang -analyze-headers -enable-checker security -enable-checker unix -enable-checker valist -o scan-build --status-bugs make default


include $(BOLOS_SDK)/Makefile.standard_app
