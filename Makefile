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

APPNAME      = "Cardano ADA"
APPVERSION_M = 6
APPVERSION_N = 0
APPVERSION_P = 1
APPVERSION   = "$(APPVERSION_M).$(APPVERSION_N).$(APPVERSION_P)"

ifeq ($(BOLOS_SDK),)
$(error Environment variable BOLOS_SDK is not set)
endif

include $(BOLOS_SDK)/Makefile.defines

ifeq ($(TARGET_NAME),TARGET_NANOS)
	ICONNAME=icon_ada_nanos.gif
else
	ICONNAME=icon_ada_nanox.gif
endif

##############
#  Compiler  #
##############

# based in part on https://interrupt.memfault.com/blog/best-and-worst-gcc-clang-compiler-flags
WERROR   := -Werror=incompatible-pointer-types -Werror=return-type -Werror=parentheses -Werror=format-security

CC       := $(CLANGPATH)clang
CFLAGS   += -std=gnu99 -Wall -Wextra -Wuninitialized -Wshadow -Wformat=2 -Wwrite-strings -Wundef -fno-common $(WERROR)

AS       := $(GCCPATH)arm-none-eabi-gcc
LD       := $(GCCPATH)arm-none-eabi-gcc
LDFLAGS  += -Wall
LDLIBS   += -lm -lgcc -lc


############
# Platform #
############

DEFINES += OS_IO_SEPROXYHAL
DEFINES += HAVE_BAGL HAVE_SPRINTF HAVE_SNPRINTF_FORMAT_U
DEFINES += APPVERSION=\"$(APPVERSION)\"
DEFINES += MAJOR_VERSION=$(APPVERSION_M) MINOR_VERSION=$(APPVERSION_N) PATCH_VERSION=$(APPVERSION_P)

## USB HID?
DEFINES += HAVE_IO_USB HAVE_L4_USBLIB IO_USB_MAX_ENDPOINTS=4 IO_HID_EP_LENGTH=64 HAVE_USB_APDU

## USB U2F
DEFINES += HAVE_U2F HAVE_IO_U2F U2F_PROXY_MAGIC=\"ADA\" USB_SEGMENT_SIZE=64

## WEBUSB
#WEBUSB_URL = https://www.ledger.com/pages/supported-crypto-assets
#DEFINES += HAVE_WEBUSB WEBUSB_URL_SIZE_B=$(shell echo -n $(WEBUSB_URL) | wc -c) WEBUSB_URL=$(shell echo -n $(WEBUSB_URL) | sed -e "s/./\\\'\0\\\',/g")
DEFINES   += HAVE_WEBUSB WEBUSB_URL_SIZE_B=0 WEBUSB_URL=""

## BLUETOOTH
ifeq ($(TARGET_NAME),TARGET_NANOX)
	DEFINES += HAVE_BLE BLE_COMMAND_TIMEOUT_MS=2000 HAVE_BLE_APDU
endif

## Protect stack overflows
DEFINES += HAVE_BOLOS_APP_STACK_CANARY

ifeq ($(TARGET_NAME),TARGET_NANOS)
DEFINES += IO_SEPROXYHAL_BUFFER_SIZE_B=128
DEFINES += HAVE_BOLOS_UX HAVE_UX_LEGACY COMPLIANCE_UX_160
else
DEFINES += IO_SEPROXYHAL_BUFFER_SIZE_B=300
DEFINES += HAVE_GLO096
DEFINES += HAVE_BAGL BAGL_WIDTH=128 BAGL_HEIGHT=64
DEFINES += HAVE_BAGL_ELLIPSIS # long label truncation feature
DEFINES += HAVE_BAGL_FONT_OPEN_SANS_REGULAR_11PX
DEFINES += HAVE_BAGL_FONT_OPEN_SANS_EXTRABOLD_11PX
DEFINES += HAVE_BAGL_FONT_OPEN_SANS_LIGHT_16PX
DEFINES += HAVE_UX_FLOW
endif

DEFINES += RESET_ON_CRASH

## Use developer build
#DEVEL = 1
#DEFINES += HEADLESS

# Enabling debug PRINTF
ifeq ($(DEVEL), 1)
	DEFINES += DEVEL HAVE_PRINTF
	ifeq ($(TARGET_NAME),TARGET_NANOS)
		DEFINES += PRINTF=screen_printf
	else
		DEFINES += PRINTF=mcu_usb_printf
	endif
else
	DEFINES += PRINTF\(...\)=
endif


##################
#  Dependencies  #
##################

# import rules to compile glyphs
include $(BOLOS_SDK)/Makefile.glyphs

### computed variables
APP_SOURCE_PATH  += src
SDK_SOURCE_PATH  += lib_stusb lib_stusb_impl lib_u2f
SDK_SOURCE_PATH  += lib_ux
ifeq ($(TARGET_NAME),TARGET_NANOX)
	SDK_SOURCE_PATH  += lib_blewbxx lib_blewbxx_impl
endif


################
# Default rule #
################

all: default


##############
#   Build    #
##############

# import generic rules from the sdk
include $(BOLOS_SDK)/Makefile.rules

#add dependency on custom makefile filename
dep/%.d: %.c Makefile

listvariants:
	@echo VARIANTS COIN cardano_ada

# part of CI
analyze: clean
	scan-build --use-cc=clang -analyze-headers -enable-checker security -enable-checker unix -enable-checker valist -o scan-build --status-bugs make default

##############
#   Load     #
##############

NANOS_ID = 1
WORDS = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
PIN = 5555

APP_LOAD_PARAMS =--appFlags 0x240 --curve ed25519 --path "44'/1815'" --path "1852'/1815'" --path "1853'/1815'" --path "1854'/1815'" --path "1855'/1815'" --path "1694'/1815'"
APP_LOAD_PARAMS += $(COMMON_LOAD_PARAMS)

load: all
	python -m ledgerblue.loadApp $(APP_LOAD_PARAMS)

delete:
	python -m ledgerblue.deleteApp $(COMMON_DELETE_PARAMS)

seed:
	python -m ledgerblue.hostOnboard --id $(NANOS_ID) --words $(WORDS) --pin $(PIN)


##############
#   Style    #
##############

format:
	astyle --options=.astylerc "src/*.h" "src/*.c" --exclude=src/glyphs.h --exclude=src/glyphs.c


##############
#    Size    #
##############

# prints app size, max is about 140K

size: all
	$(GCCPATH)arm-none-eabi-size --format=gnu bin/app.elf
