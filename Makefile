#*******************************************************************************
#   Ledger App
#   (c) 2017 Ledger
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

ifeq ($(BOLOS_SDK),)
$(error Environment variable BOLOS_SDK is not set)
endif
include $(BOLOS_SDK)/Makefile.defines

#########
#  App  #
#########

APPNAME  = Ardor
TARGET_NAME = TARGET_NANOS

DEVEL = 1 #Use when devolping #todo change this up in production

ifeq ($(TARGET_NAME),TARGET_NANOX)
	ICONNAME = ArdorIcon.gif
else
	ICONNAME = ArdorIcon.gif
endif

ifeq ($(TARGET_NAME),TARGET_NANOX)
	DEFINES += HAVE_BLE BLE_COMMAND_TIMEOUT_MS=2000 HAVE_BLE_APDU
endif


APPVERSION_M = 0
APPVERSION_N = 3
APPVERSION_P = 0
APPVERSION   = $(APPVERSION_M).$(APPVERSION_N).$(APPVERSION_P)

# The --path argument here restricts which BIP32 paths the app is allowed to derive.
APP_LOAD_PARAMS = --appFlags 0x40 --path "44'/29'" --curve ed25519 $(COMMON_LOAD_PARAMS)
APP_SOURCE_PATH = src
SDK_SOURCE_PATH = lib_stusb lib_stusb_impl lib_u2f

ifeq ($(TARGET_NAME),TARGET_NANOX)
	SDK_SOURCE_PATH  += lib_blewbxx lib_blewbxx_impl
	SDK_SOURCE_PATH  += lib_ux
endif

all: default

load: all
	python -m ledgerblue.loadApp $(APP_LOAD_PARAMS)

delete:
	python -m ledgerblue.deleteApp $(COMMON_DELETE_PARAMS)

############
# Platform #
############

ifeq ($(TARGET_NAME),TARGET_NANOX)
DEFINES += IO_SEPROXYHAL_BUFFER_SIZE_B=300
DEFINES += HAVE_GLO096
DEFINES += HAVE_BAGL BAGL_WIDTH=128 BAGL_HEIGHT=64
DEFINES += HAVE_BAGL_ELLIPSIS # long label truncation feature
DEFINES += HAVE_BAGL_FONT_OPEN_SANS_REGULAR_11PX
DEFINES += HAVE_BAGL_FONT_OPEN_SANS_EXTRABOLD_11PX
DEFINES += HAVE_BAGL_FONT_OPEN_SANS_LIGHT_16PX
DEFINES += HAVE_UX_FLOW
else
DEFINES += IO_SEPROXYHAL_BUFFER_SIZE_B=128 OS_IO_SEPROXYHAL

endif

DEFINES += HAVE_BAGL HAVE_SPRINTF
DEFINES += HAVE_IO_USB HAVE_L4_USBLIB IO_USB_MAX_ENDPOINTS=6 IO_HID_EP_LENGTH=64 HAVE_USB_APDU
DEFINES += LEDGER_MAJOR_VERSION=$(APPVERSION_M) LEDGER_MINOR_VERSION=$(APPVERSION_N) LEDGER_PATCH_VERSION=$(APPVERSION_P) TCS_LOADER_PATCH_VERSION=0
DEFINES += APPVERSION=\"$(APPVERSION)\"

# U2F
DEFINES   += HAVE_U2F HAVE_IO_U2F
DEFINES   += U2F_PROXY_MAGIC=\"ARD\"
DEFINES   += USB_SEGMENT_SIZE=64 
DEFINES   += BLE_SEGMENT_SIZE=32 #max MTU, min 20



# Enabling debug PRINTF
ifeq ($(DEVEL), 1)
	DEFINES += DEVEL HAVE_PRINTF
	ifeq ($(TARGET_NAME),TARGET_NANOX)
		DEFINES += PRINTF=mcu_usb_printf
	else
		DEFINES += PRINTF=screen_printf
	endif
else
    DEFINES += PRINTF\(...\)=
endif

WEBUSB_URL = https://www.ledger.com/pages/supported-crypto-assets
DEFINES += HAVE_WEBUSB WEBUSB_URL_SIZE_B=$(shell echo -n $(WEBUSB_URL) | wc -c) WEBUSB_URL=$(shell echo -n $(WEBUSB_URL) | sed -e "s/./\\\'\0\\\',/g")

DEFINES += BLAKE_SDK

##############
#  Compiler  #
##############

CC := $(CLANGPATH)clang
CFLAGS += -O3 -Os

AS := $(GCCPATH)arm-none-eabi-gcc
LD := $(GCCPATH)arm-none-eabi-gcc
LDFLAGS += -O3 -Os
LDLIBS += -lm -lgcc -lc

##################
#  Dependencies  #
##################

# import rules to compile glyphs
include $(BOLOS_SDK)/Makefile.glyphs
# import generic rules from the sdk
include $(BOLOS_SDK)/Makefile.rules

dep/%.d: %.c Makefile

listvariants:
	@echo VARIANTS COIN sia