#*******************************************************************************
#   Ledger App
#   (c) 2017 Ledger
#   (c) 2019 Haim Bender
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

#Defines

APPNAME = Ardor#Here you need switch between Ardor and NXT (Mind the letter casing, it matters)
DEVEL = 0#This means we are in DEBUG mode, change this up when releasing in production

#####################################3

ifeq ($(BOLOS_SDK),)
	$(error Environment variable BOLOS_SDK is not set)
endif

include $(BOLOS_SDK)/Makefile.defines

ifeq ($(APPNAME),Ardor)
	DEFINES = "PATH_PREFIX={44|0x80000000,16754|0x80000000}"
	PATH_PREFIX = "44'/16754'"
	DEFINES += APP_PREFIX=\"ARDOR-\"

	ifeq ($(TARGET_NAME),TARGET_NANOX)
		ICONNAME = ArdorIconNanoX.gif
	else
		ICONNAME = ArdorIconNanoS.gif
	endif
else
	echo $(APPNAME)
	DEFINES = "PATH_PREFIX={44|0x80000000,29|0x80000000}"
	PATH_PREFIX = "44'/29'"
	DEFINES += APP_PREFIX=\"NXT-\"

	ifeq ($(TARGET_NAME),TARGET_NANOX)
		ICONNAME = NXTIconNanoX.gif
	else
		ICONNAME = NXTIconNanoS.gif
	endif
endif

############
# Platform #
############

#This inits the SDK_SOURCE_PATH variable, moving this will screw up the build, because the next if does +=
SDK_SOURCE_PATH = lib_stusb lib_stusb_impl lib_u2f lib_ux
APP_LOAD_PARAMS = --curve ed25519 $(COMMON_LOAD_PARAMS) 

# Ledger: add the "Pending security review" disclaimer
APP_LOAD_PARAMS += --tlvraw 9F:01

ifeq ($(TARGET_NAME),TARGET_NANOX)
	SDK_SOURCE_PATH += lib_blewbxx lib_blewbxx_impl
	
	# The --appFlags param gives permision to open bluetooth
	APP_LOAD_PARAMS += --appFlags 0x0200

	DEFINES += HAVE_BLE BLE_COMMAND_TIMEOUT_MS=2000
	DEFINES += IO_SEPROXYHAL_BUFFER_SIZE_B=300
	DEFINES += HAVE_BLE BLE_COMMAND_TIMEOUT_MS=2000
	DEFINES += HAVE_BLE_APDU # basic ledger apdu transport over BLE

	DEFINES += HAVE_GLO096
	DEFINES += BAGL_WIDTH=128 BAGL_HEIGHT=64
	DEFINES += HAVE_BAGL_ELLIPSIS # long label truncation feature
	DEFINES += HAVE_BAGL_FONT_OPEN_SANS_REGULAR_11PX
	DEFINES += HAVE_BAGL_FONT_OPEN_SANS_EXTRABOLD_11PX
	DEFINES += HAVE_BAGL_FONT_OPEN_SANS_LIGHT_16PX
else
	# Since we don't have bluetooth in NanoS we set --appFlags to 0
	APP_LOAD_PARAMS += --appFlags 0x0000

	DEFINES += IO_SEPROXYHAL_BUFFER_SIZE_B=128
endif

DEFINES += HAVE_UX_FLOW

APPVERSION_M = 1
APPVERSION_N = 0
APPVERSION_P = 1

DEFINES += APPVERSION_M=$(APPVERSION_M)
DEFINES += APPVERSION_N=$(APPVERSION_N)
DEFINES += APPVERSION_P=$(APPVERSION_P)
APPVERSION   = $(APPVERSION_M).$(APPVERSION_N).$(APPVERSION_P)



# The --path argument here restricts which BIP32 paths the app is allowed to derive.
APP_LOAD_PARAMS += --path $(PATH_PREFIX)
APP_SOURCE_PATH = src

DEFINES += HAVE_BAGL HAVE_SPRINTF HAVE_BOLOS_APP_STACK_CANARY OS_IO_SEPROXYHAL
DEFINES += HAVE_IO_USB HAVE_L4_USBLIB IO_USB_MAX_ENDPOINTS=6 IO_HID_EP_LENGTH=64 HAVE_USB_APDU
DEFINES += LEDGER_MAJOR_VERSION=$(APPVERSION_M) LEDGER_MINOR_VERSION=$(APPVERSION_N) LEDGER_PATCH_VERSION=$(APPVERSION_P) TCS_LOADER_PATCH_VERSION=0
DEFINES += APPVERSION=\"$(APPVERSION)\"

# U2F
DEFINES   += HAVE_U2F HAVE_IO_U2F
DEFINES   += U2F_PROXY_MAGIC=\"ARD\"
DEFINES   += USB_SEGMENT_SIZE=64
DEFINES   += BLE_SEGMENT_SIZE=32 #max MTU, min 20


WEBUSB_URL = https://www.ledger.com/pages/supported-crypto-assets #todo swap this to some jelurida web site
DEFINES += HAVE_WEBUSB WEBUSB_URL_SIZE_B=$(shell echo -n $(WEBUSB_URL) | wc -c) WEBUSB_URL=$(shell echo -n $(WEBUSB_URL) | sed -e "s/./\\\'\0\\\',/g")

DEFINES += BLAKE_SDK

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


all: default

src/authAndSignTxn.o: src/authAndSignTxn.c src/txnTypeLists.c

src/txnTypeLists.c:
	python ./createTxnTypes.py > $@

load: all
	python -m ledgerblue.loadApp $(APP_LOAD_PARAMS)

delete:
	python -m ledgerblue.deleteApp $(COMMON_DELETE_PARAMS)


##############
#  Compiler  #
##############

CC := $(CLANGPATH)clang
CFLAGS += -O3 -Os

AS := $(GCCPATH)arm-none-eabi-gcc
LD := $(GCCPATH)arm-none-eabi-gcc
LDFLAGS += -O3 -Os
LDLIBS += -lm -lgcc -lc

SOURCE_FILES += src/txnTypeLists.c

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