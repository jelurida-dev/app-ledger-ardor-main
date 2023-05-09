#*******************************************************************************
#   Ledger App
#   (c) 2017 Ledger
#   (c) 2019 Haim Bender
#   (c) 2021-2023 Jelurida IP B.V.
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

# Enabling DEBUG flag will enable PRINTF and disable optimizations
DEBUG ?= 0

ifeq ($(BOLOS_SDK),)
    $(error Environment variable BOLOS_SDK is not set)
endif

include $(BOLOS_SDK)/Makefile.defines

APPNAME = Ardor
APPVERSION_M = 1
APPVERSION_N = 0
APPVERSION_P = 3
DEFINES += APPVERSION_M=$(APPVERSION_M)
DEFINES += APPVERSION_N=$(APPVERSION_N)
DEFINES += APPVERSION_P=$(APPVERSION_P)
APPVERSION = $(APPVERSION_M).$(APPVERSION_N).$(APPVERSION_P)

VARIANT_PARAM = COIN
VARIANT_VALUES = ardor  

DEFINES += "PATH_PREFIX={44|0x80000000,16754|0x80000000}"
PATH_PREFIX = "44'/16754'"
DEFINES += APP_PREFIX=\"ARDOR-\"

ifeq ($(TARGET_NAME),TARGET_NANOS)
    ICONNAME = icons/ArdorIconNanoS.gif
else ifeq ($(TARGET_NAME),TARGET_STAX)
    ICONNAME = icons/ArdorIcon32px.gif
else
    ICONNAME = icons/ArdorIconNanoX.gif
endif

APP_LOAD_PARAMS += --curve ed25519
APP_LOAD_PARAMS += --path $(PATH_PREFIX)

# Ledger: add the "Pending security review" disclaimer
APP_LOAD_PARAMS += --tlvraw 9F:01
DEFINES += HAVE_PENDING_REVIEW_SCREEN

ENABLE_BLUETOOTH = 1

APP_SOURCE_PATH += src

AUTOGEN_SRC := src/txnTypeLists.c
AUTOGEN_OBJ := $(AUTOGEN_SRC:src/%.c=obj/%.o)

SOURCE_FILES += $(AUTOGEN_SRC)

.PHONY: realclean

$(AUTOGEN_OBJ): $(AUTOGEN_SRC)

$(AUTOGEN_SRC): createTxnTypes.py txtypes.txt
	python ./createTxnTypes.py > $@

realclean: clean
	rm -f $(AUTOGEN_SRC)

include $(BOLOS_SDK)/Makefile.standard_app
