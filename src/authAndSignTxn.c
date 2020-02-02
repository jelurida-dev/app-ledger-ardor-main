/*******************************************************************************
*  (c) 2019 Haim Bender
*
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/


#include <string.h>
#include <stdbool.h>

#include <os_io_seproxyhal.h>

#include "ux.h"

#include "returnValues.h"
#include "ardor.h"

static unsigned int ui_auth_button(unsigned int button_mask, unsigned int button_mask_counter);

static unsigned int ui_firstScreen_button(unsigned int button_mask, unsigned int button_mask_counter) {
    return ui_auth_button(button_mask, button_mask_counter);
}

static unsigned int ui_centerScreen_button(unsigned int button_mask, unsigned int button_mask_counter) {
    return ui_auth_button(button_mask, button_mask_counter);
} 

static unsigned int ui_finalScreen_button(unsigned int button_mask, unsigned int button_mask_counter) {
    return ui_auth_button(button_mask, button_mask_counter);
} 

static const bagl_element_t ui_firstScreen[] = {
        UI_BACKGROUND(),
        {{BAGL_ICON,0x00,3,12,7,7,0,0,0,0xFFFFFF,0,0,BAGL_GLYPH_ICON_CROSS},NULL,0,0,0,NULL,NULL,NULL},
        {{BAGL_ICON,0x00,117,13,8,6,0,0,0,0xFFFFFF,0,0,BAGL_GLYPH_ICON_RIGHT},NULL,0,0,0,NULL,NULL,NULL},        
        UI_TEXT(0x00, 0, 12, 128, state.txnAuth.displayTitle),
        {{BAGL_LABELINE,0x01,15,26,98,12,10,0,0,0xFFFFFF,0,BAGL_FONT_OPEN_SANS_EXTRABOLD_11px|BAGL_FONT_ALIGNMENT_CENTER,26},(char*)state.txnAuth.displaystate,0,0,0,NULL,NULL,NULL}
};

static const bagl_element_t ui_centerScreen[] = {
        UI_BACKGROUND(),
        {{BAGL_ICON,0x00,3,12,7,7,0,0,0,0xFFFFFF,0,0,BAGL_GLYPH_ICON_LEFT},NULL,0,0,0,NULL,NULL,NULL},
        {{BAGL_ICON,0x00,117,13,8,6,0,0,0,0xFFFFFF,0,0,BAGL_GLYPH_ICON_RIGHT},NULL,0,0,0,NULL,NULL,NULL},
        UI_TEXT(0x00, 0, 12, 128, state.txnAuth.displayTitle),
        {{BAGL_LABELINE,0x01,15,26,98,12,10,0,0,0xFFFFFF,0,BAGL_FONT_OPEN_SANS_EXTRABOLD_11px|BAGL_FONT_ALIGNMENT_CENTER,26},(char*)state.txnAuth.displaystate,0,0,0,NULL,NULL,NULL}
};

static const bagl_element_t ui_finalScreen[] = {
        UI_BACKGROUND(),
        {{BAGL_ICON,0x00,3,12,7,7,0,0,0,0xFFFFFF,0,0,BAGL_GLYPH_ICON_LEFT},NULL,0,0,0,NULL,NULL,NULL},
        {{BAGL_ICON,0x00,117,13,8,6,0,0,0,0xFFFFFF,0,0,BAGL_GLYPH_ICON_CHECK},NULL,0,0,0,NULL,NULL,NULL},
        UI_TEXT(0x00, 0, 12, 128, state.txnAuth.displayTitle),
        {{BAGL_LABELINE,0x01,15,26,98,12,10,0,0,0xFFFFFF,0,BAGL_FONT_OPEN_SANS_EXTRABOLD_11px|BAGL_FONT_ALIGNMENT_CENTER,26},(char*)state.txnAuth.displaystate,0,0,0,NULL,NULL,NULL}
};

unsigned int makeTextGoAround_preprocessor(const bagl_element_t * const element);

void cleanState() {

    state.txnAuth.txnSizeBytes = 0;
    state.txnAuth.numBytesRead = 0;

    os_memset(state.txnAuth.functionStack, 0, sizeof(state.txnAuth.functionStack));
    state.txnAuth.functionStack[0] = 1; //Add the first parse function on the stack
    state.txnAuth.functionStack[1] = 2; //The appendages parse function
    state.txnAuth.numFunctionsOnStack = 2;

    state.txnAuth.txnPassedAutherization = false;
    state.txnAuth.isClean = true;
    
    os_memset(state.txnAuth.finalHash, 0, sizeof(state.txnAuth.finalHash));
    cx_sha256_init(&state.txnAuth.hashstate);

    //todo: add all constructors for new members here

    os_memset(state.txnAuth.readBuffer, 0, sizeof(state.txnAuth.readBuffer));
    state.txnAuth.readBufferReadOffset = 0;
    state.txnAuth.readBufferEndPos = 0;


    os_memset(state.txnAuth.tempBuffer, 0, sizeof(state.txnAuth.tempBuffer));


    os_memset(state.txnAuth.displayTitle, 0, sizeof(state.txnAuth.displayTitle));
    os_memset(state.txnAuth.displaystate, 0, sizeof(state.txnAuth.displaystate));


    state.txnAuth.chainId = 0;
    state.txnAuth.transactionTypeAndSubType = 0;
    state.txnAuth.txnTypeIndex = 0;
    state.txnAuth.version = 0;
    state.txnAuth.recipientId = 0;
    state.txnAuth.amount = 0;
    state.txnAuth.fee = 0;
    state.txnAuth.appendagesFlags = 0;
    state.txnAuth.displayType = 0;

    state.txnAuth.screenNum = 0;

    state.txnAuth.attachmentTempInt32Num1 = 0;
    state.txnAuth.attachmentTempInt32Num2 = 0;
    state.txnAuth.attachmentTempInt64Num1 = 0;
    state.txnAuth.attachmentTempInt64Num2 = 0;
    state.txnAuth.attachmentTempInt64Num3 = 0;
}


void showScreen() {
    switch (state.txnAuth.displayType) {
        case 0:
            UX_DISPLAY(ui_firstScreen, NULL)
            return;
        case 1:
            UX_DISPLAY(ui_centerScreen, (bagl_element_callback_t)makeTextGoAround_preprocessor)
            return;
        case 2:
            UX_DISPLAY(ui_finalScreen, (bagl_element_callback_t)makeTextGoAround_preprocessor)
            return;
    }
}

typedef struct {
    uint32_t chainId;
    char * name;
    uint8_t numDecimalsBeforePoint;
} chainType;


//todo move it somewhere else
static const chainType CHAINS[] = {{0x00000001, "Ardor", 8}, {0x00000002, "Ignis", 8}, {0x00000003, "AEUR", 4}, {0x00000004, "BITS", 8}, {0x00000005, "MPG", 8}};


txnType * txnTypeAtIndex(const uint8_t index) {
    return (txnType*)PIC(&TXN_TYPES[index]);
}

//todo write a note here why not returning the class because of PIC, rename to txnTypeName
char * txnNameAtIndex(const uint8_t index) {
    return (char*)PIC(((txnType*)PIC(&TXN_TYPES[index]))->name);
}

//uint8_t txnNumScreensAtIndex(uint8_t index) {
//    return ((txnType*)PIC(&TXN_TYPES[index]))->numScreens;
//}

char * chainName(const uint8_t chainId) {
    return (char*)PIC(((chainType*)PIC(&CHAINS[chainId - 1]))->name);
}

uint8_t chainNumDecimalsBeforePoint(const uint8_t chainId) {
    return ((chainType*)PIC(&CHAINS[chainId - 1]))->numDecimalsBeforePoint;
}

//numberToFormat isn't const cuz we play with it in order to format the number
//returns 0 iff some kind of error happend, else the length of the output string including the null terminator
uint8_t formatAmount(uint8_t * const outputString, const uint16_t maxOutputLength, uint64_t numberToFormat, const uint8_t numDigitsBeforeDecimal) {
    
    uint16_t outputIndex = 0;
    bool wasANumberWritten = false;
    bool isDotWritten = false;
    uint8_t numberIndex = 0;


    while (42) {

        uint8_t modulo = numberToFormat % 10;
        numberToFormat -= modulo;
        numberToFormat /= 10;

        if (numDigitsBeforeDecimal == numberIndex) {
            if (wasANumberWritten && (!isDotWritten) && (0 != numDigitsBeforeDecimal)) {
                isDotWritten = true;
                outputString[outputIndex++] = '.';
            }

            wasANumberWritten = true;
        }

        if (0 != modulo)
            wasANumberWritten = true;

        if (wasANumberWritten || (0 == numDigitsBeforeDecimal))
            outputString[outputIndex++] = '0' + modulo;

        if (outputIndex >= maxOutputLength)
            return 0;

        if ((0 == numberToFormat) && (numDigitsBeforeDecimal <= numberIndex))
            break;

        numberIndex++;

    }


    //reverse the string since we are creating it from left to right, and numbers are right to left
    for (uint16_t i = 0; i < outputIndex - 1 - i; i++) {
        uint8_t temp = outputString[i];
        outputString[i] = outputString[outputIndex - i - 1];
        outputString[outputIndex - i - 1] = temp;
    }

    outputString[outputIndex] = 0;
    return outputIndex + 1;
}

void reedSolomonEncode(const uint64_t inp, const uint8_t * output);


//note, when adding screen's make sure to add "return R_SUCCESS;" at the end 
uint8_t setScreenTexts() {

    int8_t counter = state.txnAuth.screenNum; //can't be uint cuz it has to have the ability to get negative

    if (-1 == counter)
        return R_REJECT;

    if (0 == counter--) {
        state.txnAuth.displayType = 0; //todo: rename to display type
        snprintf(state.txnAuth.displayTitle, sizeof(state.txnAuth.displayTitle), "Authorize");
        snprintf(state.txnAuth.displaystate, sizeof(state.txnAuth.displaystate), "Transaction");

        return R_SUCCESS;
    }

    if (0 == counter--) {
        state.txnAuth.displayType = 1;
        snprintf(state.txnAuth.displayTitle, sizeof(state.txnAuth.displayTitle), "Chain&TxnType");

        if (LEN_TXN_TYPES > state.txnAuth.txnTypeIndex) {
            snprintf(state.txnAuth.displaystate, sizeof(state.txnAuth.displaystate), "%s %s",
                chainName(state.txnAuth.chainId), txnNameAtIndex(state.txnAuth.txnTypeIndex));
        } else {
            snprintf(state.txnAuth.displaystate, sizeof(state.txnAuth.displaystate), "%s UnknownTxnType", 
                chainName(state.txnAuth.chainId));
        }

        return R_SUCCESS;
    }

    //if the txn type is unknown we skip it
    if (LEN_TXN_TYPES > state.txnAuth.txnTypeIndex) {

        switch (state.txnAuth.transactionTypeAndSubType) {

            //note: you have to write the type and subtype in reverse, because of little endian buffer representation an big endian C code representation

            case 0x0000: //OrdinaryPayment
            case 0x00fe: //FxtPayment

                if (0 == counter--) {
                    state.txnAuth.displayType = 1;

                    snprintf(state.txnAuth.displayTitle, sizeof(state.txnAuth.displayTitle), "Amount");
                    if (0 == formatAmount(state.txnAuth.displaystate, sizeof(state.txnAuth.displaystate), state.txnAuth.amount, chainNumDecimalsBeforePoint(state.txnAuth.chainId)))
                        return R_FORMAT_AMOUNT_ERR;

                    return R_SUCCESS;
                }

                if (0 == counter--) {
                    state.txnAuth.displayType = 1;

                    snprintf(state.txnAuth.displayTitle, sizeof(state.txnAuth.displayTitle), "Recipient");
                    snprintf(state.txnAuth.displaystate, sizeof(state.txnAuth.displaystate), APP_PREFIX);
                    reedSolomonEncode(state.txnAuth.recipientId, state.txnAuth.displaystate + strlen(state.txnAuth.displaystate));

                    return R_SUCCESS;
                }

                break;

            case 0x00fc: //FxtCoinExchangeOrderIssue
            case 0x000b: //CoinExchangeOrderIssue

                if (0 == counter--) {
                    state.txnAuth.displayType = 1;

                    snprintf(state.txnAuth.displayTitle, sizeof(state.txnAuth.displayTitle), "Amount");
                    
                    uint8_t ret = formatAmount(state.txnAuth.displaystate, sizeof(state.txnAuth.displaystate), state.txnAuth.attachmentTempInt64Num1, chainNumDecimalsBeforePoint(state.txnAuth.attachmentTempInt32Num2));

                    if (0 == ret)
                        return R_FORMAT_AMOUNT_ERR;

                    //note: the existence of chainName(state.txnAuth.attachmentTempInt32Num2) was already checked in the parsing function
                    snprintf(state.txnAuth.displaystate + ret - 1, sizeof(state.txnAuth.displaystate) - ret - 1, " %s", chainName(state.txnAuth.attachmentTempInt32Num2));

                    return R_SUCCESS;
                }

                if (0 == counter--) {
                    state.txnAuth.displayType = 1;

                    //note: the existence of chainName(state.txnAuth.attachmentTempInt32Num2) was already checked in the parsing function
                    snprintf(state.txnAuth.displayTitle, sizeof(state.txnAuth.displayTitle), "Price per %s", chainName(state.txnAuth.attachmentTempInt32Num2));
                    uint8_t ret = formatAmount(state.txnAuth.displaystate, sizeof(state.txnAuth.displaystate), state.txnAuth.attachmentTempInt64Num2, chainNumDecimalsBeforePoint(state.txnAuth.attachmentTempInt32Num1));

                    if (0 == ret)
                        return R_FORMAT_AMOUNT_ERR;

                    //note: the existence of chainName(state.txnAuth.attachmentTempInt32Num1) was already checked in the parsing function
                    snprintf(state.txnAuth.displaystate + ret - 1, sizeof(state.txnAuth.displaystate) - ret - 1, " %s", chainName(state.txnAuth.attachmentTempInt32Num1));

                    return R_SUCCESS;
                }
            

            /* case 0x0202: //Ask order placement


                if (0 == counter--) {

                    PRINTF("\n dd4 %d", state.txnAuth.attachmentTempInt32Num1);

                    state.txnAuth.displayType = 1;

                    snprintf(state.txnAuth.displayTitle, sizeof(state.txnAuth.displayTitle), "AssetId");
                    snprintf(state.txnAuth.displaystate, sizeof(state.txnAuth.displaystate), "%d", state.txnAuth.attachmentTempInt64Num1);
                    
                    return R_SUCCESS;

                }

                PRINTF("\n dd3");

                if (0 == counter--) {
                    state.txnAuth.displayType = 1;

                    snprintf(state.txnAuth.displayTitle, sizeof(state.txnAuth.displayTitle), "Quantity");
                    snprintf(state.txnAuth.displaystate, sizeof(state.txnAuth.displaystate), "%s", chainName(state.txnAuth.attachmentTempInt32Num2));

                    if (!formatAmount(state.txnAuth.displaystate, sizeof(state.txnAuth.displaystate), state.txnAuth.attachmentTempInt64Num1, chainNumDecimalsBeforePoint(state.txnAuth.attachmentTempInt32Num1)))
                        return R_FORMAT_AMOUNT_ERR;

                    return R_SUCCESS;
                }

                if (0 == counter--) {
                    state.txnAuth.displayType = 1;

                    snprintf(state.txnAuth.displayTitle, sizeof(state.txnAuth.displayTitle), "Target Amount");
                    if (!formatAmount(state.txnAuth.displaystate, sizeof(state.txnAuth.displaystate), state.txnAuth.attachmentTempInt64Num1, chainNumDecimalsBeforePoint(state.txnAuth.attachmentTempInt32Num1)))
                        return R_FORMAT_AMOUNT_ERR;

                    return R_SUCCESS;
                }
            */




            default:
                break;
        }
    }


    if (0 != state.txnAuth.appendagesFlags) {
        if (0 == counter--) {
            state.txnAuth.displayType = 1;

            snprintf(state.txnAuth.displayTitle, sizeof(state.txnAuth.displayTitle), "Apendages");
            snprintf(state.txnAuth.displaystate, sizeof(state.txnAuth.displaystate), "0x%08X", state.txnAuth.appendagesFlags);

            return R_SUCCESS;
        }
    }

    PRINTF("\nADD");

    if (0 == counter--) {
        state.txnAuth.displayType = 1;

        snprintf(state.txnAuth.displayTitle, sizeof(state.txnAuth.displayTitle), "Fee");

        PRINTF("\nADD1");

        uint8_t ret = formatAmount(state.txnAuth.displaystate, sizeof(state.txnAuth.displaystate), state.txnAuth.fee, chainNumDecimalsBeforePoint(state.txnAuth.chainId));

        PRINTF("\nADD2");

        if (0 == ret)
            return R_FORMAT_FEE_ERR;

        snprintf(state.txnAuth.displaystate + ret - 1, sizeof(state.txnAuth.displaystate) - ret - 1, " %s", chainName(state.txnAuth.chainId));                        
        return R_SUCCESS;
    }
            
    if (0 == counter--) {
        state.txnAuth.displayType = 2;

        snprintf(state.txnAuth.displayTitle, sizeof(state.txnAuth.displayTitle), "Authorize");
        snprintf(state.txnAuth.displaystate, sizeof(state.txnAuth.displaystate), "Transaction");
        return R_SUCCESS;
    }
    
    return R_FINISHED;
}

static unsigned int ui_auth_button(const unsigned int button_mask, const unsigned int button_mask_counter) {

    switch (button_mask) {
        case BUTTON_EVT_RELEASED | BUTTON_LEFT:

            state.txnAuth.screenNum--; //todo: rename screen number and display number so it will be more obvious
            break;

        case BUTTON_EVT_RELEASED | BUTTON_RIGHT:

            state.txnAuth.screenNum++;
            break;
        default:
        return 0;
    }

    uint8_t ret = setScreenTexts();

    switch (ret) {

        case R_SUCCESS:
            showScreen();
            return 0;

        case R_FINISHED:
            cx_hash(&state.txnAuth.hashstate.header, CX_LAST, 0, 0, state.txnAuth.finalHash, sizeof(state.txnAuth.finalHash));
            state.txnAuth.txnPassedAutherization = true;
            break;
            
        case R_REJECT:
            cleanState();
            break;
    }

    G_io_apdu_buffer[0] = R_SUCCESS;
    G_io_apdu_buffer[1] = ret;
    G_io_apdu_buffer[2] = 0x90;
    G_io_apdu_buffer[3] = 0x00;
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 4);
    ui_idle();

    return 0;
}

uint8_t addToFunctionStack(const uint8_t functionNum) {
    if (sizeof(state.txnAuth.functionStack) == state.txnAuth.numFunctionsOnStack)
        return R_FUNCTION_STACK_FULL;

    state.txnAuth.functionStack[state.txnAuth.numFunctionsOnStack++] = functionNum;

    return R_SUCCESS;
}


uint8_t * readFromBuffer(const uint8_t size) {

    if (state.txnAuth.readBufferEndPos - state.txnAuth.readBufferReadOffset < size)
        return 0;

    uint8_t * ret = state.txnAuth.readBuffer + state.txnAuth.readBufferReadOffset;
    state.txnAuth.readBufferReadOffset += size;
    state.txnAuth.numBytesRead += size;

    return ret;
}

uint8_t parseMainTxnData() {
     uint8_t * ptr = readFromBuffer(145);

    if (0 == ptr)
        return R_SEND_MORE_BYTES;

    os_memmove(&(state.txnAuth.chainId), ptr, sizeof(state.txnAuth.chainId));

    PRINTF("\n bb %d %.*H", state.txnAuth.chainId, 108, ptr);

    ptr += sizeof(state.txnAuth.chainId);

    if ((0 == state.txnAuth.chainId) || ((sizeof(CHAINS) / sizeof(CHAINS[0])) < state.txnAuth.chainId)) //note: we do +1 here because ardor start with index 1
        return R_BAD_CHAIN_ID_ERR;


    os_memmove(&(state.txnAuth.transactionTypeAndSubType), ptr, sizeof(state.txnAuth.transactionTypeAndSubType));

    PRINTF("\n baba %.*H", 4, &state.txnAuth.transactionTypeAndSubType);

    ptr += sizeof(state.txnAuth.transactionTypeAndSubType);

    txnType * currentTxnType = 0;

    for (state.txnAuth.txnTypeIndex = 0; state.txnAuth.txnTypeIndex < LEN_TXN_TYPES; state.txnAuth.txnTypeIndex++) {

        currentTxnType = txnTypeAtIndex(state.txnAuth.txnTypeIndex);

        if (currentTxnType->id == state.txnAuth.transactionTypeAndSubType)
            break;

        //if ((((txnType*)PIC(TXN_TYPES) + state.txnAuth.txnTypeIndex)->id) == state.txnAuth.transactionTypeAndSubType)
        //    break;
    }


    if (0 != currentTxnType->attachmentParsingFunctionNumber)
        addToFunctionStack(currentTxnType->attachmentParsingFunctionNumber);

    os_memmove(&(state.txnAuth.version), ptr, sizeof(state.txnAuth.version));
    ptr += sizeof(state.txnAuth.version);

    if (1 != state.txnAuth.version) //todo: fill this in
        return R_WRONG_VERSION_ERR;

    ptr += 4;   // Skip the timestamp
    ptr += 2;   // Skip the deadline
    ptr += 32;  // Skip the sender publickey

    os_memmove(&(state.txnAuth.recipientId), ptr, sizeof(state.txnAuth.recipientId));
    ptr += sizeof(state.txnAuth.recipientId);

    os_memmove(&(state.txnAuth.amount), ptr, sizeof(state.txnAuth.amount));
    ptr += sizeof(state.txnAuth.amount);

    os_memmove(&(state.txnAuth.fee), ptr, sizeof(state.txnAuth.fee));
    ptr += sizeof(state.txnAuth.fee);

    ptr += 64;  //Skip the sig
    ptr += 4;   //Skip the block height
    ptr += 8;   //Skip the block Id

    addToFunctionStack(6);

    return R_SUCCESS;
}

uint8_t parseReferencedTxn() {

    if (0 == readFromBuffer(sizeof(uint32_t) + 32))
        return R_SEND_MORE_BYTES;

    return R_SUCCESS;
}

uint8_t parseAppendagesFlags() {
    
    uint8_t * ptr = readFromBuffer(sizeof(state.txnAuth.appendagesFlags));

    if (0 == ptr)
        return R_SEND_MORE_BYTES;

    os_memmove(&(state.txnAuth.appendagesFlags), ptr, sizeof(state.txnAuth.appendagesFlags));

    return R_SUCCESS;
}

uint8_t parseIngoreBytesUntilTheEnd() {
    while (state.txnAuth.numBytesRead != state.txnAuth.txnSizeBytes) {
        if (0 == readFromBuffer(1))
            return R_SEND_MORE_BYTES;
    }

    return R_SUCCESS;
}

uint8_t parseFxtCoinExchangeOrderIssueOrCoinExchangeOrderIssueAttachment() {
    
    state.txnAuth.attachmentTempInt32Num1 = 0; //chaidId
    state.txnAuth.attachmentTempInt32Num2 = 0; //exchangeChain
    state.txnAuth.attachmentTempInt64Num1 = 0; //quantity
    state.txnAuth.attachmentTempInt64Num2 = 0; //price

    uint8_t * ptr = readFromBuffer(sizeof(uint8_t) + sizeof(state.txnAuth.attachmentTempInt32Num1) * 2 + sizeof(state.txnAuth.attachmentTempInt64Num1) * 2);
    if (0 == ptr)
        return R_SEND_MORE_BYTES;

    if (1 != *ptr)
        return R_UNSUPPORTED_ATTACHMENT_VERSION;

    ptr += 1;

    os_memmove(&state.txnAuth.attachmentTempInt32Num1, ptr, sizeof(state.txnAuth.attachmentTempInt32Num1));
    ptr += sizeof(state.txnAuth.attachmentTempInt32Num1);

    if (state.txnAuth.attachmentTempInt32Num1 > (sizeof(CHAINS) / sizeof(CHAINS[0])))
        return R_BAD_CHAIN_ID_ERR;

    os_memmove(&state.txnAuth.attachmentTempInt32Num2, ptr, sizeof(state.txnAuth.attachmentTempInt32Num2));
    ptr += sizeof(state.txnAuth.attachmentTempInt32Num2);

    if (state.txnAuth.attachmentTempInt32Num2 > (sizeof(CHAINS) / sizeof(CHAINS[0])))
        return R_BAD_CHAIN_ID_ERR;

    os_memmove(&state.txnAuth.attachmentTempInt64Num1, ptr, sizeof(state.txnAuth.attachmentTempInt64Num1));
    ptr += sizeof(state.txnAuth.attachmentTempInt64Num1);
    
    os_memmove(&state.txnAuth.attachmentTempInt64Num2, ptr, sizeof(state.txnAuth.attachmentTempInt64Num2));

    return R_SUCCESS;
}

uint8_t parseAskOrderPlacementAttachment() {
    
    state.txnAuth.attachmentTempInt64Num1 = 0;
    state.txnAuth.attachmentTempInt64Num2 = 0;
    state.txnAuth.attachmentTempInt64Num3 = 0;

    uint8_t * ptr = readFromBuffer(sizeof(state.txnAuth.attachmentTempInt64Num1) * 3);
    if (0 == ptr)
        return R_SEND_MORE_BYTES;

    os_memmove(&state.txnAuth.attachmentTempInt64Num1, ptr, sizeof(state.txnAuth.attachmentTempInt64Num1));
    ptr += sizeof(state.txnAuth.attachmentTempInt64Num1);

    os_memmove(&state.txnAuth.attachmentTempInt64Num2, ptr, sizeof(state.txnAuth.attachmentTempInt64Num2));
    ptr += sizeof(state.txnAuth.attachmentTempInt64Num2);

    os_memmove(&state.txnAuth.attachmentTempInt64Num3, ptr, sizeof(state.txnAuth.attachmentTempInt64Num3));

    return R_SUCCESS;
}

uint8_t addToReadBuffer(const uint8_t * const newData, const uint8_t numBytes) {

    for (uint8_t i = 0; i < state.txnAuth.readBufferEndPos - state.txnAuth.readBufferReadOffset; i++)
        state.txnAuth.readBuffer[i] = state.txnAuth.readBuffer[i + state.txnAuth.readBufferReadOffset];

    os_memset(state.txnAuth.readBuffer + state.txnAuth.readBufferEndPos - state.txnAuth.readBufferReadOffset, 0, state.txnAuth.readBufferReadOffset); //set to 0, just for saftey

    state.txnAuth.readBufferEndPos -= state.txnAuth.readBufferReadOffset;
    state.txnAuth.readBufferReadOffset = 0;

    if (state.txnAuth.readBufferEndPos + numBytes > sizeof(state.txnAuth.readBuffer))
        return R_NO_SPACE_BUFFER_TOO_SMALL;

    cx_hash(&state.txnAuth.hashstate.header, 0, newData, numBytes, state.txnAuth.finalHash, sizeof(state.txnAuth.finalHash));

    os_memcpy(state.txnAuth.readBuffer + state.txnAuth.readBufferEndPos, newData, numBytes);
    state.txnAuth.readBufferEndPos += numBytes;

    return R_SUCCESS;
}


uint8_t callFunctionNumber(const uint8_t functionNum) {

    switch (functionNum) {
        case 1:
            return parseMainTxnData();
        case 2:
            return parseAppendagesFlags();
        case 3:
            return parseReferencedTxn();
        case 4:
            return parseFxtCoinExchangeOrderIssueOrCoinExchangeOrderIssueAttachment();
        case 5:
            return parseAskOrderPlacementAttachment();
        case 6:
            return parseIngoreBytesUntilTheEnd();
    }

    return R_PARSE_FUNCTION_NOT_FOUND;
}


uint8_t parseFromStack() {
    
    while (true) {

        PRINTF("\n s %.*H", sizeof(state.txnAuth.functionStack), state.txnAuth.functionStack);

        if (0 == state.txnAuth.numFunctionsOnStack) {//todo check the state here

            PRINTF("\n b %d %d", state.txnAuth.readBufferEndPos,  state.txnAuth.readBufferReadOffset);

            if (state.txnAuth.readBufferEndPos != state.txnAuth.readBufferReadOffset)
                return R_NOT_ALL_BYTES_READ;

            setScreenTexts();
            showScreen();

            return R_SHOW_DISPLAY;
        }

        uint8_t ret = callFunctionNumber(state.txnAuth.functionStack[0]);

        if (R_SEND_MORE_BYTES == ret)
            return ret;

        uint8_t tempBuffer[FUNCTION_STACK_SIZE - 1];
        os_memmove(tempBuffer, state.txnAuth.functionStack + 1, sizeof(tempBuffer));
        os_memmove(state.txnAuth.functionStack, tempBuffer, sizeof(tempBuffer));
        state.txnAuth.functionStack[sizeof(state.txnAuth.functionStack) - 1] = 0;
        state.txnAuth.numFunctionsOnStack--;

        if (R_SUCCESS == ret)
            continue;

        return ret;
    }

}

uint8_t signTxn(const uint8_t * const data, const uint32_t derivationPath, const uint8_t derivationPathLengthInUints32, 
                 uint8_t * const destBuffer, uint16_t * const outException) {

    uint8_t keySeed[64]; os_memset(keySeed, 0, sizeof(keySeed));
    uint8_t ret = 0;

    if (R_SUCCESS != (ret = ardorKeys(derivationPath, derivationPathLengthInUints32, keySeed, 0, 0, 0, outException))) {
        os_memset(keySeed, 0, sizeof(keySeed));
        return ret;
    }

    //sign msg should only use the first 32 bytes of keyseed
    signMsg(keySeed, data, destBuffer); //is a void function, no ret value to check against
    
    os_memset(keySeed, 0, sizeof(keySeed));

    return R_SUCCESS;
}

#define P1_INIT 1
#define P1_CONTINUE 2
#define P1_SIGN 3

//todo check if we allow to sign the same txn with 2 different keys, if thats ok
//todo figure out what volotile means?
void authAndSignTxnHandlerHelper(const uint8_t p1, const uint8_t p2, const uint8_t * const dataBuffer, const uint8_t dataLength,
                volatile unsigned int *flags, volatile unsigned int *tx) {

    
    PRINTF("\n asdijasidjaisjdasid");
    PRINTF("\n asd %d %d", p1, p1 & 0x03);

    if (dataLength < 1) {
        cleanState();
        G_io_apdu_buffer[(*tx)++] = R_WRONG_SIZE_ERR;    
        return;
    }


    if (P1_SIGN == (p1 & 0x03)) {

        if (dataLength < 2 * sizeof(uint32_t)) {
            cleanState();
            G_io_apdu_buffer[(*tx)++] = R_WRONG_SIZE_ERR;
            return; 
        }

        if (!state.txnAuth.txnPassedAutherization) {
            cleanState();
            G_io_apdu_buffer[(*tx)++] = R_TXN_UNAUTHORIZED;
            return;
        }
        
        uint8_t derivationParamLengthInBytes = dataLength;

        if (0 != derivationParamLengthInBytes % 4) {
            cleanState();
            G_io_apdu_buffer[(*tx)++] = R_UNKNOWN_CMD_PARAM_ERR;
            return;
        }

        uint32_t derivationPathCpy[62]; os_memset(derivationPathCpy, 0, sizeof(derivationPathCpy));

        os_memmove(derivationPathCpy, dataBuffer, derivationParamLengthInBytes);

        uint16_t exception = 0;

        G_io_apdu_buffer[(*tx)++] = R_SUCCESS;

        uint8_t ret = signTxn(state.txnAuth.finalHash, derivationPathCpy, derivationParamLengthInBytes / 4, G_io_apdu_buffer + 1, &exception);

        if (R_SUCCESS == ret) {
            *tx += 64;
        } else {
            *tx -= 1;
            G_io_apdu_buffer[(*tx)++] = ret;

            if (R_KEY_DERIVATION_EX == ret) {
                G_io_apdu_buffer[(*tx)++] = exception >> 8;
                G_io_apdu_buffer[(*tx)++] = exception & 0xFF;   
            }
        }
    } else if ((P1_INIT == (p1 & 0x03)) || (P1_CONTINUE == (p1 & 0x03))) {

        if (P1_INIT != (p1 & 0x03)) {

            if (state.txnAuth.txnPassedAutherization) {
                cleanState();
                G_io_apdu_buffer[(*tx)++] = R_NOT_ALL_BYTES_USED;
                return;
            }

            if (state.txnAuth.isClean) {
                cleanState();
                G_io_apdu_buffer[(*tx)++] = R_ERR_NO_INIT_CANT_CONTINUE;
                return;
            }
        } else {
            cleanState();

            state.txnAuth.txnSizeBytes = ((p1 & 0b11111100) << 6) + p2;

            PRINTF("\n fasd %d", state.txnAuth.txnSizeBytes);

            if (145 > state.txnAuth.txnSizeBytes) {
                G_io_apdu_buffer[(*tx)++] = R_TXN_SIZE_TOO_SMALL;
                return;
            }
        }

        state.txnAuth.isClean = false;

        uint8_t ret = addToReadBuffer(dataBuffer, dataLength);

        if (R_SUCCESS != ret) {
            G_io_apdu_buffer[(*tx)++] = ret;
            return;
        }

        ret = parseFromStack();

        if (!((R_SEND_MORE_BYTES == ret) || (R_FINISHED == ret) || (R_SHOW_DISPLAY == ret)))
            cleanState();

        if (R_SHOW_DISPLAY == ret) {
            *flags |= IO_ASYNCH_REPLY;
        } else {
            G_io_apdu_buffer[(*tx)++] = R_SUCCESS;
            G_io_apdu_buffer[(*tx)++] = ret;
        }
    } else {
        G_io_apdu_buffer[(*tx)++] = R_UNKNOWN_CMD_PARAM_ERR;
    }
}

void authAndSignTxnHandler(uint8_t p1, uint8_t p2, uint8_t *dataBuffer, uint8_t dataLength,
                volatile unsigned int *flags, volatile unsigned int *tx) {

    authAndSignTxnHandlerHelper(p1, p2, dataBuffer, dataLength, flags, tx);

    if (0 == ((*flags) & IO_ASYNCH_REPLY)) {
        G_io_apdu_buffer[(*tx)++] = 0x90;
        G_io_apdu_buffer[(*tx)++] = 0x00;
    }
}
