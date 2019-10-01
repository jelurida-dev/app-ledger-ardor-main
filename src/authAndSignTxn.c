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

authAndSignState_t state;

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
        UI_TEXT(0x00, 0, 12, 128, state.displayTitle),
        {{BAGL_LABELINE,0x01,15,26,98,12,10,0,0,0xFFFFFF,0,BAGL_FONT_OPEN_SANS_EXTRABOLD_11px|BAGL_FONT_ALIGNMENT_CENTER,26},(char*)state.displaystate,0,0,0,NULL,NULL,NULL}
};

static const bagl_element_t ui_centerScreen[] = {
        UI_BACKGROUND(),
        {{BAGL_ICON,0x00,3,12,7,7,0,0,0,0xFFFFFF,0,0,BAGL_GLYPH_ICON_LEFT},NULL,0,0,0,NULL,NULL,NULL},
        {{BAGL_ICON,0x00,117,13,8,6,0,0,0,0xFFFFFF,0,0,BAGL_GLYPH_ICON_RIGHT},NULL,0,0,0,NULL,NULL,NULL},
        UI_TEXT(0x00, 0, 12, 128, state.displayTitle),
        {{BAGL_LABELINE,0x01,15,26,98,12,10,0,0,0xFFFFFF,0,BAGL_FONT_OPEN_SANS_EXTRABOLD_11px|BAGL_FONT_ALIGNMENT_CENTER,26},(char*)state.displaystate,0,0,0,NULL,NULL,NULL}
};

static const bagl_element_t ui_finalScreen[] = {
        UI_BACKGROUND(),
        {{BAGL_ICON,0x00,3,12,7,7,0,0,0,0xFFFFFF,0,0,BAGL_GLYPH_ICON_LEFT},NULL,0,0,0,NULL,NULL,NULL},
        {{BAGL_ICON,0x00,117,13,8,6,0,0,0,0xFFFFFF,0,0,BAGL_GLYPH_ICON_CHECK},NULL,0,0,0,NULL,NULL,NULL},
        UI_TEXT(0x00, 0, 12, 128, state.displayTitle),
        {{BAGL_LABELINE,0x01,15,26,98,12,10,0,0,0xFFFFFF,0,BAGL_FONT_OPEN_SANS_EXTRABOLD_11px|BAGL_FONT_ALIGNMENT_CENTER,26},(char*)state.displaystate,0,0,0,NULL,NULL,NULL}
};

unsigned int makeTextGoAround_preprocessor(const bagl_element_t *element);

void cleanState() {

    state.txnSizeBytes = 0;
    state.numBytesRead = 0;

    os_memset(state.functionStack, 0, sizeof(state.functionStack));
    state.functionStack[0] = 1; //Add the first parse function on the stack
    state.functionStack[1] = 2; //The appendages parse function
    state.numFunctionsOnStack = 2;

    state.txnPassedAutherization = false;
    state.isClean = true;
    
    os_memset(state.finalHash, 0, sizeof(state.finalHash));
    cx_sha256_init(&state.hashstate);

    //todo: add all constructors for new members here

    os_memset(state.readBuffer, 0, sizeof(state.readBuffer));
    state.readBufferReadOffset = 0;
    state.readBufferEndPos = 0;


    os_memset(state.tempBuffer, 0, sizeof(state.tempBuffer));


    os_memset(state.displayTitle, 0, sizeof(state.displayTitle));
    os_memset(state.displaystate, 0, sizeof(state.displaystate));


    state.chainId = 0;
    state.transactionTypeAndSubType = 0;
    state.txnTypeIndex = 0;
    state.version = 0;
    state.recipientId = 0;
    state.amount = 0;
    state.fee = 0;
    state.appendagesFlags = 0;
    state.displayType = 0;

    state.screenNum = 0;

    state.attachmentTempInt32Num1 = 0;
    state.attachmentTempInt32Num2 = 0;
    state.attachmentTempInt64Num1 = 0;
    state.attachmentTempInt64Num2 = 0;
    state.attachmentTempInt64Num3 = 0;
}


void showScreen() {
    switch (state.displayType) {
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
static const chainType CHAINS[] = {{0x00000001, "Ardor", 8}, {0x00000002, "Ignis", 8}, {0x00000003, "AEUR", 4}, {0x00000004, "BITSWIFT", 8}, {0x00000005, "MPG", 8}};


txnType * txnTypeAtIndex(uint8_t index) {
    return (txnType*)PIC(&TXN_TYPES[index]);
}

//todo write a note here why not returning the class because of PIC, rename to txnTypeName
char * txnNameAtIndex(uint8_t index) {
    return (char*)PIC(((txnType*)PIC(&TXN_TYPES[index]))->name);
}

//uint8_t txnNumScreensAtIndex(uint8_t index) {
//    return ((txnType*)PIC(&TXN_TYPES[index]))->numScreens;
//}

char * chainName(uint8_t chainId) {
    return (char*)PIC(((chainType*)PIC(&CHAINS[chainId - 1]))->name);
}

uint8_t chainNumDecimalsBeforePoint(uint8_t chainId) {
    return ((chainType*)PIC(&CHAINS[chainId - 1]))->numDecimalsBeforePoint;
}

//returns 0 iff some kind of error happend, else the length of the output string including the null terminator
uint8_t formatAmount(uint8_t * outputString, uint16_t maxOutputLength, uint64_t numberToFormat, const uint8_t numDecimalsBeforePoint) {
    
    uint16_t outputIndex = 0;
    bool wasANumberWritten = false;
    bool isDotWritten = false;
    uint8_t numberIndex = 0;


    while (42) {

        uint8_t modulo = numberToFormat % 10;
        numberToFormat -= modulo;
        numberToFormat /= 10;

        if (numDecimalsBeforePoint == numberIndex) {
            if (wasANumberWritten && (!isDotWritten) && (0 != numDecimalsBeforePoint)) {
                isDotWritten = true;
                outputString[outputIndex++] = '.';
            }

            wasANumberWritten = true;
        }

        if (0 != modulo)
            wasANumberWritten = true;

        if (wasANumberWritten || (0 == numDecimalsBeforePoint))
            outputString[outputIndex++] = '0' + modulo;

        if (outputIndex >= maxOutputLength)
            return 0;

        if ((0 == numberToFormat) && (numDecimalsBeforePoint <= numberIndex))
            break;

        numberIndex++;

    }

    for (uint16_t i = 0; i < outputIndex - 1 - i; i++) {
        uint8_t temp = outputString[i];
        outputString[i] = outputString[outputIndex - i - 1];
        outputString[outputIndex - i - 1] = temp;
    }

    outputString[outputIndex] = 0;
    return outputIndex + 1;
}

void reedSolomonEncode(uint64_t inp, uint8_t * output);


//note, when adding screen's make sure to add "return R_SUCCESS;" at the end 
uint8_t setScreenTexts() {

    int8_t counter = state.screenNum; //can't be uint cuz it has to have the ability to get negative

    if (-1 == counter)
        return R_REJECT;

    if (0 == counter--) {
        state.displayType = 0; //todo: rename to display type
        snprintf(state.displayTitle, sizeof(state.displayTitle), "Authorize");
        snprintf(state.displaystate, sizeof(state.displaystate), "Transaction");

        return R_SUCCESS;
    }

    if (0 == counter--) {
        state.displayType = 1;
        snprintf(state.displayTitle, sizeof(state.displayTitle), "Chain&TxnType");

        if (LEN_TXN_TYPES > state.txnTypeIndex) {
            snprintf(state.displaystate, sizeof(state.displaystate), "%s %s",
                chainName(state.chainId), txnNameAtIndex(state.txnTypeIndex));
        } else {
            snprintf(state.displaystate, sizeof(state.displaystate), "%s UnknownTxnType", 
                chainName(state.chainId));
        }

        return R_SUCCESS;
    }

    //if the txn type is unknown we skip it
    if (LEN_TXN_TYPES > state.txnTypeIndex) {

        switch (state.transactionTypeAndSubType) {

            //note: you have to write the type and subtype in reverse, because of little endian buffer representation an big endian C code representation

            case 0x0000: //OrdinaryPayment
            case 0x00fe: //FxtPayment

                if (0 == counter--) {
                    state.displayType = 1;

                    snprintf(state.displayTitle, sizeof(state.displayTitle), "Amount");
                    if (0 == formatAmount(state.displaystate, sizeof(state.displaystate), state.amount, chainNumDecimalsBeforePoint(state.chainId)))
                        return R_FORMAT_AMOUNT_ERR;

                    return R_SUCCESS;
                }

                if (0 == counter--) {
                    state.displayType = 1;

                    snprintf(state.displayTitle, sizeof(state.displayTitle), "Destination");
                    snprintf(state.displaystate, sizeof(state.displaystate), "ARDOR-");
                    reedSolomonEncode(state.recipientId, state.displaystate + strlen(state.displaystate));

                    return R_SUCCESS;
                }

                break;

            case 0x00fc: //FxtCoinExchangeOrderIssue
            case 0x000b: //CoinExchangeOrderIssue

                if (0 == counter--) {
                    state.displayType = 1;

                    snprintf(state.displayTitle, sizeof(state.displayTitle), "Amount");
                    
                    uint8_t ret = formatAmount(state.displaystate, sizeof(state.displaystate), state.attachmentTempInt64Num1, chainNumDecimalsBeforePoint(state.attachmentTempInt32Num2));

                    if (0 == ret)
                        return R_FORMAT_AMOUNT_ERR;

                    //note: the existence of chainName(state.attachmentTempInt32Num2) was already checked in the parsing function
                    snprintf(state.displaystate + ret - 1, sizeof(state.displaystate) - ret - 1, " %s", chainName(state.attachmentTempInt32Num2));

                    return R_SUCCESS;
                }

                if (0 == counter--) {
                    state.displayType = 1;

                    //note: the existence of chainName(state.attachmentTempInt32Num2) was already checked in the parsing function
                    snprintf(state.displayTitle, sizeof(state.displayTitle), "Price per %s", chainName(state.attachmentTempInt32Num2));
                    uint8_t ret = formatAmount(state.displaystate, sizeof(state.displaystate), state.attachmentTempInt64Num2, chainNumDecimalsBeforePoint(state.attachmentTempInt32Num1));

                    if (0 == ret)
                        return R_FORMAT_AMOUNT_ERR;

                    //note: the existence of chainName(state.attachmentTempInt32Num1) was already checked in the parsing function
                    snprintf(state.displaystate + ret - 1, sizeof(state.displaystate) - ret - 1, " %s", chainName(state.attachmentTempInt32Num1));

                    return R_SUCCESS;
                }
            

            /* case 0x0202: //Ask order placement


                if (0 == counter--) {

                    PRINTF("\n dd4 %d", state.attachmentTempInt32Num1);

                    state.displayType = 1;

                    snprintf(state.displayTitle, sizeof(state.displayTitle), "AssetId");
                    snprintf(state.displaystate, sizeof(state.displaystate), "%d", state.attachmentTempInt64Num1);
                    
                    return R_SUCCESS;

                }

                PRINTF("\n dd3");

                if (0 == counter--) {
                    state.displayType = 1;

                    snprintf(state.displayTitle, sizeof(state.displayTitle), "Quantity");
                    snprintf(state.displaystate, sizeof(state.displaystate), "%s", chainName(state.attachmentTempInt32Num2));

                    if (!formatAmount(state.displaystate, sizeof(state.displaystate), state.attachmentTempInt64Num1, chainNumDecimalsBeforePoint(state.attachmentTempInt32Num1)))
                        return R_FORMAT_AMOUNT_ERR;

                    return R_SUCCESS;
                }

                if (0 == counter--) {
                    state.displayType = 1;

                    snprintf(state.displayTitle, sizeof(state.displayTitle), "Target Amount");
                    if (!formatAmount(state.displaystate, sizeof(state.displaystate), state.attachmentTempInt64Num1, chainNumDecimalsBeforePoint(state.attachmentTempInt32Num1)))
                        return R_FORMAT_AMOUNT_ERR;

                    return R_SUCCESS;
                }
            */




            default:
                break;
        }
    }


    if (0 != state.appendagesFlags) {
        if (0 == counter--) {
            state.displayType = 1;

            snprintf(state.displayTitle, sizeof(state.displayTitle), "Apendages");
            snprintf(state.displaystate, sizeof(state.displaystate), "0x%08X", state.appendagesFlags);

            return R_SUCCESS;
        }
    }

    PRINTF("\nADD");

    if (0 == counter--) {
        state.displayType = 1;

        snprintf(state.displayTitle, sizeof(state.displayTitle), "Fee");

        PRINTF("\nADD1");

        uint8_t ret = formatAmount(state.displaystate, sizeof(state.displaystate), state.fee, chainNumDecimalsBeforePoint(state.chainId));

        PRINTF("\nADD2");

        if (0 == ret)
            return R_FORMAT_FEE_ERR;

        snprintf(state.displaystate + ret - 1, sizeof(state.displaystate) - ret - 1, " %s", chainName(state.chainId));                        
        return R_SUCCESS;
    }
            
    if (0 == counter--) {
        state.displayType = 2;

        snprintf(state.displayTitle, sizeof(state.displayTitle), "Authorize");
        snprintf(state.displaystate, sizeof(state.displaystate), "Transaction");
        return R_SUCCESS;
    }
    
    return R_FINISHED;
}

static unsigned int ui_auth_button(unsigned int button_mask, unsigned int button_mask_counter) {

    switch (button_mask) {
        case BUTTON_EVT_RELEASED | BUTTON_LEFT:

            state.screenNum--; //todo: rename screen number and display number so it will be more obvious
            break;

        case BUTTON_EVT_RELEASED | BUTTON_RIGHT:

            state.screenNum++;
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
            cx_hash(&state.hashstate.header, CX_LAST, 0, 0, state.finalHash, sizeof(state.finalHash));
            state.txnPassedAutherization = true;
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

uint8_t addToFunctionStack(uint8_t functionNum) {
    if (sizeof(state.functionStack) == state.numFunctionsOnStack)
        return R_FUNCTION_STACK_FULL;

    state.functionStack[state.numFunctionsOnStack++] = functionNum;

    return R_SUCCESS;
}


uint8_t * readFromBuffer(uint8_t size) {

    PRINTF("\n %d %d %d", state.readBufferEndPos,  state.readBufferReadOffset, size);

    if (state.readBufferEndPos - state.readBufferReadOffset < size)
        return 0;

    uint8_t * ret = state.readBuffer + state.readBufferReadOffset;
    state.readBufferReadOffset += size;
    state.numBytesRead += size;

    return ret;
}

uint8_t parseMainTxnData() {
     uint8_t * ptr = readFromBuffer(145);

    if (0 == ptr)
        return R_SEND_MORE_BYTES;

    os_memmove(&(state.chainId), ptr, sizeof(state.chainId));

    PRINTF("\n bb %d %.*H", state.chainId, 108, ptr);

    ptr += sizeof(state.chainId);

    if ((0 == state.chainId) || ((sizeof(CHAINS) / sizeof(CHAINS[0])) < state.chainId)) //note: we do +1 here because ardor start with index 1
        return R_BAD_CHAIN_ID_ERR;


    os_memmove(&(state.transactionTypeAndSubType), ptr, sizeof(state.transactionTypeAndSubType));

    PRINTF("\n baba %.*H", 4, &state.transactionTypeAndSubType);

    ptr += sizeof(state.transactionTypeAndSubType);

    txnType * currentTxnType = 0;

    for (state.txnTypeIndex = 0; state.txnTypeIndex < LEN_TXN_TYPES; state.txnTypeIndex++) {

        currentTxnType = txnTypeAtIndex(state.txnTypeIndex);

        if (currentTxnType->id == state.transactionTypeAndSubType)
            break;

        //if ((((txnType*)PIC(TXN_TYPES) + state.txnTypeIndex)->id) == state.transactionTypeAndSubType)
        //    break;
    }


    if (0 != currentTxnType->attachmentParsingFunctionNumber)
        addToFunctionStack(currentTxnType->attachmentParsingFunctionNumber);

    os_memmove(&(state.version), ptr, sizeof(state.version));
    ptr += sizeof(state.version);

    if (1 != state.version) //todo: fill this in
        return R_WRONG_VERSION_ERR;

    ptr += 4;   // Skip the timestamp
    ptr += 2;   // Skip the deadline
    ptr += 32;  // Skip the sender publickey

    os_memmove(&(state.recipientId), ptr, sizeof(state.recipientId));
    ptr += sizeof(state.recipientId);

    os_memmove(&(state.amount), ptr, sizeof(state.amount));
    ptr += sizeof(state.amount);

    os_memmove(&(state.fee), ptr, sizeof(state.fee));
    ptr += sizeof(state.fee);

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
    
    uint8_t * ptr = readFromBuffer(sizeof(state.appendagesFlags));

    if (0 == ptr)
        return R_SEND_MORE_BYTES;

    os_memmove(&(state.appendagesFlags), ptr, sizeof(state.appendagesFlags));

    return R_SUCCESS;
}

uint8_t parseIngoreBytesUntilTheEnd() {
    while (state.numBytesRead != state.txnSizeBytes) {
        if (0 == readFromBuffer(1))
            return R_SEND_MORE_BYTES;
    }

    return R_SUCCESS;
}

uint8_t parseFxtCoinExchangeOrderIssueOrCoinExchangeOrderIssueAttachment() {
    
    state.attachmentTempInt32Num1 = 0; //chaidId
    state.attachmentTempInt32Num2 = 0; //exchangeChain
    state.attachmentTempInt64Num1 = 0; //quantity
    state.attachmentTempInt64Num2 = 0; //price

    uint8_t * ptr = readFromBuffer(sizeof(uint8_t) + sizeof(state.attachmentTempInt32Num1) * 2 + sizeof(state.attachmentTempInt64Num1) * 2);
    if (0 == ptr)
        return R_SEND_MORE_BYTES;

    if (1 != *ptr)
        return R_UNSUPPORTED_ATTACHMENT_VERSION;

    ptr += 1;

    os_memmove(&state.attachmentTempInt32Num1, ptr, sizeof(state.attachmentTempInt32Num1));
    ptr += sizeof(state.attachmentTempInt32Num1);

    if (state.attachmentTempInt32Num1 > (sizeof(CHAINS) / sizeof(CHAINS[0])))
        return R_BAD_CHAIN_ID_ERR;

    os_memmove(&state.attachmentTempInt32Num2, ptr, sizeof(state.attachmentTempInt32Num2));
    ptr += sizeof(state.attachmentTempInt32Num2);

    if (state.attachmentTempInt32Num2 > (sizeof(CHAINS) / sizeof(CHAINS[0])))
        return R_BAD_CHAIN_ID_ERR;

    os_memmove(&state.attachmentTempInt64Num1, ptr, sizeof(state.attachmentTempInt64Num1));
    ptr += sizeof(state.attachmentTempInt64Num1);
    
    os_memmove(&state.attachmentTempInt64Num2, ptr, sizeof(state.attachmentTempInt64Num2));

    return R_SUCCESS;
}

uint8_t parseAskOrderPlacementAttachment() {
    
    state.attachmentTempInt64Num1 = 0;
    state.attachmentTempInt64Num2 = 0;
    state.attachmentTempInt64Num3 = 0;

    uint8_t * ptr = readFromBuffer(sizeof(state.attachmentTempInt64Num1) * 3);
    if (0 == ptr)
        return R_SEND_MORE_BYTES;

    os_memmove(&state.attachmentTempInt64Num1, ptr, sizeof(state.attachmentTempInt64Num1));
    ptr += sizeof(state.attachmentTempInt64Num1);

    os_memmove(&state.attachmentTempInt64Num2, ptr, sizeof(state.attachmentTempInt64Num2));
    ptr += sizeof(state.attachmentTempInt64Num2);

    os_memmove(&state.attachmentTempInt64Num3, ptr, sizeof(state.attachmentTempInt64Num3));

    return R_SUCCESS;
}

uint8_t addToReadBuffer(uint8_t * newData, uint8_t numBytes) {

    for (uint8_t i = 0; i < state.readBufferEndPos - state.readBufferReadOffset; i++)
        state.readBuffer[i] = state.readBuffer[i + state.readBufferReadOffset];

    os_memset(state.readBuffer + state.readBufferEndPos - state.readBufferReadOffset, 0, state.readBufferReadOffset); //set to 0, just for saftey

    state.readBufferEndPos -= state.readBufferReadOffset;
    state.readBufferReadOffset = 0;

    if (state.readBufferEndPos + numBytes > sizeof(state.readBuffer))
        return R_NO_SPACE_BUFFER_TOO_SMALL;

    cx_hash(&state.hashstate.header, 0, newData, numBytes, state.finalHash, sizeof(state.finalHash));

    os_memcpy(state.readBuffer + state.readBufferEndPos, newData, numBytes);
    state.readBufferEndPos += numBytes;

    return R_SUCCESS;
}


uint8_t callFunctionNumber(uint8_t functionNum) {

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

        PRINTF("\n s %.*H", sizeof(state.functionStack), state.functionStack);

        if (0 == state.numFunctionsOnStack) {//todo check the state here

            PRINTF("\n b %d %d", state.readBufferEndPos,  state.readBufferReadOffset);

            if (state.readBufferEndPos != state.readBufferReadOffset)
                return R_NOT_ALL_BYTES_READ;

            setScreenTexts();
            showScreen();

            return R_SHOW_DISPLAY;
        }

        uint8_t ret = callFunctionNumber(state.functionStack[0]);

        if (R_SEND_MORE_BYTES == ret)
            return ret;

        uint8_t tempBuffer[FUNCTION_STACK_SIZE - 1];
        os_memmove(tempBuffer, state.functionStack + 1, sizeof(tempBuffer));
        os_memmove(state.functionStack, tempBuffer, sizeof(tempBuffer));
        state.functionStack[sizeof(state.functionStack) - 1] = 0;
        state.numFunctionsOnStack--;

        if (R_SUCCESS == ret)
            continue;

        return ret;
    }

}

uint8_t signTxn(uint8_t * data, const uint32_t derivationPath, const uint8_t derivationPathLengthInUints32, 
                 uint8_t * destBuffer, uint16_t * outException) {

    uint8_t keySeed[32]; os_memset(keySeed, 0, sizeof(keySeed));
    uint8_t ret = 0;

    if (R_SUCCESS != (ret = ardorKeys(derivationPath, derivationPathLengthInUints32, keySeed, 0, 0, outException))) {
        os_memset(keySeed, 0, sizeof(keySeed));
        return ret;
    }

    signMsg(keySeed, data, destBuffer); //is a void function, no ret value to check against
    
    os_memset(keySeed, 0, sizeof(keySeed));

    return R_SUCCESS;
}

#define P1_INIT 1
#define P1_CONTINUE 2
#define P1_SIGN 3

void authAndSignTxnHandlerHelper(uint8_t p1, uint8_t p2, uint8_t *dataBuffer, uint16_t dataLength,
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
            G_io_apdu_buffer[(*tx)++] = R_WRONG_SIZE_ERR;
            return; 
        }

        if (!state.txnPassedAutherization) {
            G_io_apdu_buffer[(*tx)++] = R_TXN_UNAUTHORIZED;
            return;
        }

        
        uint8_t derivationParamLengthInBytes = dataLength;

        if (0 != derivationParamLengthInBytes % 4) {
            G_io_apdu_buffer[(*tx)++] = R_UNKNOWN_CMD_PARAM_ERR;
            return;
        }

        uint32_t derivationPathCpy[55]; os_memset(derivationPathCpy, 0, sizeof(derivationPathCpy));

        os_memmove(derivationPathCpy, dataBuffer, derivationParamLengthInBytes);

        uint16_t exception = 0;

        G_io_apdu_buffer[(*tx)++] = R_SUCCESS;

        uint8_t ret = signTxn(state.finalHash, derivationPathCpy, derivationParamLengthInBytes / 4, G_io_apdu_buffer + 1, &exception);

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

            if (state.txnPassedAutherization) {
                cleanState();
                G_io_apdu_buffer[(*tx)++] = R_NOT_ALL_BYTES_USED;
                return;
            }

            if (state.isClean) {
                cleanState();
                G_io_apdu_buffer[(*tx)++] = R_ERR_NO_INIT_CANT_CONTINUE;
                return;
            }
        } else {
            cleanState();

            state.txnSizeBytes = ((p1 & 0b11111100) << 6) + p2;

            PRINTF("\n fasd %d", state.txnSizeBytes);

            if (145 > state.txnSizeBytes) {
                G_io_apdu_buffer[(*tx)++] = R_TXN_SIZE_TOO_SMALL;
                return;
            }
        }

        state.isClean = false;

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

void authAndSignTxnHandler(uint8_t p1, uint8_t p2, uint8_t *dataBuffer, uint16_t dataLength,
                volatile unsigned int *flags, volatile unsigned int *tx) {

    authAndSignTxnHandlerHelper(p1, p2, dataBuffer, dataLength, flags, tx);

    if (0 == ((*flags) & IO_ASYNCH_REPLY)) {
        G_io_apdu_buffer[(*tx)++] = 0x90;
        G_io_apdu_buffer[(*tx)++] = 0x00;
    }
}
