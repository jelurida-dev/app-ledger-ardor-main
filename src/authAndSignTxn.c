/*******************************************************************************
*  (c) 2019 Haim Bender
*  (c) 2021-2023 Jelurida IP B.V.
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

#include <cx.h>
#include <os.h>

#include "glyphs.h"
#include "returnValues.h"
#include "config.h"
#include "ardor.h"
#include "reedSolomon.h"
#include "transactionParser.h"
#include "ui/menu.h"
#include "ui/display.h"

#define P1_INIT 1
#define P1_CONTINUE 2
#define P1_SIGN 3

// This is the code that parses the txn for signing, it parses streamed txn bytes into the state object while hashing the bytes to be signed later,
// displays a dialog of screens which contain the parsed txn bytes from the state, 
// It solves 2 no trivial problems
// 1 - Allowing txn bytes to be parsed from a stream of bytes (this is very hard, since we don't have a lot memory, so we need to parse bytes and forget about them)
// 2 - txn's very in length depending on type, so the same bytes are sometimes not parsed into the same place, so it has to be dynamic about parsing
//
//
// The way these problems are solved is by the following flow:
//
// The function stack is initiated with an index reference to parseMainTxnData
// 
//
// authAndSignTxnHandlerHelper is called with some of the txn bytes
// => addToReadBuffer is called adds these bytes to the read buffer
// => parseTransaction is called, which calls the first parse function on the stack which is parseMainTxnData
// => parseMainTxnData trys to pull 142 bytes from the buffer
//      if there is are 142 bytes there:
//          parseMainTxnData parses the main txn bytes and then adds more functions to parse stack depending on the appendages
//      else
//          R_SEND_MORE_BYTES is trickled down by the function to be sent to back to the client
//      
// and so on the process goes until the stack of functions is empty and there are no more bytes in the read buffer
// if the parsing goes well without errors => setScreenTexts(); is called which sets up the labels and first screen of the autherization dialog
// => showScreen(); make the first screen apeare setting and sets ui_auth_button() to be the button callback for the dialog =>
// pressing on the right does state.txnAuth.dialogScreenIndex++; if it reaches the end number then the txn is autherized for signing and state.txnAuth.txnPassedAutherization is set to true
// pressing left does state.txnAuth.dialogScreenIndex--; and if it gets to a negative number it will be interpretate as a txn rejection => initTxnAuthState() 
// will be called and R_REJECT will be returned to client


//  API:
//
//
//      The mode is encoded in the first 2 bits of the p1 parameter and the size of the txn should be ((p1 & 0b11111100) << 6) + p2
//      you only need to pass the size when calling P1_INIT
//
//      P1: P1_INIT:
//      dataBuffer: txn bytes //you can send all of your bytes here if you want
//      returns:    1 byte status
//
//      P1: P1_CONTINUE:    more txn bytes
//      returns:    1 byte status
//
//      P1: P1_SIGN:
//      dataBuffer: derivaiton path (uint32) * some length
//      returns:    1 bytes status | 64 byte signiture


//This function cleans the state, its important to call it before starting to load a txn
//also whenever there is an error you should call it so that no one can exploit an error state for 
//some sort of attack, the cleaner the state is, the better, always clean when you can
void initTxnAuthState() {
    memset(&state, 0, sizeof(state));

    state.txnAuth.functionStack[0] = PARSE_FN_MAIN; //Add the first parse function on the stack
    state.txnAuth.functionStack[1] = PARSE_FN_APPENDAGES_FLAGS; //The appendages parse function
    state.txnAuth.numFunctionsOnStack = 2;

    state.txnAuth.isClean = true;
    
    cx_sha256_init(&state.txnAuth.hashstate);
}

//Accept click callback
void signTransactionConfirm() {
    state.txnAuth.txnPassedAutherization = true;
    G_io_apdu_buffer[0] = R_SUCCESS;
    G_io_apdu_buffer[1] = R_FINISHED;
    G_io_apdu_buffer[2] = 0x90;
    G_io_apdu_buffer[3] = 0x00;
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 4);
}

//Canceled click callback
void signTransactionCancel() {  
    initTxnAuthState();

    G_io_apdu_buffer[0] = R_SUCCESS;
    G_io_apdu_buffer[1] = R_REJECT;
    G_io_apdu_buffer[2] = 0x90;
    G_io_apdu_buffer[3] = 0x00;
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 4);
}

//This function formats trxn data into text memebers of the state which the UI flow will read from
//Returns: Success iff everything is good, otherwise probably some kind of formating error
uint8_t setScreenTexts() {

    uint8_t ret = 0;

    if (LEN_TXN_TYPES > state.txnAuth.txnTypeIndex) {

        switch (state.txnAuth.txnTypeAndSubType) {

            case TX_TYPE_ORDINARY_PAYMENT:
            case TX_TYPE_FXT_PAYMENT:

                    state.txnAuth.uiFlowBitfeild |= 2; //turn on the second bit for optional 1 & 2

                    snprintf(state.txnAuth.optionalWindow1Title, sizeof(state.txnAuth.optionalWindow1Title), "Amount");

                    if (0 == formatAmount(state.txnAuth.optionalWindow1Text, sizeof(state.txnAuth.optionalWindow1Text), state.txnAuth.amount, chainNumDecimalsBeforePoint(state.txnAuth.chainId)))
                        return R_FORMAT_AMOUNT_ERR;

                    snprintf(state.txnAuth.optionalWindow2Title, sizeof(state.txnAuth.optionalWindow2Title), "Recipient");
                    snprintf(state.txnAuth.optionalWindow2Text, sizeof(state.txnAuth.optionalWindow2Text), APP_PREFIX);
                    reedSolomonEncode(state.txnAuth.recipientId, state.txnAuth.optionalWindow2Text + strlen(state.txnAuth.optionalWindow2Text));

                    break;

            case TX_TYPE_FXT_COIN_EXCHANGE_ORDER_ISSUE:
            case TX_TYPE_COIN_EXCHANGE_ORDER_ISSUE:
                    
                    state.txnAuth.uiFlowBitfeild |= 2; //turn on the second bit for optional 1 & 2


                    snprintf(state.txnAuth.optionalWindow1Title, sizeof(state.txnAuth.optionalWindow1Title), "Amount");

                    ret = formatAmount(state.txnAuth.optionalWindow1Text, sizeof(state.txnAuth.optionalWindow1Text), state.txnAuth.attachmentTempInt64Num1, chainNumDecimalsBeforePoint(state.txnAuth.attachmentTempInt32Num2));

                    if (0 == ret)
                        return R_FORMAT_AMOUNT_ERR;

                    //note: the existence of chainName(state.txnAuth.attachmentTempInt32Num2) was already checked in the parsing function
                    snprintf(state.txnAuth.optionalWindow1Text + ret - 1, sizeof(state.txnAuth.optionalWindow1Text) - ret - 1, " %s", chainName(state.txnAuth.attachmentTempInt32Num2));

                    //note: the existence of chainName(state.txnAuth.attachmentTempInt32Num2) was already checked in the parsing function
                    snprintf(state.txnAuth.optionalWindow2Title, sizeof(state.txnAuth.optionalWindow2Title), "Price per %s", chainName(state.txnAuth.attachmentTempInt32Num2));
                    ret = formatAmount(state.txnAuth.optionalWindow2Text, sizeof(state.txnAuth.optionalWindow2Text), state.txnAuth.attachmentTempInt64Num2, chainNumDecimalsBeforePoint(state.txnAuth.attachmentTempInt32Num1));

                    if (0 == ret)
                        return R_FORMAT_AMOUNT_ERR;

                    //note: the existence of chainName(state.txnAuth.attachmentTempInt32Num1) was already checked in the parsing function
                    snprintf(state.txnAuth.optionalWindow2Text + ret - 1, sizeof(state.txnAuth.optionalWindow2Text) - ret - 1, " %s", chainName(state.txnAuth.attachmentTempInt32Num1));

                    break;

            case TX_TYPE_ASSET_TRANSFER:

                    state.txnAuth.uiFlowBitfeild |= 6; // turn bits 2&3 for all three optional screens

                    snprintf(state.txnAuth.optionalWindow1Title, sizeof(state.txnAuth.optionalWindow1Title), "Asset Id");
                    formatAmount(state.txnAuth.optionalWindow1Text, sizeof(state.txnAuth.optionalWindow1Text), state.txnAuth.attachmentTempInt64Num1, 0);

                    snprintf(state.txnAuth.optionalWindow2Title, sizeof(state.txnAuth.optionalWindow2Title), "Quantity QNT");
                    formatAmount(state.txnAuth.optionalWindow2Text, sizeof(state.txnAuth.optionalWindow2Text), state.txnAuth.attachmentTempInt64Num2, 0);

                    snprintf(state.txnAuth.optionalWindow3Title, sizeof(state.txnAuth.optionalWindow3Title), "Recipient");
                    snprintf(state.txnAuth.optionalWindow3Text, sizeof(state.txnAuth.optionalWindow3Text), APP_PREFIX);
                    reedSolomonEncode(state.txnAuth.recipientId, state.txnAuth.optionalWindow3Text + strlen(state.txnAuth.optionalWindow3Text));
                    break;
        }
    }

    return R_SUCCESS;
}

//This is the function used to sign the hash of the txn
//@param txnSha256 -                     ptr to 32 byte sha256 of the txn
//@param derivationPath -                ptr to the derivation path buffer
//@param derivationPathLengthInUints32 - length of the derivation path buffer
//@param destBuffer -                    ptr to 64 bytes of memory of where to write the buffer
//@param outException out -              ptr to where to write the exception if it happends
//@returns R_SUCCESS iff success else the appropriate error code is returned

uint8_t signTxn(const uint8_t * const derivationPath, const uint8_t derivationPathLengthInUints32, 
                 uint8_t * const destBuffer, uint16_t * const outException) {

    uint8_t keySeed[32]; memset(keySeed, 0, sizeof(keySeed));
    uint8_t ret = 0;

    if (R_SUCCESS != (ret = ardorKeys(derivationPath, derivationPathLengthInUints32, keySeed, 0, 0, 0, outException))) {
        memset(keySeed, 0, sizeof(keySeed));
        return ret;
    }

    uint8_t finalTxnSha256[32];
    cx_hash(&state.txnAuth.hashstate.header, CX_LAST, 0, 0, finalTxnSha256, sizeof(finalTxnSha256));

    //sign msg should only use the first 32 bytes of keyseed
    signMsg(keySeed, finalTxnSha256, destBuffer); //is a void function, no ret value to check against
    
    memset(finalTxnSha256, 0, sizeof(finalTxnSha256)); //for security
    memset(keySeed, 0, sizeof(keySeed));

    return R_SUCCESS;
}

//// HANDLER MAIN FUNCTIONS

void p1InitContinueCommon(const uint8_t * const dataBuffer, const uint8_t dataLength, uint8_t * const flags, uint8_t * const tx) {
    state.txnAuth.isClean = false;

    uint8_t ret = addToReadBuffer(dataBuffer, dataLength);

    if (R_SUCCESS != ret) {
        G_io_apdu_buffer[(*tx)++] = ret;
        return;
    }

    ret = parseTransaction(&setScreenTexts, &signTransactionScreen);

    if (!((R_SEND_MORE_BYTES == ret) || (R_FINISHED == ret) || (R_SHOW_DISPLAY == ret)))
        initTxnAuthState();

    if (R_SHOW_DISPLAY == ret) {
        *flags |= IO_ASYNCH_REPLY;
    } else {
        G_io_apdu_buffer[(*tx)++] = R_SUCCESS;
        G_io_apdu_buffer[(*tx)++] = ret;
    }
}

void p1InitHandler(const uint8_t p1, const uint8_t p2, const uint8_t * const dataBuffer, const uint8_t dataLength, uint8_t * const flags, uint8_t * const tx) {
    initTxnAuthState();

    state.txnAuth.txnSizeBytes = ((p1 & 0b11111100) << 6) + p2;

    if (BASE_TRANSACTION_SIZE > state.txnAuth.txnSizeBytes) {
        G_io_apdu_buffer[(*tx)++] = R_TXN_SIZE_TOO_SMALL;
        return;
    }

    p1InitContinueCommon(dataBuffer, dataLength, flags, tx);
}

void p1ContinueHandler(const uint8_t * const dataBuffer, const uint8_t dataLength, uint8_t * const flags, uint8_t * const tx, const bool isLastCommandDifferent) {
    if (isLastCommandDifferent) {
        initTxnAuthState();
        G_io_apdu_buffer[(*tx)++] = R_ERR_NO_INIT_CANT_CONTINUE;
        return;
    }

    if (state.txnAuth.txnPassedAutherization) {
        initTxnAuthState();
        G_io_apdu_buffer[(*tx)++] = R_NOT_ALL_BYTES_USED;
        return;
    }

    if (state.txnAuth.isClean) {
        initTxnAuthState();
        G_io_apdu_buffer[(*tx)++] = R_ERR_NO_INIT_CANT_CONTINUE;
        return;
    }

    p1InitContinueCommon(dataBuffer, dataLength, flags, tx);
}

void p1SignHandler(const uint8_t * const dataBuffer, const uint8_t dataLength, uint8_t * const tx, const bool isLastCommandDifferent) {
    if (isLastCommandDifferent) {
        initTxnAuthState();
        G_io_apdu_buffer[(*tx)++] = R_TXN_UNAUTHORIZED;
        return;
    }

    // dataLength is the derivation path length in bytes
    if ((MIN_DERIVATION_LENGTH * sizeof(uint32_t) > dataLength) || (MAX_DERIVATION_LENGTH * sizeof(uint32_t) < dataLength) || (0 != dataLength % sizeof(uint32_t))) {
        initTxnAuthState();
        G_io_apdu_buffer[(*tx)++] = R_WRONG_SIZE_ERR;
        return; 
    }

    if (!state.txnAuth.txnPassedAutherization) {
        initTxnAuthState();
        G_io_apdu_buffer[(*tx)++] = R_TXN_UNAUTHORIZED;
        return;
    }

    uint16_t exception = 0;

    G_io_apdu_buffer[(*tx)++] = R_SUCCESS;

    uint8_t ret = signTxn(dataBuffer, dataLength / 4, G_io_apdu_buffer + 1, &exception);

    initTxnAuthState();

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
}

//This is the main command handler, it checks that params are in the right size,
//and manages calls to initTxnAuthState(), signTxn(), addToReadBuffer(), parseTransaction()
//Since this is a callback function, and this handler manages state, it's this function's reposibility to call initTxnAuthState
//Every time we get some sort of an error
void authAndSignTxnHandlerHelper(const uint8_t p1, const uint8_t p2, const uint8_t * const dataBuffer, const uint8_t dataLength,
        uint8_t * const flags, uint8_t * const tx, const bool isLastCommandDifferent) {

    if (1 > dataLength) {
        initTxnAuthState();
        G_io_apdu_buffer[(*tx)++] = R_WRONG_SIZE_ERR;
    } else if (P1_INIT == (p1 & 0x03)) {
        p1InitHandler(p1, p2, dataBuffer, dataLength, flags, tx);
    } else if (P1_CONTINUE == (p1 & 0x03)) {
        p1ContinueHandler(dataBuffer, dataLength, flags, tx, isLastCommandDifferent);
    } else if (P1_SIGN == (p1 & 0x03)) {
        p1SignHandler(dataBuffer, dataLength, tx, isLastCommandDifferent);
    } else {
        G_io_apdu_buffer[(*tx)++] = R_UNKNOWN_CMD_PARAM_ERR;
    }
}

void authAndSignTxnHandler(const uint8_t p1, const uint8_t p2, const uint8_t * const dataBuffer, const uint8_t dataLength,
        uint8_t * const flags, uint8_t * const tx, const bool isLastCommandDifferent) {

    authAndSignTxnHandlerHelper(p1, p2, dataBuffer, dataLength, flags, tx, isLastCommandDifferent);

    if (0 == ((*flags) & IO_ASYNCH_REPLY)) {
        G_io_apdu_buffer[(*tx)++] = 0x90;
        G_io_apdu_buffer[(*tx)++] = 0x00;
    }
}
