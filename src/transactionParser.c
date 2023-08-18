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

#include "ardor.h"
#include "returnValues.h"
#include "transactionParser.h"

#define TX_TIMESTAMP_SIZE 4
#define TX_TIMESTAMP_DEADLINE 2
#define TX_PUBLIC_KEY_SIZE 32

// returns the txn type at the given index
txnType* txnTypeAtIndex(const uint8_t index) {
    return (txnType*) PIC(&TXN_TYPES[index]);
}

// returns the txn type name at the given index
char* txnTypeNameAtIndex(const uint8_t index) {
    return (char*) PIC(((txnType*) PIC(&TXN_TYPES[index]))->name);
}

char* appendageTypeName(const uint8_t index) {
    return (char*) PIC(((appendageType*) PIC(&APPENDAGE_TYPES[index]))->name);
}

// adds a parsing function to the top of the stack
uint8_t addToFunctionStack(const uint8_t functionNum) {
    if (sizeof(state.txnAuth.functionStack) == state.txnAuth.numFunctionsOnStack) {
        return R_FUNCTION_STACK_FULL;
    }

    state.txnAuth.functionStack[state.txnAuth.numFunctionsOnStack++] = functionNum;

    return R_SUCCESS;
}

// Takes bytes away from the buffer, returns 0 if there aren't enough bytes
uint8_t* readFromBuffer(const uint8_t size) {
    if (size > state.txnAuth.readBufferEndPos - state.txnAuth.readBufferReadOffset) {
        return 0;
    }

    uint8_t* ret = state.txnAuth.readBuffer + state.txnAuth.readBufferReadOffset;
    state.txnAuth.readBufferReadOffset += size;
    state.txnAuth.numBytesRead += size;

    return ret;
}

// PARSE_FN_MAIN 1
// This is the main parse function, it parses the main tx body and adds more functions to the parse
// stack if needed
uint8_t parseMainTxnData() {
    uint8_t* ptr = readFromBuffer(BASE_TRANSACTION_SIZE);

    if (0 == ptr) {
        return R_SEND_MORE_BYTES;
    }

    memmove(&(state.txnAuth.chainId), ptr, sizeof(state.txnAuth.chainId));

    ptr += sizeof(state.txnAuth.chainId);

    // note: ardor chain index starts with index 1
    if ((0 == state.txnAuth.chainId) || (NUM_CHAINS < state.txnAuth.chainId)) {
        return R_BAD_CHAIN_ID_ERR;
    }

    memmove(&(state.txnAuth.txnTypeAndSubType), ptr, sizeof(state.txnAuth.txnTypeAndSubType));

    ptr += sizeof(state.txnAuth.txnTypeAndSubType);

    txnType* currentTxnType = 0;

    for (state.txnAuth.txnTypeIndex = 0; state.txnAuth.txnTypeIndex < LEN_TXN_TYPES;
         state.txnAuth.txnTypeIndex++) {
        currentTxnType = txnTypeAtIndex(state.txnAuth.txnTypeIndex);

        if (currentTxnType->id == state.txnAuth.txnTypeAndSubType) {
            break;
        }
    }

    if (LEN_TXN_TYPES > state.txnAuth.txnTypeIndex &&
        0 != currentTxnType->attachmentParsingFunctionNumber) {
        addToFunctionStack(currentTxnType->attachmentParsingFunctionNumber);
    }

    // general blind signing check, functions without specific parsing are marked as blind signing
    // except payments which don't require special parsing
    if (0 == currentTxnType->attachmentParsingFunctionNumber &&
        0x0000 != state.txnAuth.txnTypeAndSubType && 0x00fe != state.txnAuth.txnTypeAndSubType) {
        state.txnAuth.requiresBlindSigning = true;
    }

    if (LEN_TXN_TYPES > state.txnAuth.txnTypeIndex) {
        snprintf(state.txnAuth.chainAndTxnTypeText,
                 sizeof(state.txnAuth.chainAndTxnTypeText),
                 "%s\n%s",
                 chainName(state.txnAuth.chainId),
                 txnTypeNameAtIndex(state.txnAuth.txnTypeIndex));
    } else {
        snprintf(state.txnAuth.chainAndTxnTypeText,
                 sizeof(state.txnAuth.chainAndTxnTypeText),
                 "%s\nUnknownTxnType",
                 chainName(state.txnAuth.chainId));
        state.txnAuth.requiresBlindSigning = true;
    }

    if (SUPPORTED_TXN_VERSION != *((uint8_t*) ptr)) {
        return R_WRONG_VERSION_ERR;
    }

    ptr += sizeof(uint8_t);

    ptr += TX_TIMESTAMP_SIZE;      // Skip the timestamp
    ptr += TX_TIMESTAMP_DEADLINE;  // Skip the deadline
    ptr += TX_PUBLIC_KEY_SIZE;     // Skip the sender publickey

    memmove(&(state.txnAuth.recipientId), ptr, sizeof(state.txnAuth.recipientId));
    ptr += sizeof(state.txnAuth.recipientId);

    memmove(&(state.txnAuth.amount), ptr, sizeof(state.txnAuth.amount));
    ptr += sizeof(state.txnAuth.amount);

    uint64_t fee = 0;
    memmove(&fee, ptr, sizeof(fee));

    uint8_t ret = formatAmount(state.txnAuth.feeText,
                               sizeof(state.txnAuth.feeText),
                               fee,
                               chainNumDecimalsBeforePoint(state.txnAuth.chainId));

    if (0 == ret) {
        return R_FORMAT_FEE_ERR;
    }

    snprintf(state.txnAuth.feeText + ret - 1,
             sizeof(state.txnAuth.feeText) - ret - 1,
             " %s",
             chainName(state.txnAuth.chainId));

    /* Comment unnecessary pointer movement over the last fields. Keeping for future reference.
    ptr += sizeof(uint64_t);

    ptr += 64;  //Skip the sig
    ptr += 4;   //Skip the block height
    ptr += 8;   //Skip the block Id
    */

    addToFunctionStack(PARSE_FN_IGNORE_BYTES_UNTIL_THE_END);

    return R_SUCCESS;
}

// PARSE_FN_APPENDAGES_FLAGS 2
/**
 * Parses the appendage type flag and prepares the text to show the user.
 * This function is added to the function stack on init.
 *
 * Current known appendages types:
 *      MessageAppendix = 1
 *      EncryptedMessageAppendix = 2
 *      EncryptToSelfMessageAppendix = 4
 *      PrunablePlainMessageAppendix = 8
 *      PrunableEncryptedMessageAppendix = 16
 *      PublicKeyAnnouncementAppendix = 32
 *      PhasingAppendix = 64
 */
uint8_t parseAppendagesFlags() {
    uint8_t* buffPtr = readFromBuffer(sizeof(uint32_t));

    if (0 == buffPtr) {
        return R_SEND_MORE_BYTES;
    }

    uint32_t appendages = 0;

    memmove(&appendages, buffPtr, sizeof(appendages));

    if (0 != appendages) {
        state.txnAuth.requiresBlindSigning = true;

        // fallback to hex string if we found unknown appendages
        if (appendages >= 1 << NUM_APPENDAGE_TYPES) {
            snprintf(state.txnAuth.appendagesText,
                     sizeof(state.txnAuth.appendagesText),
                     "0x%08X",
                     appendages);
        } else {
            char* ptr = state.txnAuth.appendagesText;
            size_t free = sizeof(state.txnAuth.appendagesText);
            for (uint8_t j = 0; j < NUM_APPENDAGE_TYPES; j++) {
                if (0 != (appendages & 1 << j)) {
                    size_t len = strlen(appendageTypeName(j));

                    // special case: not enough space to show the text for all appendages, revert to
                    // bitmap
                    if (free < len + 2) {  // +2 for separator and null terminator
                        for (uint8_t i = 0; i < NUM_APPENDAGE_TYPES; i++) {
                            state.txnAuth.appendagesText[i] =
                                (appendages & 1 << i) != 0 ? '1' + i : '_';
                        }
                        state.txnAuth.appendagesText[NUM_APPENDAGE_TYPES] = '\0';
                        return R_SUCCESS;
                    }

                    snprintf(ptr,
                             free,
                             ptr == state.txnAuth.appendagesText ? "%s" : "\n%s",
                             appendageTypeName(j));
                    ptr += ptr == state.txnAuth.appendagesText ? len : len + 1;
                    free -= ptr == state.txnAuth.appendagesText ? len : len + 1;
                }
            }
        }
    }

    return R_SUCCESS;
}

// PARSE_FN_REFERENCED_TXN 3
// Parses a txn reference, by just skiping over the bytes :)
uint8_t parseReferencedTxn() {
    state.txnAuth.requiresBlindSigning = true;
    if (0 == readFromBuffer(sizeof(uint32_t) + 32)) {
        return R_SEND_MORE_BYTES;
    }

    return R_SUCCESS;
}

// PARSE_FN_FXT_COIN_EXCHANGE_ORDER_ISSUE_OR_COIN_EXCHANGE_ORDER_ISSUE_ATTACHMENT 4
// Parses a specific type of attachment
uint8_t parseFxtCoinExchangeOrderIssueOrCoinExchangeOrderIssueAttachment() {
    state.txnAuth.attachmentInt32Num1 = 0;  // chainId
    state.txnAuth.attachmentInt32Num2 = 0;  // exchangeChain
    state.txnAuth.attachmentInt64Num1 = 0;  // quantity
    state.txnAuth.attachmentInt64Num2 = 0;  // price

    uint8_t* ptr = readFromBuffer(sizeof(uint8_t) + sizeof(state.txnAuth.attachmentInt32Num1) * 2 +
                                  sizeof(state.txnAuth.attachmentInt64Num1) * 2);
    if (0 == ptr) {
        return R_SEND_MORE_BYTES;
    }

    if (1 != *ptr) {
        return R_UNSUPPORTED_ATTACHMENT_VERSION;
    }

    ptr += 1;

    memmove(&state.txnAuth.attachmentInt32Num1, ptr, sizeof(state.txnAuth.attachmentInt32Num1));
    ptr += sizeof(state.txnAuth.attachmentInt32Num1);

    if (NUM_CHAINS < state.txnAuth.attachmentInt32Num1 || 1 > state.txnAuth.attachmentInt32Num1) {
        return R_BAD_CHAIN_ID_ERR;
    }

    memmove(&state.txnAuth.attachmentInt32Num2, ptr, sizeof(state.txnAuth.attachmentInt32Num2));
    ptr += sizeof(state.txnAuth.attachmentInt32Num2);

    if (NUM_CHAINS < state.txnAuth.attachmentInt32Num2 || 1 > state.txnAuth.attachmentInt32Num2) {
        return R_BAD_CHAIN_ID_ERR;
    }

    memmove(&state.txnAuth.attachmentInt64Num1, ptr, sizeof(state.txnAuth.attachmentInt64Num1));
    ptr += sizeof(state.txnAuth.attachmentInt64Num1);

    memmove(&state.txnAuth.attachmentInt64Num2, ptr, sizeof(state.txnAuth.attachmentInt64Num2));

    return R_SUCCESS;
}

// PARSE_FN_ASK_ORDER_PLACEMENT_ATTACHMENT 5
// Parses a specific type of attachment
uint8_t parseAskOrderPlacementAttachment() {
    state.txnAuth.attachmentInt64Num1 = 0;  // assetId
    state.txnAuth.attachmentInt64Num2 = 0;  // quantityQNT
    state.txnAuth.attachmentInt64Num3 = 0;  // priceNQT

    uint8_t* ptr = readFromBuffer(sizeof(state.txnAuth.attachmentInt64Num1) * 3);
    if (0 == ptr) {
        return R_SEND_MORE_BYTES;
    }

    memmove(&state.txnAuth.attachmentInt64Num1, ptr, sizeof(state.txnAuth.attachmentInt64Num1));
    ptr += sizeof(state.txnAuth.attachmentInt64Num1);

    memmove(&state.txnAuth.attachmentInt64Num2, ptr, sizeof(state.txnAuth.attachmentInt64Num2));
    ptr += sizeof(state.txnAuth.attachmentInt64Num2);

    memmove(&state.txnAuth.attachmentInt64Num3, ptr, sizeof(state.txnAuth.attachmentInt64Num3));

    return R_SUCCESS;
}

// PARSE_FN_IGNORE_BYTES_UNTIL_THE_END 6
// Parses all the bytes until the endof the txn, since we don't parse the specifics of all the
// types, sometimes this is needed
uint8_t parseIgnoreBytesUntilTheEnd() {
    while (state.txnAuth.numBytesRead != state.txnAuth.txnSizeBytes) {
        uint8_t* ptr = readFromBuffer(1);
        if (0 == ptr) {
            return R_SEND_MORE_BYTES;
        }
        if (0 != *ptr) {
            state.txnAuth.requiresBlindSigning = true;
        }
    }

    return R_SUCCESS;
}

// PARSE_FN_ASSET_TRANSFER_ATTACHMENT 7
uint8_t parseAssetTransferAttachment() {
    state.txnAuth.attachmentInt64Num1 = 0;  // asset id
    state.txnAuth.attachmentInt64Num2 = 0;  // quantity

    uint8_t* ptr = readFromBuffer(sizeof(state.txnAuth.attachmentInt64Num1) * 2);
    if (0 == ptr) {
        return R_SEND_MORE_BYTES;
    }

    if (1 != *ptr) {
        return R_UNSUPPORTED_ATTACHMENT_VERSION;
    }

    ptr += 1;  // skip version byte

    memmove(&state.txnAuth.attachmentInt64Num1, ptr, sizeof(state.txnAuth.attachmentInt64Num1));
    ptr += sizeof(state.txnAuth.attachmentInt64Num1);

    memmove(&state.txnAuth.attachmentInt64Num2, ptr, sizeof(state.txnAuth.attachmentInt64Num2));

    return R_SUCCESS;
}

// Addes bytes to the read buffer
//@param newData: ptr to the data
//@param numBytes: number of bytes in the data
// return R_SUCCESS on success, R_NO_SPACE_BUFFER_TOO_SMALL othereize
uint8_t addToReadBuffer(const uint8_t* const newData, const uint8_t numBytes) {
    uint16_t offset = state.txnAuth.readBufferReadOffset;
    for (uint16_t i = 0; i < state.txnAuth.readBufferEndPos - offset; i++) {
        state.txnAuth.readBuffer[i] = state.txnAuth.readBuffer[i + offset];
    }

    memset(state.txnAuth.readBuffer + state.txnAuth.readBufferEndPos - offset, 0, offset);

    state.txnAuth.readBufferEndPos -= offset;
    state.txnAuth.readBufferReadOffset = 0;

    if (sizeof(state.txnAuth.readBuffer) < state.txnAuth.readBufferEndPos + numBytes) {
        return R_NO_SPACE_BUFFER_TOO_SMALL;
    }

    cx_hash_no_throw(&state.txnAuth.hashstate.header, 0, newData, numBytes, 0, 0);

    memcpy(state.txnAuth.readBuffer + state.txnAuth.readBufferEndPos, newData, numBytes);
    state.txnAuth.readBufferEndPos += numBytes;

    return R_SUCCESS;
}

// Since we can't store function pointers in the functionstack, we store number and then call the
// following function to make a call to the corresponding function
uint8_t callFunctionNumber(const uint8_t functionNum) {
    switch (functionNum) {
        case PARSE_FN_MAIN:
            return parseMainTxnData();
        case PARSE_FN_APPENDAGES_FLAGS:
            return parseAppendagesFlags();
        case PARSE_FN_REFERENCED_TXN:
            return parseReferencedTxn();
        case PARSE_FN_FXT_COIN_EXCHANGE_ORDER_ISSUE_OR_COIN_EXCHANGE_ORDER_ISSUE_ATTACHMENT:
            return parseFxtCoinExchangeOrderIssueOrCoinExchangeOrderIssueAttachment();
        case PARSE_FN_ASK_ORDER_PLACEMENT_ATTACHMENT:
            return parseAskOrderPlacementAttachment();
        case PARSE_FN_IGNORE_BYTES_UNTIL_THE_END:
            return parseIgnoreBytesUntilTheEnd();
        case PARSE_FN_ASSET_TRANSFER_ATTACHMENT:
            return parseAssetTransferAttachment();
    }

    return R_PARSE_FUNCTION_NOT_FOUND;
}

// This function manages the parsing of the readBuffer with functionStack functions
// If there aren't enough bytes in the read buffer it returns R_SEND_MORE_BYTES
// which will be sent back to the user
uint8_t parseTransaction(uint8_t (*setScreenTexts)(), void (*showScreen)()) {
    while (true) {
        if (0 == state.txnAuth.numFunctionsOnStack) {
            if (state.txnAuth.readBufferEndPos != state.txnAuth.readBufferReadOffset) {
                return R_NOT_ALL_BYTES_READ;
            }

            uint8_t ret = (*setScreenTexts)();

            if (R_SUCCESS != ret) {
                return ret;
            }

            (*showScreen)();

            return R_SHOW_DISPLAY;
        }

        uint8_t ret = callFunctionNumber(state.txnAuth.functionStack[0]);

        if (R_SEND_MORE_BYTES == ret) {
            return ret;
        }

        uint8_t tempBuffer[FUNCTION_STACK_SIZE - 1];
        memmove(tempBuffer, state.txnAuth.functionStack + 1, sizeof(tempBuffer));
        memmove(state.txnAuth.functionStack, tempBuffer, sizeof(tempBuffer));
        state.txnAuth.functionStack[sizeof(state.txnAuth.functionStack) - 1] = 0;
        state.txnAuth.numFunctionsOnStack--;

        if (R_SUCCESS == ret) {
            continue;
        }

        return ret;
    }
}
