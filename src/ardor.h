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

#pragma once

#include "cx.h"
#include "os.h"
#include "config.h"

uint64_t publicKeyToId(const uint8_t* const publicKey);

uint8_t ardorKeys(const uint8_t* const derivationPath,
                  const uint8_t derivationPathLengthInUints32,
                  uint8_t* const keySeedBfrOut,
                  uint8_t* const publicKeyCurveXout,
                  uint8_t* const publicKeyEd25519YLEWithXParityOut,
                  uint8_t* const chainCodeOut,
                  uint16_t* const exceptionOut);

char* chainName(const uint8_t chainId);

void signMsg(uint8_t* const keySeedBfr, const uint8_t* const msgSha256, uint8_t* const sig);

bool check_canary();

uint8_t getSharedEncryptionKey(const uint8_t* const derivationPath,
                               const uint8_t derivationPathLengthInUints32,
                               const uint8_t* const targetPublicKey,
                               const uint8_t* const nonce,
                               uint16_t* const exceptionOut,
                               uint8_t* const aesKeyOut);

// the amount of digits on the right of the decimal dot for each chain
uint8_t chainNumDecimalsBeforePoint(const uint8_t chainId);

uint8_t formatAmount(char* const outputString,
                     const uint16_t maxOutputLength,
                     uint64_t numberToFormat,
                     const uint8_t numDigitsBeforeDecimal);

// define max text sizes for the different UI screens
#define MAX_FEE_TEXT_SIZE \
    21                                       // 9,223,372,036,854,775,807 is the biggest number you
                                             // can hold in uint64 + the dot + null
#define MAX_CHAIN_AND_TXN_TYPE_TEXT_SIZE 60  // Aproximation of size
#define MAX_WIN1_TITLE_SIZE 9                // MAX("Amount","Asset Id")
#define MAX_WIN1_TEXT_SIZE 31                // same as fee text + name of the chain + space
#define MAX_WIN2_TITLE_SIZE 20               // The longest string is price per (chain name here)
#define MAX_WIN2_TEXT_SIZE 31                // MAX(Ardor arddress = 27, feeText + chainName)
#define MAX_WIN3_TITLE_SIZE 10               // MAX("Recipient")
#define MAX_WIN3_TEXT_SIZE 28                // MAX(Ardor arddress = 27)
#define MAX_APPENDAGES_TEXT_SIZE \
    60  // this should allow displaying the names for up to
        // three types, otherwise we show a bitmap

// This is the state object that authAndSignTxn uses
typedef struct {
    bool txnPassedAutherization;  // This most important bool, means the user confirmed the txn
                                  // content via the dialog and we can sign the current TXN

    uint8_t readBuffer[512];        // This is where unparsed temp buffer data is kept, since we do
                                    // streamed parsing we have to have it here
    uint16_t readBufferEndPos;      // Index of the last byte in readBuffer
    uint16_t readBufferReadOffset;  // Index of the first byte in readBuffer
    uint16_t numBytesRead;          // The total number of bytes parsed up until now

    uint8_t functionStack[FUNCTION_STACK_SIZE];  // This is stack of all the function that have yet
                                                 // to parse the TXN, the C handler file explains
                                                 // this process in more detail
    uint8_t numFunctionsOnStack;

    bool isClean;  // If the state was just initilized

    cx_sha256_t hashstate;  // The state of the hash for the txn buffer

    uint32_t chainId;
    uint16_t txnTypeAndSubType;
    uint8_t txnTypeIndex;  // txnTypeAndSubType's index in TXN_TYPES

    uint64_t recipientId;  // the recipient address ID
    uint64_t amount;  // the amount to be sent in the txn, note that every chain parses this number
                      // differently, it divides this number by some 10^X
    uint64_t fee;

    // Different attachments parse in different ways, they all need space in state, so this is how
    // it's defined
    uint32_t attachmentInt32Num1;  // chainId for FxtCoinExchangeOrderIssue,CoinExchangeOrderIssue
    uint32_t attachmentInt32Num2;  // chainId for FxtCoinExchangeOrderIssue,CoinExchangeOrderIssue
    uint64_t attachmentInt64Num1;  // amountQNT for FxtCoinExchangeOrderIssue,CoinExchangeOrderIssue
                                   // assetId for AssetTransfer,AskOrderPlacement
    uint64_t attachmentInt64Num2;  // price for FxtCoinExchangeOrderIssue,CoinExchangeOrderIssue
                                   // quantityQNT for AssetTransfer,AskOrderPlacement
    uint64_t attachmentInt64Num3;  // price for AskOrderPlacement

    uint16_t txnSizeBytes;  // The declared Txn size

    char feeText[MAX_FEE_TEXT_SIZE];
    char chainAndTxnTypeText[MAX_CHAIN_AND_TXN_TYPE_TEXT_SIZE];
    char optionalWindow1Title[MAX_WIN1_TITLE_SIZE];
    char optionalWindow1Text[MAX_WIN1_TEXT_SIZE];
    char optionalWindow2Title[MAX_WIN2_TITLE_SIZE];
    char optionalWindow2Text[MAX_WIN2_TEXT_SIZE];
    char optionalWindow3Title[MAX_WIN3_TITLE_SIZE];
    char optionalWindow3Text[MAX_WIN3_TEXT_SIZE];
    char appendagesText[MAX_APPENDAGES_TEXT_SIZE];
    uint8_t uiFlowBitField;  // This is a bit field for selecting the right UI flow

} authTxn_t;

#define MAX_CHUNK_SIZE_ENCRYPT 224

// State for the encryptDecrypt handler
typedef struct {
    uint8_t mode;                                // Modes are described in the .C file
    uint8_t cbc[CX_AES_BLOCK_SIZE];              // Something to do with AES state
    cx_aes_key_t aesKey;                         // This is the encryption key
    uint8_t buffer[MAX_CHUNK_SIZE_ENCRYPT + 1];  // +1 for R_SUCCESS at position 0
} encyptionState_t;

// State of the sign token handler
typedef struct {
    uint8_t mode;                           // Modes described in the .C file
    cx_sha256_t sha256;                     // The state of the token hash
    uint32_t timestamp;                     // The timestamp of the token
    uint8_t derivationPathLengthInUints32;  // The length of the derivation path
    uint8_t* ptrDerivationPath;             // The derivation path
    uint8_t token[101];                     // The 1 byte response code + token
    // 100-byte token consists of a 32-byte public key, a 4-byte timestamp, and a 64-byte signature
} signTokenState_t;

// This is the union states type, the actual object is defined in ardor.c
typedef union {
    encyptionState_t encryption;
    authTxn_t txnAuth;
    signTokenState_t tokenSign;
} states_t;

// declared in ardor.c
extern states_t state;

// used to list txn types
typedef struct {
    uint16_t id;
    const char* name;
    uint8_t attachmentParsingFunctionNumber;
} txnType;

// These to are automaticly generated by createTxnTypes.py into src/txnTypeLists.c
extern const txnType TXN_TYPES[];
extern const uint8_t LEN_TXN_TYPES;

// These are the offsets of various parts of a request APDU packet. INS
// identifies the requested command (see above), and P1 and P2 are parameters
// to the command.
#define CLA 0xE0
#define OFFSET_CLA 0x00
#define OFFSET_INS 0x01
#define OFFSET_P1 0x02
#define OFFSET_P2 0x03
#define OFFSET_LC 0x04
#define OFFSET_CDATA 0x05
