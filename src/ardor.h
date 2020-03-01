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

uint64_t publicKeyToId(const uint8_t * const publicKey);
uint8_t ardorKeys(const uint32_t * derivationPath, const uint8_t derivationPathLengthInUints32, 
                            uint8_t *keySeedBfrOut, uint8_t *publicKeyCurveOut, uint8_t * publicKeyEd25519Out, uint8_t * chainCodeOut, uint16_t * exceptionOut);

void signMsg(uint8_t * const keySeedBfr, const uint8_t * const msgSha256, uint8_t * const sig);


unsigned int makeTextGoAround_preprocessor(bagl_element_t * const element);
bool check_canary();

uint8_t getSharedEncryptionKey(const uint32_t * const derivationPath, const uint8_t derivationPathLengthInUints32, const uint8_t* const targetPublicKey, 
                                const uint8_t * const nonce, uint16_t * const exceptionOut, uint8_t * const aesKeyOut);


//This is the state object that authAndSignTxn uses
typedef struct {

	bool txnPassedAutherization;                           //This most important bool, means the user confirmed the txn content via the dialog and we can sign the current TXN

    uint8_t readBuffer[512];                               //This is where unparsed temp buffer data is kept, since we do streamed parsing we have to have it here
    uint16_t readBufferEndPos;                             //Index of the last byte in readBuffer
    uint16_t readBufferReadOffset;                         //Index of the first byte in readBuffer
    uint16_t numBytesRead;                                 //The total number of bytes parsed up until now

    uint8_t functionStack[FUNCTION_STACK_SIZE];            //This is stack of all the function that have yet to parse the TXN, the C handler file explains this process in more detail
    uint8_t numFunctionsOnStack;                           //Is what it says

    bool isClean;                                          //If the state was just initilized


    char displayTitle[64];                              //The title in the autherization dialog
    char displaystate[130];                             //The content line in the autherization dialog
    
    cx_sha256_t hashstate;                                 //The state of the hash for the txn buffer

    uint32_t chainId;                                      //What it says it is
    uint16_t txnTypeAndSubType;                            //What it says it is
    uint8_t txnTypeIndex;                                  //txnTypeAndSubType's index in TXN_TYPES

    uint8_t version;                                       //the txn version
    uint64_t recipientId;                                  //the recipient address ID
    uint64_t amount;                                       //the amount to be sent in the txn, note that every chain parses this number differently, it dives this number by some 10^X
    uint64_t fee;                                          //What it says it is
    uint32_t appendagesFlags;                              //What it says it is
    
    uint8_t displayType;                                   //If this is a first, middle or last display in the dialog sequence
    int8_t dialogScreenIndex;                              //The window index in the currently showing dialog


   	int32_t attachmentTempInt32Num1, attachmentTempInt32Num2;    //Different attachments parse in different ways, they all need space in state, so this is how it's defined
   	int64_t attachmentTempInt64Num1, attachmentTempInt64Num2, attachmentTempInt64Num3; 

   	uint16_t txnSizeBytes;                                 //The decalred Txn size

} authTxn_t;

//State for the encryptDecrypt handler
typedef struct {
    uint8_t mode;                           //Modes are described in the .C file
    uint8_t cbc[16];                        //Something to do with AES state
    unsigned int ctx[(4 * 4 * 15 + 4) / sizeof(unsigned int)];      //This is the encryption key, unsigned int is the type it uses aes_uint *
} encyptionState_t;

//State of the sign token handler
typedef struct {
    uint8_t mode;                           //Modes descrived in the .C file
    cx_sha256_t sha256;                     //The state of the token hash
} signTokenState_t;

//This is the union states type, the actual object is defined in ardor.c
typedef union {
    encyptionState_t encryption;
    authTxn_t txnAuth;
    signTokenState_t tokenCreation;
} states_t;

//declared in ardor.c
extern states_t state;

//used to list txn types
typedef struct {
    uint16_t id;
    char * name;
    uint8_t attachmentParsingFunctionNumber;
} txnType;


//These to are automaticly generated by createTxnTypes.py into src/txnTypeLists.c
extern const txnType TXN_TYPES[];
extern const uint8_t LEN_TXN_TYPES;

// These are the offsets of various parts of a request APDU packet. INS
// identifies the requested command (see above), and P1 and P2 are parameters
// to the command.
#define CLA          0xE0
#define OFFSET_CLA   0x00
#define OFFSET_INS   0x01
#define OFFSET_P1    0x02
#define OFFSET_P2    0x03
#define OFFSET_LC    0x04
#define OFFSET_CDATA 0x05
