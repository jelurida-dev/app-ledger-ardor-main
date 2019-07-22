

void fillBufferWithAnswerAndEnding(uint8_t answer, uint8_t * tx);
uint8_t ardorKeys(const uint32_t * derivationPath, const uint8_t derivationPathLengthInUints32, 
                            uint8_t *keySeedBfrOut, uint8_t *publicKeyOut, uint8_t * chainCodeOut, uint16_t * exceptionOut);

#define FUNCTION_STACK_SIZE 30

typedef struct {

	bool txnPassedAutherization;

    uint8_t readBuffer[512];
    uint16_t readBufferEndPos;
    uint16_t readBufferReadOffset;

    uint8_t functionStack[FUNCTION_STACK_SIZE];
    uint8_t numFunctionsOnStack;

    bool isClean;


    uint8_t displayTitle[64];
    uint8_t displaystate[130]; //todo dont know if this is the best, maybe we can make it shorter?

    
    uint8_t tempBuffer[32];
    
    cx_sha256_t hashstate;
    uint8_t finalHash[32];

    uint32_t chainId;
    uint16_t transactionTypeAndSubType; //todo rename all of these to txn
    uint8_t txnTypeIndex;

    uint8_t version;
    uint64_t recipientId;
    uint64_t amount;
    uint64_t fee;
    uint32_t appendagesFlags;
    
    uint8_t displayType;
    int8_t screenNum;

} authAndSignState_t;