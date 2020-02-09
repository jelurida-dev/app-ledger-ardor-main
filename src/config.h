


//This is the header for different types of consts and configurations, the actual values are set in config.c

typedef struct {
    uint32_t chainId;
    char * name;
    uint8_t numDecimalsBeforePoint;
} chainType;

static const chainType CHAINS[];
static const uint8_t NUM_CHAINS;
static const uint8_t SUPPORTED_TXN_VERSION;

#define VERSION 		0x0001
#define VERSION_FLAGS   0x00

static const uint8_t ARDOR_SPECIAL_IDENTIFIER[];
static const uint8_t ARDOR_SPECIAL_IDENTIFIER_LEN;
