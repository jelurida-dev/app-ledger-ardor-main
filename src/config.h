


//This is the header for different types of consts and configurations, the actual values are set in config.c

typedef struct {
    uint32_t chainId;
    char * name;
    uint8_t numDecimalsBeforePoint;
} chainType;

static const chainType CHAINS[];
static const uint8_t NUM_CHAINS;
