


//This is the header for different types of consts and configurations, the actual values are set in config.c

typedef struct {
    uint32_t chainId;
    char * name;
    uint8_t numDecimalsBeforePoint;
} chainType;

static const chainType CHAINS[];
static const uint8_t NUM_CHAINS;
static const uint8_t SUPPORTED_TXN_VERSION;

static const uint8_t ARDOR_SPECIAL_IDENTIFIER[];
static const uint8_t ARDOR_SPECIAL_IDENTIFIER_LEN;


static const uint16_t VERSION;
static const uint8_t VERSION_FLAGS;
static const char UI_APP_VERSION_TXT[];


//must make this a define instead of static const, because some array declirations are dependant on this size
#define MIN_DERIVATION_LENGTH 3
#define MAX_DERIVATION_LENGTH 20
