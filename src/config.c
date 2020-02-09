

#include <stdint.h>
#include <stdbool.h>

#include "config.h"

//Note: TXN_TYPES are configured in txnTypesList.c, it's there cuz the list is auto-generated from some other java file in order to sync between projects

//This configures the supported chain types, chainId, name and amount of decimals to the right of the point
static const chainType CHAINS[] = {{0x00000001, "Ardor", 8}, {0x00000002, "Ignis", 8}, {0x00000003, "AEUR", 4}, {0x00000004, "BITS", 8}, {0x00000005, "MPG", 8}};
static const uint8_t NUM_CHAINS = sizeof(CHAINS);

static const uint8_t SUPPORTED_TXN_VERSION = 1;

static const uint8_t ARDOR_SPECIAL_IDENTIFIER[] = {0xba, 0xbe, 0x00};
static const uint8_t ARDOR_SPECIAL_IDENTIFIER_LEN = 3;
