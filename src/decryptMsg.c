#include <stdint.h>
#include <stdbool.h>

#include <os.h>
#include <os_io_seproxyhal.h>
#include "ux.h"

#include "ardor.h"
#include "returnValues.h"

void decryptMessageHelper(uint8_t p1, uint8_t p2, uint8_t *dataBuffer, uint16_t dataLength,
        volatile unsigned int *flags, volatile unsigned int *tx) {

	if (p1 < 2) {
		G_io_apdu_buffer[(*tx)++] = R_DERIVATION_PATH_TOO_SHORT;
        return; 
	}

    if (p1 > 54) {
		G_io_apdu_buffer[(*tx)++] = R_DERIVATION_PATH_TOO_LONG;
        return; 
    }

    if (dataLength <  p1 * sizeof(uint32_t) + 32 + 32 + 16) {
        G_io_apdu_buffer[(*tx)++] = R_WRONG_SIZE_ERR;
        return; 
    }

    uint8_t dataToDecryptLength = dataLength - p1 * sizeof(uint32_t) - 32 - 32;

    if (0 != dataToDecryptLength % 16) {
        G_io_apdu_buffer[(*tx)++] = R_WRONG_SIZE_MODULO_ERR;
        return;
    }

    uint32_t derivationPath[54];

    os_memcpy(derivationPath, dataBuffer, p1 * sizeof(uint32_t));
   	
   	uint8_t exceptionOut = 0;
 	uint8_t numBytesWrittenOut = 0;

    cx_aes_key_t aesKey;

    uint8_t ret = getSharedEncryptionKey(derivationPath, p1, dataBuffer + p1 * sizeof(uint32_t), dataBuffer + p1 * sizeof(uint32_t) + 32, &exceptionOut, &aesKey);

    if (R_KEY_DERIVATION_EX == ret) {
        G_io_apdu_buffer[0] = ret;
        G_io_apdu_buffer[1] = exceptionOut >> 8;
        G_io_apdu_buffer[2] = exceptionOut & 0xFF;
        *tx = 3;
        return;
    } else if (R_SUCCESS != ret) {
        G_io_apdu_buffer[0] = ret;
        *tx = 1;
        return;
    }

    uint32_t outBfr[256];
    uint8_t outSize = 0;

    ret = decryptMessage(aesKey, dataBuffer + p1 * sizeof(uint32_t) + 32 + 32, dataToDecryptLength, outBfr, &outSize, &exceptionOut);

    G_io_apdu_buffer[0] = ret;
    
    if (R_EXCEPTION == ret) {
        G_io_apdu_buffer[1] = exceptionOut >> 8;
        G_io_apdu_buffer[2] = exceptionOut & 0xFF;
        *tx = 3;
        return;
    } else if (R_SUCCESS != ret) {
        *tx = 1;
    	return;
    }

    os_memcpy(G_io_apdu_buffer + 1, outBfr, outSize);
    *tx = outSize + 1;
}

void decryptMessageHandler(uint8_t p1, uint8_t p2, uint8_t *dataBuffer, uint16_t dataLength,
                volatile unsigned int *flags, volatile unsigned int *tx) {

    encryptMessageHandlerHelper(p1, p2, dataBuffer, dataLength, flags, tx);
    
    G_io_apdu_buffer[(*tx)++] = 0x90;
    G_io_apdu_buffer[(*tx)++] = 0x00;
}
