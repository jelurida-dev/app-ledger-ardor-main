#include <stdint.h>
#include <stdbool.h>

#include <os.h>
#include <os_io_seproxyhal.h>
#include "ux.h"

#include "ardor.h"
#include "returnValues.h"

void encryptMessageHandlerHelper(uint8_t p1, uint8_t p2, uint8_t *dataBuffer, uint16_t dataLength,
        volatile unsigned int *flags, volatile unsigned int *tx) {

	PRINTF("\nd0");


	if (p1 < 2) {
		G_io_apdu_buffer[(*tx)++] = R_DERIVATION_PATH_TOO_SHORT;
        return; 
	}

    if (p1 > 54) {
		G_io_apdu_buffer[(*tx)++] = R_DERIVATION_PATH_TOO_LONG;
        return; 
    }

    PRINTF("\nd1");

    if (dataLength <  p1 * sizeof(uint32_t) + 32 + 1) {
        G_io_apdu_buffer[(*tx)++] = R_WRONG_SIZE_ERR;
        return; 
    }

    PRINTF("\nd2");

    uint8_t dataToEncryptPos = p1 * sizeof(uint32_t) + 32;

    if (208 < dataLength - dataToEncryptPos) {
    	G_io_apdu_buffer[(*tx)++] = R_DATA_BUFFER_TOO_BIG;
        return; 
    }

    PRINTF("\nd3");

    uint32_t derivationPath[54];

    os_memcpy(derivationPath, dataBuffer, p1 * sizeof(uint32_t));
   	
   	uint8_t exceptionOut = 0;

 	uint8_t nonce[32]; os_memset(nonce, 0, sizeof(nonce));
 	cx_rng(nonce, sizeof(nonce));

	cx_aes_key_t aesKey;

	uint8_t ret = getSharedEncryptionKey(derivationPath, p1, dataBuffer + p1 * sizeof(uint32_t), nonce, &exceptionOut, &aesKey);

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

 	ret = encryptMessage(&aesKey, dataBuffer + dataToEncryptPos, dataLength - dataToEncryptPos, G_io_apdu_buffer + 1 + 32, tx, &exceptionOut);

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
}

void encryptMessageHandler(uint8_t p1, uint8_t p2, uint8_t *dataBuffer, uint16_t dataLength,
                volatile unsigned int *flags, volatile unsigned int *tx) {


	PRINTF("\nd0");

    encryptMessageHandlerHelper(p1, p2, dataBuffer, dataLength, flags, tx);
    
    G_io_apdu_buffer[(*tx)++] = 0x90;
    G_io_apdu_buffer[(*tx)++] = 0x00;
}
