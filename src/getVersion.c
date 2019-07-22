#include <stdint.h>
#include <os.h>
#include <os_io_seproxyhal.h>
#include <stdbool.h>

#define VERSION 0x0001
#define FLAGS   0x00

void handleGetVersion(uint8_t p1, uint8_t p2, uint8_t *dataBuffer, uint16_t dataLength,
                            volatile unsigned int *flags, volatile unsigned int *tx) {
	
	uint8_t ardorSpecial[] = {0xba, 0xbe, 0x00};

	G_io_apdu_buffer[(*tx)++] = VERSION >> 8;
	G_io_apdu_buffer[(*tx)++] = VERSION & 0xFF;
	G_io_apdu_buffer[(*tx)++] = FLAGS;

	os_memmove(G_io_apdu_buffer + (*tx), ardorSpecial, sizeof(ardorSpecial));
	*tx += sizeof(ardorSpecial);

	G_io_apdu_buffer[(*tx)++] = 0x90;
	G_io_apdu_buffer[(*tx)++] = 0x00;
}
