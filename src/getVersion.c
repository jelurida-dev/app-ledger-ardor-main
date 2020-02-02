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

#include <stdint.h>
#include <os.h>
#include <os_io_seproxyhal.h>
#include <stdbool.h>

#define VERSION 0x0001
#define FLAGS   0x00

void getVersionHandler(const uint8_t p1, const uint8_t p2, const uint8_t * const dataBuffer, const uint8_t dataLength,
                volatile unsigned int * const flags, volatile unsigned int * const tx) {
	
	uint8_t ardorSpecial[] = {0xba, 0xbe, 0x00};

	G_io_apdu_buffer[(*tx)++] = VERSION >> 8;
	G_io_apdu_buffer[(*tx)++] = VERSION & 0xFF;
	G_io_apdu_buffer[(*tx)++] = FLAGS;

	os_memmove(G_io_apdu_buffer + (*tx), ardorSpecial, sizeof(ardorSpecial));
	*tx += sizeof(ardorSpecial);

	G_io_apdu_buffer[(*tx)++] = 0x90;
	G_io_apdu_buffer[(*tx)++] = 0x00;
}
