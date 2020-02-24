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

#include "config.h"

//function that returns the version, in order to see if this is actually the ardor app
//returns VERSION 2 bytes | FLAGS 1 byte | ARDOR_SPECIAL_IDENTIFIER 3 bytes
void getVersionHandler(const uint8_t p1, const uint8_t p2, const uint8_t * const dataBuffer, const uint8_t dataLength,
        unsigned int * const flags, unsigned int * const tx, const bool isLastCommandDifferent) {

	G_io_apdu_buffer[(*tx)++] = VERSION >> 8;
	G_io_apdu_buffer[(*tx)++] = VERSION & 0xFF;
	G_io_apdu_buffer[(*tx)++] = VERSION_FLAGS;

	os_memmove(G_io_apdu_buffer + (*tx), ARDOR_SPECIAL_IDENTIFIER, ARDOR_SPECIAL_IDENTIFIER_LEN);
	*tx += ARDOR_SPECIAL_IDENTIFIER_LEN;

	G_io_apdu_buffer[(*tx)++] = 0x90;
	G_io_apdu_buffer[(*tx)++] = 0x00;
}
