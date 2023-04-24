/*******************************************************************************
*  (c) 2019 Haim Bender
*  (c) 2021-2023 Jelurida IP B.V.
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
        uint8_t * const flags, uint8_t * const tx, const bool isLastCommandDifferent) {

	UNUSED(p1); UNUSED(p2); UNUSED(dataBuffer); UNUSED(dataLength); UNUSED(flags); UNUSED(isLastCommandDifferent);

	G_io_apdu_buffer[(*tx)++] = APPVERSION_M;
	G_io_apdu_buffer[(*tx)++] = APPVERSION_N;
	G_io_apdu_buffer[(*tx)++] = APPVERSION_P;
	G_io_apdu_buffer[(*tx)++] = VERSION_FLAGS;

	memmove(G_io_apdu_buffer + (*tx), ARDOR_SPECIAL_IDENTIFIER, ARDOR_SPECIAL_IDENTIFIER_LEN);
	*tx += ARDOR_SPECIAL_IDENTIFIER_LEN;

	G_io_apdu_buffer[(*tx)++] = 0x90;
	G_io_apdu_buffer[(*tx)++] = 0x00;
}
