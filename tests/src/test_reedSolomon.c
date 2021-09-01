/*******************************************************************************
*  (c) 2021 Jelurida IP B.V.
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

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <../../src/reedSolomon.h>
#include <cmocka.h>

struct testvector_t { int64_t account_id; char account_rs[20]; };

struct testvector_t testvectors[] = {
    {8264278205416377583L, "K59H-9RMF-64CY-9X6E7"},
    {8301188658053077183L, "4Q7Z-5BEE-F5JZ-9ZXE8"},
    {1798923958688893959L, "GM29-TWRT-M5CK-3HSXK"},
    {6899983965971136120L, "MHMS-VHZT-W5CY-7CFJZ"},
    {1629938923029941274L, "JM2U-U4AE-G7WF-3NP9F"},
    {6474206656034063375L, "4K2H-NVHQ-7WXY-72AQM"},
    {1691406066100673814L, "Y9AQ-VE8F-U9SY-3NAYG"},
    {2992669254877342352L, "6UNJ-UMFM-Z525-4S24M"},
    {43918951749449909L, "XY7P-3R8Y-26FC-2A293"},
    {9129355674909631300L, "YSU6-MRRL-NSC4-9WHEX"},
    {0L, "2222-2222-2222-22222"},
    {1L, "2223-2222-KB8Y-22222"},
    {10L, "222C-2222-VJTL-22222"},
    {100L, "2256-2222-QFKF-22222"},
    {1000L, "22ZA-2222-ZK43-22222"},
    {10000L, "2BSJ-2222-KC3Y-22222"},
    {100000L, "53P2-2222-SQQW-22222"},
    {1000000L, "YJL2-2222-ZZPC-22222"},
    {10000000L, "K7N2-222B-FVFG-22222"},
    {100000000L, "DSA2-224Z-849U-22222"},
    {1000000000L, "PLJ2-22XT-DVNG-22222"},
    {10000000000L, "RT22-2BC2-SMPD-22222"},
    {100000000000L, "FU22-4X69-74VX-22222"},
    {1000000000000L, "C622-X5CC-EMM8-22222"},
    {10000000000000L, "7A22-5399-RNFK-2B222"},
    {100000000000000L, "NJ22-YEA9-KWDV-2U422"},
    {1000000000000000L, "F222-HULE-NWMS-2FW22"},
    {10000000000000000L, "4222-YBRW-T4XW-28WA2"},
    {100000000000000000L, "N222-H3GS-QPZD-27US4"},
    {1000000000000000000L, "A222-QGMQ-WDH2-2Q7SV"}};

static void test_reedSolomonEncode(void **state) {
    char out[21];

    int n = sizeof(testvectors) / sizeof(struct testvector_t);
    for(int i = 0; i < n; i++) {
        reedSolomonEncode(testvectors[i].account_id, out);
        assert_string_equal(testvectors[i].account_rs, out);
    }
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_reedSolomonEncode)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}