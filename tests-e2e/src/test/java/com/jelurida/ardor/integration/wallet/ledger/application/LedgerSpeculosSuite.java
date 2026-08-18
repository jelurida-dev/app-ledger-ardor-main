/*
 * Copyright © 2016-2023 Jelurida IP B.V.
 * Copyright © 2023-2026 Jelurida Swiss SA
 *
 * See the LICENSE.txt file at the top-level directory of this distribution
 * for licensing information.
 *
 * Unless otherwise agreed in a custom licensing agreement with Jelurida
 * Swiss SA, no part of this software, including this file, may be copied,
 * modified, propagated, or distributed except according to the terms
 * contained in the LICENSE.txt file.
 *
 * Removal or modification of this copyright notice is prohibited.
 *
 */

package com.jelurida.ardor.integration.wallet.ledger.application;

import nxt.http.AbstractHttpApiSuite;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;

/**
 * The entry point of the end to end tests: it starts one node for all the test classes it
 * aggregates, which then drive it against the Ardor app running on the Speculos emulator.
 */
@RunWith(Suite.class)
@Suite.SuiteClasses({
        ArdorSpeculosTest.class,
        SpeculosHeadlessTest.class,
        SpeculosKeyComparisonTest.class,
        SpeculosSignTransactionTest.class
})
public class LedgerSpeculosSuite extends AbstractHttpApiSuite {
}
