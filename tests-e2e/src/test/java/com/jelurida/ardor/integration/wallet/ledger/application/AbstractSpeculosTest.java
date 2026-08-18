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

import com.jelurida.ardor.integration.wallet.ledger.speculos.SpeculosRemote;
import nxt.BlockchainTest;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;

import java.util.concurrent.Callable;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.ForkJoinTask;
import java.util.concurrent.TimeUnit;

/**
 * The base of the end to end tests. They live in this package because they reach the
 * package-private raw-byte entry points of {@link ArdorAppBridge}; the classes are named
 * after Speculos to keep them apart from the like-named node tests the ardor-tests jar
 * ships in the very same package.
 */
public abstract class AbstractSpeculosTest extends BlockchainTest {

    protected static final String PATH_STR_PARENT_1 = "m/44'/16754'/0'/1'";
    protected static final String PATH_STR_PARENT_2 = "m/44'/16754'/0'/2'";

    protected static final String PATH_STR_0 = "m/44'/16754'/0'/1'/0";
    protected static final String PATH_STR_3 = "m/44'/16754'/0'/1'/3";

    /** The 24 words Speculos is seeded with. Must match the seed the emulator is started with. */
    protected static final String MNEMONIC = "opinion change copy struggle town cigar input kit school patient execute bird bundle option canvas defense hover poverty skill donkey pottery infant sense orchard";

    /** How long the app may take to answer once the review has been confirmed. */
    private static final int RESPONSE_TIMEOUT_SECONDS = 10;

    protected static final SpeculosRemote speculosRemote = new SpeculosRemote();

    protected static ArdorAppInterface app;

    @BeforeClass
    public static void init() {
        BlockchainTest.init();
        app = ArdorAppBridge.getApp();
        speculosRemote.awaitHomeScreen();
    }

    @Before
    public void checkDeviceStatus() {
        Assert.assertTrue(app.getLastError(), app instanceof ArdorAppBridge);
    }

    /**
     * Runs a command that makes the app display a review, checks that review against the
     * expected screens, confirms it, and returns what the command answered. Blind signing is
     * turned on and the command run again if the app refuses it for want of the setting.
     */
    protected static <V> V confirmOnDevice(Callable<V> command, String confirmLabel, String... expectedScreens)
            throws Exception {
        speculosRemote.awaitHomeScreen();
        ForkJoinTask<V> task = ForkJoinPool.commonPool().submit(command);
        if (speculosRemote.blindSigningRefused()) {
            speculosRemote.enableBlindSigning();
            task = ForkJoinPool.commonPool().submit(command);
        }
        speculosRemote.reviewAndConfirm(confirmLabel, expectedScreens);
        return task.get(RESPONSE_TIMEOUT_SECONDS, TimeUnit.SECONDS);
    }
}
