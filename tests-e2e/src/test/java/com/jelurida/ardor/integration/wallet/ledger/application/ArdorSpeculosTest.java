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

import nxt.account.Account;
import nxt.account.Token;
import nxt.crypto.KeyDerivation;
import nxt.util.Convert;
import org.junit.Assert;
import org.junit.Test;

import java.util.Random;

import static com.jelurida.ardor.integration.wallet.ledger.speculos.SpeculosRemote.screen;

/**
 * The commands the app displays a review for: showing an address and signing a token.
 */
public class ArdorSpeculosTest extends AbstractSpeculosTest {

    @Test
    public void showAddress0() throws Exception {
        showAddress(PATH_STR_0);
    }

    @Test
    public void showAddress3() throws Exception {
        showAddress(PATH_STR_3);
    }

    private void showAddress(String path) throws Exception {
        byte[] publicKey = KeyDerivation.deriveMnemonic(path, MNEMONIC).getPublicKey();
        long accountId = Account.getId(publicKey);
        String address = Convert.rsAccount(accountId);

        confirmOnDevice(() -> {
            app.showAddress(path);
            return null;
        }, "Confirm", screen("Your Address", address));
    }

    @Test
    public void generateToken() throws Exception {
        int timestamp = Convert.toEpochTime(System.currentTimeMillis());
        String tokenData = "Token Data";

        String tokenStr = signToken(PATH_STR_0, timestamp, Convert.toBytes(tokenData));

        Token token = Token.parseToken(tokenStr, tokenData);
        Assert.assertTrue(token.isValid());
        Assert.assertEquals(token.getTimestamp(), timestamp);
        Assert.assertArrayEquals(token.getPublicKey(), app.getWalletPublicKeys(PATH_STR_0, false));
    }

    @Test
    public void generateTokenFromLargeDataSet() throws Exception {
        Random r = new Random(1);
        int timestamp = r.nextInt();
        byte[] blob = new byte[40000];
        r.nextBytes(blob);

        String tokenStr = signToken(PATH_STR_3, timestamp, blob);

        Token token = Token.parseToken(tokenStr, blob);
        Assert.assertTrue(token.isValid());
        Assert.assertEquals(token.getTimestamp(), timestamp);
        Assert.assertArrayEquals(token.getPublicKey(), app.getWalletPublicKeys(PATH_STR_3, false));
    }

    /** Signing a token always needs blind signing: the app cannot show what it is signing. */
    private static String signToken(String accountPath, int timestamp, byte[] tokenData) throws Exception {
        String tokenHexData = Convert.toHexString(tokenData);
        return confirmOnDevice(() -> app.signToken(accountPath, timestamp, tokenHexData),
                               "Sign", screen("Blind", "Signing"));
    }
}
