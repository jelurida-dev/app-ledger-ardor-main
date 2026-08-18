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

import nxt.Tester;
import nxt.account.Account;
import nxt.addons.JO;
import nxt.blockchain.ChildChain;
import nxt.http.assetexchange.AssetExchangeTest;
import nxt.http.callers.BroadcastTransactionCall;
import nxt.http.callers.ExchangeCoinsCall;
import nxt.http.callers.GetAccountAssetsCall;
import nxt.http.callers.GetBalanceCall;
import nxt.http.callers.GetCoinExchangeOrderCall;
import nxt.http.callers.ParseTransactionCall;
import nxt.http.callers.SendMoneyCall;
import nxt.http.callers.TransferAssetCall;
import nxt.util.Convert;
import nxt.util.Logger;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import static com.jelurida.ardor.integration.wallet.ledger.speculos.SpeculosRemote.screen;

import java.util.stream.Stream;

/**
 * Builds real transactions on the node, has the app parse, display and sign them, then
 * verifies and broadcasts the result.
 */
public class SpeculosSignTransactionTest extends AbstractSpeculosTest {

    private static final int SIGNATURE_POSITION = 69;
    private static final int SIGNATURE_LENGTH = 64;

    private static byte[] ledgerPublicKey;
    private static long ledgerAccountId;

    @BeforeClass
    public static void initLedgerAccount() {
        ledgerPublicKey = app.getWalletPublicKeys(PATH_STR_0, false);
        ledgerAccountId = Account.getId(ledgerPublicKey);
    }

    @Test
    public void testSendMoneyTransaction() throws Exception {
        fundLedgerAccount(2, 100000000);
        generateBlock();

        JO sendMoneyTx = SendMoneyCall.create(2).recipient(BOB.getStrId()).amountNQT(200000000).feeNQT(100000000).publicKey(ledgerPublicKey).callNoError();
        sendTransactionToSpeculos(sendMoneyTx,
                                  screen("Chain&TxnType", "IGNIS", "Make Payment"),
                                  screen("Amount", "2 IGNIS"),
                                  screen("Recipient", BOB.getRsAccount()),
                                  screen("Fees", "1 IGNIS"));
        Assert.assertEquals(500000000 - 200000000 - 100000000,
                            GetBalanceCall.create(2).account(ledgerAccountId).callNoError().getLong("balanceNQT"));
        Assert.assertEquals(200000000, BOB.getChainBalanceDiff(2));
    }

    @Test
    public void testSendMoneyWithMessageTransaction() throws Exception {
        fundLedgerAccount(2, 100000000);
        generateBlock();

        JO sendMoneyTx = SendMoneyCall.create(2).recipient(BOB.getStrId()).amountNQT(200000000).feeNQT(100000000)
                                      .message("hello world").publicKey(ledgerPublicKey).callNoError();
        sendTransactionToSpeculos(sendMoneyTx,
                                  screen("Blind", "Signing"),
                                  screen("Chain&TxnType", "IGNIS", "Make Payment"),
                                  screen("Amount", "2 IGNIS"),
                                  screen("Recipient", BOB.getRsAccount()),
                                  screen("Appendages", "Message"),
                                  screen("Fees", "1 IGNIS"));

        Assert.assertEquals(500000000 - 200000000 - 100000000,
                            GetBalanceCall.create(2).account(ledgerAccountId).callNoError().getLong("balanceNQT"));
        Assert.assertEquals(200000000, BOB.getChainBalanceDiff(2));
    }

    @Test
    public void testSendArdorTransaction() throws Exception {
        fundLedgerAccount(1, 200000000);
        generateBlock();

        JO sendArdrTx = SendMoneyCall.create(1).recipient(BOB.getId()).amountNQT(200000000).feeNQT(100000000)
                                     .publicKey(ledgerPublicKey).callNoError();
        sendTransactionToSpeculos(sendArdrTx,
                                  screen("Chain&TxnType", "ARDR", "Make Payment"),
                                  screen("Amount", "2 ARDR"),
                                  screen("Recipient", BOB.getRsAccount()),
                                  screen("Fees", "1 ARDR"));
        Assert.assertEquals(500000000 - 200000000 - 100000000,
                            GetBalanceCall.create(1).account(ledgerAccountId).callNoError().getLong("balanceNQT"));
        Assert.assertEquals(200000000, BOB.getFxtBalanceDiff());
    }

    @Test
    public void testArdorCoinExchangeOrderIssue() throws Exception {
        fundLedgerAccount(1, 200000000);
        fundLedgerAccount(2, 100000000);
        generateBlock();

        JO tx = ExchangeCoinsCall.create(1).quantityQNT(400000000).exchange(2).priceNQTPerCoin(50000000)
                                 .feeNQT(50000000).publicKey(ledgerPublicKey).callNoError();
        String fullHash = sendTransactionToSpeculos(tx,
                                                    screen("Chain&TxnType", "ARDR", "Issue Exchange Order"),
                                                    screen("Amount", "4 IGNIS"),
                                                    screen("Price per IGNIS", "0.5 ARDR"),
                                                    screen("Fees", "0.5 ARDR"));

        JO response = GetCoinExchangeOrderCall.create().order(Tester.hexFullHashToStringId(fullHash)).call();
        Assert.assertEquals("200000000", response.getString("askNQTPerCoin"));
        Assert.assertEquals("200000000", response.getString("exchangeQNT"));
        Assert.assertEquals("400000000", response.getString("quantityQNT"));
        Assert.assertEquals(1, response.getInt("chain"));
        Assert.assertEquals("50000000", response.getString("bidNQTPerCoin"));
        Assert.assertEquals(2, response.getInt("exchange"));
        Assert.assertEquals(ledgerAccountId, response.getLong("account"));
    }

    @Test
    public void testCoinExchangeOrderIssue() throws Exception {
        fundLedgerAccount(2, 100000000);
        generateBlock();

        // Buy 2 BITS coins at 1,5 IGNIS each. Total 3 IGNIS.
        JO tx = ExchangeCoinsCall.create(2).quantityQNT(200000000).exchange(ChildChain.BITSWIFT.getId())
                                 .priceNQTPerCoin(150000000).feeNQT(100000000).publicKey(ledgerPublicKey).callNoError();
        String fullHash = sendTransactionToSpeculos(tx,
                                                    screen("Chain&TxnType", "IGNIS", "Issue Exchange Order"),
                                                    screen("Amount", "2 BITS"),
                                                    screen("Price per BITS", "1.5 IGNIS"),
                                                    screen("Fees", "1 IGNIS"));

        JO response = GetCoinExchangeOrderCall.create().order(Tester.hexFullHashToStringId(fullHash)).call();
        Assert.assertEquals("300000000", response.getString("exchangeQNT"));
        Assert.assertEquals("200000000", response.getString("quantityQNT"));
        Assert.assertEquals(2, response.getInt("chain"));
        Assert.assertEquals("150000000", response.getString("bidNQTPerCoin"));
        Assert.assertEquals(ChildChain.BITSWIFT.getId(), response.getInt("exchange"));
        Assert.assertEquals(ledgerAccountId, response.getLong("account"));
    }

    @Test
    public void testAssetTransfer() throws Exception {
        String assetId = AssetExchangeTest.issueAsset(ALICE, "LDGR").getAssetIdString();
        fundLedgerAccount(2, 100000000);
        TransferAssetCall.create(2).secretPhrase(ALICE.getSecretPhrase()).recipient(ledgerAccountId)
                         .asset(assetId).quantityQNT(10000).feeNQT(100000000).callNoError();
        generateBlock();

        JO tx = TransferAssetCall.create(2).recipient(BOB.getId()).asset(assetId).quantityQNT(2000)
                                 .feeNQT(100000000).publicKey(ledgerPublicKey).callNoError();
        sendTransactionToSpeculos(tx,
                                  screen("Chain&TxnType", "IGNIS", "Transfer Asset"),
                                  screen("Asset Id", assetId),
                                  screen("Quantity QNT", "2000"),
                                  screen("Recipient", BOB.getRsAccount()),
                                  screen("Fees", "1 IGNIS"));

        JO response = GetAccountAssetsCall.create().account(ledgerAccountId).asset(assetId).call();
        Assert.assertEquals(10000 - 2000, response.getLong("quantityQNT"));
        response = GetAccountAssetsCall.create().account(BOB.getId()).asset(assetId).call();
        Assert.assertEquals(2000, response.getLong("quantityQNT"));
    }

    /** Sends the ledger account 5 coins of the given chain, so it can pay for what it signs. */
    private static void fundLedgerAccount(int chain, long feeNQT) {
        SendMoneyCall.create(chain).recipient(ledgerAccountId).amountNQT(500000000).feeNQT(feeNQT)
                     .secretPhrase(ALICE.getSecretPhrase()).callNoError();
    }

    /**
     * Sends the unsigned transaction to the app, checks the review it displays against the
     * expected texts, signs it there, then verifies and broadcasts the signed transaction.
     * Returns the full hash of the broadcast transaction.
     */
    private String sendTransactionToSpeculos(JO unsignedTransaction, String... expectedScreens) throws Exception {
        Logger.logInfoMessage("Sending unsigned transaction bytes to Speculos: %s", unsignedTransaction.toJSONString());
        String unsignedBytesHex = unsignedTransaction.getString("unsignedTransactionBytes");

        Assert.assertTrue(confirmOnDevice(() -> app.loadWalletTransaction(unsignedBytesHex),
                                          "Accept", prependAuthorizeScreen(expectedScreens)));
        byte[] signature = app.signWalletTransaction(PATH_STR_0);
        String signatureHex = Convert.toHexString(signature);
        Logger.logDebugMessage("Signature: %s", signatureHex);

        // Insert the signature into the transaction bytes and verify the signature
        int sigPos = 2 * SIGNATURE_POSITION;
        int sigLen = 2 * SIGNATURE_LENGTH;
        String signedBytesHex = unsignedBytesHex.substring(0, sigPos) + signatureHex + unsignedBytesHex.substring(sigPos + sigLen);
        JO response = ParseTransactionCall.create().transactionBytes(signedBytesHex).callNoError();
        Assert.assertTrue(response.getBoolean("verify"));

        JO broadcastTransactionResponse = BroadcastTransactionCall.create().transactionBytes(signedBytesHex).callNoError();
        String fullHash = broadcastTransactionResponse.getString("fullHash");
        Assert.assertNotNull(fullHash);
        generateBlock();
        return fullHash;
    }

    /** Every transaction review opens with the same screen. */
    private static String[] prependAuthorizeScreen(String... expectedScreens) {
        return Stream.concat(Stream.of(screen("Authorize", "transaction")), Stream.of(expectedScreens))
                     .toArray(String[]::new);
    }
}
