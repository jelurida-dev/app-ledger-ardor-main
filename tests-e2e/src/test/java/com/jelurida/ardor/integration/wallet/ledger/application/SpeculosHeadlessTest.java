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

import nxt.Constants;
import nxt.crypto.DecryptedData;
import nxt.crypto.EncryptedData;
import nxt.crypto.KeyDerivation;
import nxt.util.Bip32Path;
import nxt.util.Convert;
import org.junit.Assert;
import org.junit.Test;

import java.util.Random;

/**
 * The commands the app answers without displaying anything: key derivation, encryption and
 * decryption.
 */
public class SpeculosHeadlessTest extends AbstractSpeculosTest {

    @Test
    public void getVersion() {
        // That the app is reachable and answers is what @Before already asserts.
        Assert.assertFalse(((ArdorAppBridge) app).isInvalidAppSignature());
    }

    @Test
    public void getPublicKeys() {
        KeyDerivation.Bip32Node parentNode =
                KeyDerivation.deriveMnemonic(Constants.ARDOR_TESTNET_BIP32_ROOT_PATH.toString(), MNEMONIC);
        assertDerivedPublicKey(parentNode, 0, PATH_STR_0);
        assertDerivedPublicKey(parentNode, 3, PATH_STR_3);
    }

    private static void assertDerivedPublicKey(KeyDerivation.Bip32Node parentNode, int childIndex, String path) {
        String expected = Convert.toHexString(KeyDerivation.deriveChildPublicKey(parentNode, childIndex).getPublicKey());
        Assert.assertEquals(expected, Convert.toHexString(app.getWalletPublicKeys(path, false)));
    }

    @Test
    public void ledgerEncryptDecrypt() {
        assertEncryptDecryptRoundTrip("LYLY".getBytes());
    }

    @Test
    public void ledgerEncryptDecryptLongMessage() {
        byte[] dataToEncrypt = new byte[1024];
        new Random().nextBytes(dataToEncrypt);
        assertEncryptDecryptRoundTrip(dataToEncrypt);
    }

    /** Encrypts on the device from one path to another, then decrypts it back on the device. */
    private static void assertEncryptDecryptRoundTrip(byte[] plainText) {
        byte[] recipientPublicKey = app.getWalletPublicKeys(PATH_STR_3, false);
        Assert.assertEquals(recipientPublicKey.length, 32);
        String result = app.encryptBuffer(PATH_STR_0, Convert.toHexString(recipientPublicKey), Convert.toHexString(plainText));
        Assert.assertNotNull(result);
        String[] tokens = result.split(",");
        String dataHex = tokens[0];
        String nonceHex = tokens[1];
        byte[] senderPublicKey = app.getWalletPublicKeys(PATH_STR_0, false);
        String decryptedData = app.decryptBuffer(PATH_STR_3, Convert.toHexString(senderPublicKey), nonceHex, dataHex);
        tokens = decryptedData.split(",");
        Assert.assertArrayEquals(Convert.parseHexString(tokens[0]), plainText);
    }

    @Test
    public void ledgerEncryptJavaDecrypt() {
        byte[] dataToEncrypt = new byte[64];
        Random r = new Random();
        r.nextBytes(dataToEncrypt);
        byte[] recipientPublicKey = ALICE.getPublicKey();
        Assert.assertEquals(recipientPublicKey.length, 32);
        EncryptedData encryptedData = ((ArdorAppBridge)app).encryptBuffer(Bip32Path.bip32StrToPath(PATH_STR_0), recipientPublicKey, dataToEncrypt);
        byte[] senderPublicKey = app.getWalletPublicKeys(PATH_STR_0, false);
        byte[] decryptedMessage = encryptedData.decrypt(ALICE.getPrivateKey(), senderPublicKey);
        decryptedMessage = Convert.uncompress(decryptedMessage);
        Assert.assertArrayEquals(decryptedMessage, dataToEncrypt);
    }

    @Test
    public void javaEncryptLedgerDecrypt() {
        byte[] dataToEncrypt = new byte[64];
        new Random().nextBytes(dataToEncrypt);
        byte[] recipientPublicKey = app.getWalletPublicKeys(PATH_STR_3, false);
        EncryptedData encryptedData = EncryptedData.encrypt(Convert.compress(dataToEncrypt), ALICE.getPrivateKey(), recipientPublicKey);
        DecryptedData decryptedData = ((ArdorAppBridge)app).decryptBuffer(Bip32Path.bip32StrToPath(PATH_STR_3), ALICE.getPublicKey(), encryptedData);
        Assert.assertArrayEquals(decryptedData.getData(), dataToEncrypt);
    }

    @SuppressWarnings("PointlessArithmeticExpression")
    @Test
    public void parsePath() {
        Assert.assertArrayEquals(new int[]{ 0x2C + Constants.HARDENED, 0x4172 + Constants.HARDENED, 0x00 + Constants.HARDENED, 0x01 + Constants.HARDENED, 0x00 }, Bip32Path.bip32StrToPath(PATH_STR_0));
        Assert.assertEquals(PATH_STR_0, Bip32Path.fromString("m/44'/16754'/0'/1'/0").toString());
    }

    @Test
    public void keyDerivation() {
        deriveChildKeys(PATH_STR_PARENT_1, 4);
        deriveChildKeys(PATH_STR_PARENT_2, 3);
    }

    private void deriveChildKeys(String parentPath, int numKeys) {
        // Get master key for parent path
        PublicKeyData parentPublicKeyData = app.getPublicKeyData(parentPath);
        if (parentPublicKeyData.getEd25519PublicKey().length == 0) {
            Assert.fail("Perhaps ledger is disconnected or locked or not in ardor app?");
        }
        for (int i=0; i < numKeys; i++) {
            deriveChildKey(parentPublicKeyData.getEd25519PublicKey(), parentPublicKeyData.getChainCode(), i, parentPath);
        }
    }

    private void deriveChildKey(byte[] masterPublicKey, byte[] chainCode, int childIndex, String parentPath) {
        // Derive the ed25519 child public key using Java code
        KeyDerivation.Bip32Node bip32NodeData = KeyDerivation.deriveChildPublicKey(masterPublicKey, chainCode, childIndex);

        // We need the curve25519 public key
        byte[] curve25519PublicKeyBytes = bip32NodeData.getPublicKey();

        // Make sure the curve25519 key calculated in Java is identical to the key returned by ledger from the same path
        // when asked for directly. This proves that the keys generated offline are identical to the keys generated by ledger.
        byte[] childCurve25519PublicKey = app.getWalletPublicKeys(parentPath + "/" + childIndex, false);
        Assert.assertEquals(Convert.toHexString(childCurve25519PublicKey), Convert.toHexString(curve25519PublicKeyBytes));
    }

}
