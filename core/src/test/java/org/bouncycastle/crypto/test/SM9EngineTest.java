package org.bouncycastle.crypto.test;

import java.math.BigInteger;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.engines.SM9Engine;
import org.bouncycastle.crypto.generators.SM9EncMasterKeyPairGenerator;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.SM9EncMasterPrivateKeyParameters;
import org.bouncycastle.crypto.params.SM9EncMasterPublicKeyParameters;
import org.bouncycastle.crypto.params.SM9EncPrivateKeyParameters;
import org.bouncycastle.crypto.params.SM9EncPublicKeyParameters;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Tests of the SM9 public-key encryption engine (GM/T 0044.4-2016) at the lightweight layer.
 * The GM/T 0044.5 known answers for both data-encapsulation methods are checked through the
 * provider in the jce SM9CipherTest; this test covers what the raw C1 || C3 || C2 form leaves to
 * the caller - the engine's mode has to be the one the sender used, nothing in the ciphertext
 * records it - and both modes' refusal of the one C2 length, 16 bytes, at which the two
 * methods' KDF calls coincide and a ciphertext of either passes the other's MAC check.
 */
public class SM9EngineTest
    extends SimpleTest
{
    // The GM/T 0044.5-2016 Annex D encryption master private key ke, and a one-block SM4-mode
    // ciphertext C1 || C3 || C2 of the message "one block" to the identity "Bob" under it, made with
    // the annex's r by this engine before its SM4 mode stopped encrypting messages of fewer than 16
    // bytes - so C1 is the annex's C1 and the K1 and K2 behind C2 and C3 are its method b) K1 and K2.
    private static final BigInteger ANNEX_D_KE =
        new BigInteger("01EDEE3778F441F8DEA3D9FA0ACC4E07EE36C93F9A08618AF4AD85CEDE1C22", 16);
    private static final byte[] ONE_BLOCK_SM4 = Hex.decode(
        "2445471164490618E1EE20528FF1D545B0F14C8BCAA44544F03DAB5DAC07D8FF"
            + "42FFCA97D57CDDC05EA405F2E586FEB3A6930715532B8000759F13059ED59AC0"
            + "059C700E0E8FEE2801B3EEA529A39390C9138881914C3CAD9E1331EA9E430E9F"
            + "195527A7B90D2A8CE59D01C20EC36E06");

    public String getName()
    {
        return "SM9Engine";
    }

    public void performTest()
        throws Exception
    {
        SM9EncMasterKeyPairGenerator kpGen = new SM9EncMasterKeyPairGenerator();
        kpGen.init(new KeyGenerationParameters(CryptoServicesRegistrar.getSecureRandom(), 256));
        AsymmetricCipherKeyPair master = kpGen.generateKeyPair();
        byte[] identity = Strings.toByteArray("Bob");
        SM9EncPublicKeyParameters bobPublic =
            ((SM9EncMasterPublicKeyParameters)master.getPublic()).getUserPublicKey(identity);
        SM9EncPrivateKeyParameters bobKey =
            ((SM9EncMasterPrivateKeyParameters)master.getPrivate()).generateUserKey(identity, SM9EncMasterPrivateKeyParameters.HID);

        // both methods round-trip, the stream method at the lengths either side of 16
        int[] streamLengths = { 1, 15, 17, 32 };
        for (int i = 0; i != streamLengths.length; i++)
        {
            byte[] message = message(streamLengths[i]);
            byte[] ciphertext = encrypt(SM9Engine.Mode.STREAM, bobPublic, message);
            isTrue("SM9 stream-mode C2 is the message length at " + message.length + " bytes",
                ciphertext.length == 96 + message.length);
            isTrue("SM9 stream-mode round-trip at " + message.length + " bytes",
                Arrays.areEqual(message, decrypt(SM9Engine.Mode.STREAM, bobKey, ciphertext)));
        }
        int[] sm4Lengths = { 16, 17, 32 };
        for (int i = 0; i != sm4Lengths.length; i++)
        {
            byte[] message = message(sm4Lengths[i]);
            byte[] ciphertext = encrypt(SM9Engine.Mode.SM4, bobPublic, message);
            isTrue("SM9 SM4-mode C2 is the padded message at " + message.length + " bytes",
                ciphertext.length == 96 + ((message.length / 16) + 1) * 16);
            isTrue("SM9 SM4-mode round-trip at " + message.length + " bytes",
                Arrays.areEqual(message, decrypt(SM9Engine.Mode.SM4, bobKey, ciphertext)));
        }

        // a one-block SM4 ciphertext (a message of 0 to 15 bytes, so |C2| = 16) offered to a
        // stream-mode engine: same C1 and the same KDF call, so the same K1 and K2 and a MAC that
        // checks - the engine would return K1 xor C2, from which K1 and then the message follow.
        // Refused by length, before the pairing.
        SM9EncPrivateKeyParameters annexKey = new SM9EncMasterPrivateKeyParameters(ANNEX_D_KE)
            .generateUserKey(identity, SM9EncMasterPrivateKeyParameters.HID);
        isTrue("SM9 one-block SM4 ciphertext has a 16-byte C2", ONE_BLOCK_SM4.length == 96 + 16);
        try
        {
            decrypt(SM9Engine.Mode.STREAM, annexKey, ONE_BLOCK_SM4);
            fail("SM9 stream-mode engine decrypted a one-block SM4-mode ciphertext");
        }
        catch (InvalidCipherTextException e)
        {
            isTrue("SM9 stream-mode 16-byte C2 rejection message",
                "SM9 stream-mode ciphertext has a 16-byte C2".equals(e.getMessage()));
        }

        // and the stream mode will not produce a 16-byte C2 either
        try
        {
            encrypt(SM9Engine.Mode.STREAM, bobPublic, message(16));
            fail("SM9 stream-mode engine encrypted a 16-byte message");
        }
        catch (InvalidCipherTextException e)
        {
            isTrue("SM9 stream-mode 16-byte message rejection message",
                "SM9 stream mode cannot encrypt a 16-byte message".equals(e.getMessage()));
        }

        // nor will the SM4 mode, which is why the ciphertext above is a stored one: a recipient
        // that refuses the length is protected by that, but the message given away is the SM4-mode
        // sender's, who cannot tell whether the recipient does - so no message that pads to one
        // block is encrypted
        int[] oneBlockLengths = { 0, 1, 15 };
        for (int i = 0; i != oneBlockLengths.length; i++)
        {
            try
            {
                encrypt(SM9Engine.Mode.SM4, bobPublic, message(oneBlockLengths[i]));
                fail("SM9 SM4-mode engine encrypted a " + oneBlockLengths[i] + "-byte message");
            }
            catch (InvalidCipherTextException e)
            {
                isTrue("SM9 SM4-mode short message rejection message at " + oneBlockLengths[i] + " bytes",
                    "SM9 SM4 mode cannot encrypt a message shorter than 16 bytes".equals(e.getMessage()));
            }
        }

        // and with neither mode producing a 16-byte C2 the SM4 mode does not accept one - here
        // the stored ciphertext, genuine and once decryptable, in its own mode
        try
        {
            decrypt(SM9Engine.Mode.SM4, annexKey, ONE_BLOCK_SM4);
            fail("SM9 SM4-mode engine decrypted a ciphertext with a 16-byte C2");
        }
        catch (InvalidCipherTextException e)
        {
            isTrue("SM9 SM4-mode 16-byte C2 rejection message",
                "SM9 SM4-mode ciphertext has a 16-byte C2".equals(e.getMessage()));
        }

        // at every other length the two methods take K2 from different offsets of the KDF output,
        // so a ciphertext of one fails the other's MAC check: a two-block SM4 ciphertext offered
        // to the stream mode, and a 32-byte stream ciphertext offered to the SM4 mode
        byte[] twoBlocks = encrypt(SM9Engine.Mode.SM4, bobPublic, message(16));
        isTrue("SM9 two-block SM4 ciphertext has a 32-byte C2", twoBlocks.length == 96 + 32);
        try
        {
            decrypt(SM9Engine.Mode.STREAM, bobKey, twoBlocks);
            fail("SM9 stream-mode engine decrypted a two-block SM4-mode ciphertext");
        }
        catch (InvalidCipherTextException e)
        {
            isTrue("SM9 stream-mode MAC rejection message", "SM9 MAC check failed".equals(e.getMessage()));
        }
        byte[] stream32 = encrypt(SM9Engine.Mode.STREAM, bobPublic, message(32));
        try
        {
            decrypt(SM9Engine.Mode.SM4, bobKey, stream32);
            fail("SM9 SM4-mode engine decrypted a 32-byte stream-mode ciphertext");
        }
        catch (InvalidCipherTextException e)
        {
            isTrue("SM9 SM4-mode MAC rejection message", "SM9 MAC check failed".equals(e.getMessage()));
        }
    }

    private static byte[] message(int length)
    {
        byte[] message = new byte[length];
        for (int i = 0; i != length; i++)
        {
            message[i] = (byte)(i + 1);
        }
        return message;
    }

    private static byte[] encrypt(SM9Engine.Mode mode, SM9EncPublicKeyParameters recipient, byte[] message)
        throws InvalidCipherTextException
    {
        SM9Engine engine = new SM9Engine(mode);
        engine.init(true, new ParametersWithRandom(recipient, CryptoServicesRegistrar.getSecureRandom()));
        return engine.processBlock(message, 0, message.length);
    }

    private static byte[] decrypt(SM9Engine.Mode mode, SM9EncPrivateKeyParameters userKey, byte[] ciphertext)
        throws InvalidCipherTextException
    {
        SM9Engine engine = new SM9Engine(mode);
        engine.init(false, userKey);
        return engine.processBlock(ciphertext, 0, ciphertext.length);
    }

    public static void main(String[] args)
    {
        runTest(new SM9EngineTest());
    }
}
