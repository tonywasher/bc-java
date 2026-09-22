package org.bouncycastle.jce.provider.test;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.gm.SM9Cipher;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.params.SM9EncMasterPrivateKeyParameters;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.interfaces.SM9EncMasterPrivateKey;
import org.bouncycastle.jcajce.interfaces.SM9EncMasterPublicKey;
import org.bouncycastle.jcajce.interfaces.SM9EncUserPrivateKey;
import org.bouncycastle.jcajce.interfaces.SM9EncUserPublicKey;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.jcajce.spec.SM9EncUserPrivateKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.test.TestResourceFinder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.TestRandomBigInteger;

/**
 * JCE-level tests for SM9 public-key encryption exposed as {@code Cipher.SM9}.
 */
public class SM9CipherTest
    extends SimpleTest
{
    // The GM/T 0044.5-2016 Annex D encryption master private key ke, and the C1, C3 and C2 of a
    // one-block SM4-mode ciphertext of the message "one block" to the identity "Bob" under it, made
    // with the annex's r before the SM4 mode stopped encrypting messages of fewer than 16 bytes - so
    // C1 is the annex's C1 and the K1 and K2 behind C2 and C3 are its method b) K1 and K2.
    private static final BigInteger ANNEX_D_KE =
        new BigInteger("01EDEE3778F441F8DEA3D9FA0ACC4E07EE36C93F9A08618AF4AD85CEDE1C22", 16);
    private static final byte[] ONE_BLOCK_C1 = Hex.decode(
        "042445471164490618E1EE20528FF1D545B0F14C8BCAA44544F03DAB5DAC07D8FF"
            + "42FFCA97D57CDDC05EA405F2E586FEB3A6930715532B8000759F13059ED59AC0");
    private static final byte[] ONE_BLOCK_C3 = Hex.decode(
        "059C700E0E8FEE2801B3EEA529A39390C9138881914C3CAD9E1331EA9E430E9F");
    private static final byte[] ONE_BLOCK_C2 = Hex.decode("195527A7B90D2A8CE59D01C20EC36E06");

    public String getName()
    {
        return "SM9Cipher";
    }

    public void performTest()
        throws Exception
    {
        byte[] bob = "Bob".getBytes("US-ASCII");
        byte[] plaintext = "hello sm9 encryption".getBytes("US-ASCII");

        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("SM9-ENC", "BC");
        KeyPair masterPair = kpGen.generateKeyPair();
        SM9EncMasterPrivateKey masterPriv = (SM9EncMasterPrivateKey)masterPair.getPrivate();
        PrivateKey bobKey = masterPriv.generateUserKeyPair(bob, SM9EncMasterPrivateKeyParameters.HID).getPrivate();
        PublicKey bobPublic = ((SM9EncMasterPublicKey)masterPair.getPublic()).getUserPublicKey(bob);

        // the user keys derive their identity (and, for the public key, the master public
        // key) directly, rather than a caller having to track them separately
        isTrue("SM9 enc user private key identity",
            Arrays.areEqual(bob, ((SM9EncUserPrivateKey)bobKey).getIdentity()));
        SM9EncUserPublicKey bobPublicKey = (SM9EncUserPublicKey)bobPublic;
        isTrue("SM9 enc user public key identity", Arrays.areEqual(bob, bobPublicKey.getIdentity()));
        isTrue("SM9 enc user public key master public key",
            Arrays.areEqual(masterPair.getPublic().getEncoded(), bobPublicKey.getMasterPublicKey().getEncoded()));

        // KeyFactory round-trip of the encryption master public key
        KeyFactory kf = KeyFactory.getInstance("SM9", "BC");
        PublicKey pub2 = kf.generatePublic(new X509EncodedKeySpec(masterPair.getPublic().getEncoded()));
        isTrue("SM9 KeyFactory enc master public round-trip",
            Arrays.areEqual(pub2.getEncoded(), masterPair.getPublic().getEncoded()));

        // default (SM4) mode round-trip - encryption takes the recipient's public key
        Cipher enc = Cipher.getInstance("SM9", "BC");
        enc.init(Cipher.ENCRYPT_MODE, bobPublic);
        byte[] ct = enc.doFinal(plaintext);
        Cipher dec = Cipher.getInstance("SM9", "BC");
        dec.init(Cipher.DECRYPT_MODE, bobKey);
        isTrue("SM9 Cipher SM4-mode round-trip", Arrays.areEqual(dec.doFinal(ct), plaintext));

        // KDF stream mode round-trip - the mode has to be set for decryption too, a
        // stream-mode ciphertext is not decryptable through the SM4-mode default
        Cipher encX = Cipher.getInstance("SM9/XOR/NoPadding", "BC");
        encX.init(Cipher.ENCRYPT_MODE, bobPublic);
        byte[] ctX = encX.doFinal(plaintext);
        Cipher decX = Cipher.getInstance("SM9/XOR/NoPadding", "BC");
        decX.init(Cipher.DECRYPT_MODE, bobKey);
        isTrue("SM9 Cipher stream-mode round-trip", Arrays.areEqual(decX.doFinal(ctX), plaintext));

        // empty plaintext: the stream mode has no K1 for an empty message and must reject it
        // rather than loop retrying (the SM4 mode refuses it as one of the messages of fewer
        // than 16 bytes, further down)
        try
        {
            Cipher encXEmpty = Cipher.getInstance("SM9/XOR/NoPadding", "BC");
            encXEmpty.init(Cipher.ENCRYPT_MODE, bobPublic);
            encXEmpty.doFinal(new byte[0]);
            fail("SM9 stream mode encrypted an empty plaintext");
        }
        catch (BadPaddingException e)
        {
            // expected - no K1 to derive for an empty message
        }

        // a tampered C3 (MAC) must be rejected
        SM9Cipher parsed = SM9Cipher.getInstance(ct);
        byte[] brokenC3 = Arrays.clone(parsed.getC3());
        brokenC3[0] ^= 1;
        byte[] tampered = new SM9Cipher(parsed.getEnType(), parsed.getC1(), brokenC3, parsed.getC2()).getEncoded();
        try
        {
            Cipher decBad = Cipher.getInstance("SM9", "BC");
            decBad.init(Cipher.DECRYPT_MODE, bobKey);
            decBad.doFinal(tampered);
            fail("SM9 decryption accepted a tampered C3");
        }
        catch (BadPaddingException e)
        {
            // expected - MAC check failed
        }

        // a relabelled enType must be rejected. enType is not covered by C3 = MAC(K2, C2),
        // and at |C2| = 16 both modes ask the KDF for the same K1_len and so derive the same
        // K2 - an SM4 ciphertext of a one-block message presented as stream mode therefore
        // passes the MAC check, and a decrypt that took its mode from the wire would return
        // K1 xor C2, from which the SM4 key K1 and the plaintext both follow. The SM4 mode no
        // longer produces a one-block ciphertext, so the one relabelled here is a stored one,
        // decrypted with the user key of the master key it was made under.
        PrivateKeyInfo annexPkcs8 = new PrivateKeyInfo(new AlgorithmIdentifier(GMObjectIdentifiers.sm9encrypt),
            new DEROctetString(BigIntegers.asUnsignedByteArray(32, ANNEX_D_KE)));
        PrivateKey annexBobKey = ((SM9EncMasterPrivateKey)kf.generatePrivate(
            new PKCS8EncodedKeySpec(annexPkcs8.getEncoded())))
            .generateUserKeyPair(bob, SM9EncMasterPrivateKeyParameters.HID).getPrivate();
        isTrue("SM9 one-block SM4 ciphertext has a 16-byte C2", ONE_BLOCK_C2.length == 16);
        byte[] relabelled = new SM9Cipher(SM9Cipher.EN_TYPE_STREAM,
            ONE_BLOCK_C1, ONE_BLOCK_C3, ONE_BLOCK_C2).getEncoded();
        try
        {
            Cipher decRelabelled = Cipher.getInstance("SM9", "BC");
            decRelabelled.init(Cipher.DECRYPT_MODE, annexBobKey);
            decRelabelled.doFinal(relabelled);
            fail("SM9 decryption accepted an SM4 ciphertext relabelled as stream mode");
        }
        catch (BadPaddingException e)
        {
            // the configured mode decides, not the wire enType - and it is that check which
            // answers here, ahead of the engine's refusal of the length
            isTrue("SM9 relabelled enType rejection message",
                "SM9 decryption failed: SM9 ciphertext enType does not match the configured mode".equals(e.getMessage()));
        }

        // the configured mode settles nothing at |C2| = 16 when the Cipher is a stream-mode one:
        // the relabelled ciphertext then agrees with the configuration, the MAC check passes and
        // the output would be K1 xor C2 - so the stream mode refuses a 16-byte C2 outright, the
        // one C2 length at which the two modes collide
        try
        {
            Cipher decRelabelledStream = Cipher.getInstance("SM9/XOR/NoPadding", "BC");
            decRelabelledStream.init(Cipher.DECRYPT_MODE, annexBobKey);
            decRelabelledStream.doFinal(relabelled);
            fail("SM9 stream-mode decryption accepted a one-block SM4 ciphertext relabelled as stream mode");
        }
        catch (BadPaddingException e)
        {
            isTrue("SM9 stream-mode 16-byte C2 rejection message",
                "SM9 decryption failed: SM9 stream-mode ciphertext has a 16-byte C2".equals(e.getMessage()));
        }

        // it will not produce one either, since no stream-mode recipient could decrypt it; the
        // lengths either side of 16 round-trip, as does a 16-byte message in SM4 mode, whose
        // padded C2 is 32 bytes
        try
        {
            Cipher encX16 = Cipher.getInstance("SM9/XOR/NoPadding", "BC");
            encX16.init(Cipher.ENCRYPT_MODE, bobPublic);
            encX16.doFinal(new byte[16]);
            fail("SM9 stream mode encrypted a 16-byte plaintext");
        }
        catch (BadPaddingException e)
        {
            isTrue("SM9 stream-mode 16-byte message rejection message",
                "SM9 encryption failed: SM9 stream mode cannot encrypt a 16-byte message".equals(e.getMessage()));
        }
        int[] streamLengths = { 1, 15, 17, 32 };
        for (int i = 0; i != streamLengths.length; i++)
        {
            byte[] m = new byte[streamLengths[i]];
            for (int j = 0; j != m.length; j++)
            {
                m[j] = (byte)(j + 1);
            }
            Cipher encLen = Cipher.getInstance("SM9/XOR/NoPadding", "BC");
            encLen.init(Cipher.ENCRYPT_MODE, bobPublic);
            byte[] ctLen = encLen.doFinal(m);
            isTrue("SM9 stream-mode C2 is the message length at " + m.length + " bytes",
                SM9Cipher.getInstance(ctLen).getC2().length == m.length);
            Cipher decLen = Cipher.getInstance("SM9/XOR/NoPadding", "BC");
            decLen.init(Cipher.DECRYPT_MODE, bobKey);
            isTrue("SM9 Cipher stream-mode round-trip at " + m.length + " bytes",
                Arrays.areEqual(decLen.doFinal(ctLen), m));
        }
        Cipher enc16 = Cipher.getInstance("SM9", "BC");
        enc16.init(Cipher.ENCRYPT_MODE, bobPublic);
        byte[] ct16 = enc16.doFinal(new byte[16]);
        isTrue("SM9 SM4-mode 16-byte message pads to a 32-byte C2", SM9Cipher.getInstance(ct16).getC2().length == 32);
        Cipher dec16 = Cipher.getInstance("SM9", "BC");
        dec16.init(Cipher.DECRYPT_MODE, bobKey);
        isTrue("SM9 Cipher SM4-mode 16-byte round-trip", Arrays.areEqual(dec16.doFinal(ct16), new byte[16]));

        // the SM4 mode does not produce a 16-byte C2 either. A recipient that refuses the length
        // is protected by that alone, but the message given away is the SM4-mode sender's, who
        // cannot tell whether the recipient does - so no message that pads to one block is
        // encrypted, the empty one included
        int[] oneBlockLengths = { 0, 1, 15 };
        for (int i = 0; i != oneBlockLengths.length; i++)
        {
            try
            {
                Cipher encShort = Cipher.getInstance("SM9", "BC");
                encShort.init(Cipher.ENCRYPT_MODE, bobPublic);
                encShort.doFinal(new byte[oneBlockLengths[i]]);
                fail("SM9 SM4 mode encrypted a " + oneBlockLengths[i] + "-byte plaintext");
            }
            catch (BadPaddingException e)
            {
                isTrue("SM9 SM4-mode short message rejection message at " + oneBlockLengths[i] + " bytes",
                    "SM9 encryption failed: SM9 SM4 mode cannot encrypt a message shorter than 16 bytes".equals(e.getMessage()));
            }
        }

        // and with neither mode producing one it does not accept one: the stored one-block
        // ciphertext, genuine and under its own enType, is refused by the mode it was made in
        try
        {
            Cipher decOneBlock = Cipher.getInstance("SM9", "BC");
            decOneBlock.init(Cipher.DECRYPT_MODE, annexBobKey);
            decOneBlock.doFinal(new SM9Cipher(SM9Cipher.EN_TYPE_SM4,
                ONE_BLOCK_C1, ONE_BLOCK_C3, ONE_BLOCK_C2).getEncoded());
            fail("SM9 SM4-mode decryption accepted a ciphertext with a 16-byte C2");
        }
        catch (BadPaddingException e)
        {
            isTrue("SM9 SM4-mode 16-byte C2 rejection message",
                "SM9 decryption failed: SM9 SM4-mode ciphertext has a 16-byte C2".equals(e.getMessage()));
        }

        // and neither mode decrypts the other's ciphertext, relabelled or not
        try
        {
            Cipher decStreamAsSM4 = Cipher.getInstance("SM9", "BC");
            decStreamAsSM4.init(Cipher.DECRYPT_MODE, bobKey);
            decStreamAsSM4.doFinal(ctX);
            fail("SM9 SM4-mode decryption accepted a stream-mode ciphertext");
        }
        catch (BadPaddingException e)
        {
            // expected - enType disagrees with the configured mode
        }
        try
        {
            Cipher decSM4AsStream = Cipher.getInstance("SM9/XOR/NoPadding", "BC");
            decSM4AsStream.init(Cipher.DECRYPT_MODE, bobKey);
            decSM4AsStream.doFinal(ct);
            fail("SM9 stream-mode decryption accepted an SM4-mode ciphertext");
        }
        catch (BadPaddingException e)
        {
            // expected - enType disagrees with the configured mode
        }

        // guards: a master public key is not a recipient key, and no spec is accepted
        try
        {
            Cipher bad = Cipher.getInstance("SM9", "BC");
            bad.init(Cipher.ENCRYPT_MODE, masterPair.getPublic());
            fail("SM9 encryption accepted a master public key");
        }
        catch (InvalidKeyException e)
        {
            // expected
        }
        try
        {
            Cipher bad = Cipher.getInstance("SM9", "BC");
            bad.init(Cipher.ENCRYPT_MODE, bobPublic, new AlgorithmParameterSpec()
            {
            });
            fail("SM9 encryption accepted an AlgorithmParameterSpec");
        }
        catch (InvalidAlgorithmParameterException e)
        {
            // expected
        }

        // Reproduce both GM/T 0044.5-2016 Annex D encryption modes through the
        // provider. The KAT master key is reconstructed from its
        // known scalar through the public KeyFactory / PKCS#8 path.
        Map kat = loadVectors("sm9_encryption.txt");
        byte[] katScalar = BigIntegers.asUnsignedByteArray(32,
            new BigInteger((String)kat.get("ke"), 16));
        PrivateKeyInfo katPkcs8 = new PrivateKeyInfo(
            new AlgorithmIdentifier(GMObjectIdentifiers.sm9encrypt), new DEROctetString(katScalar));
        SM9EncMasterPrivateKey katMaster = (SM9EncMasterPrivateKey)kf.generatePrivate(
            new PKCS8EncodedKeySpec(katPkcs8.getEncoded()));
        KeyPair katBobPair = katMaster.generateUserKeyPair(hex(kat, "IDB"),
            SM9EncMasterPrivateKeyParameters.HID);
        checkEncryptionVector(kat, katBobPair, "SM9/XOR/NoPadding", SM9Cipher.EN_TYPE_STREAM, "modeA");
        checkEncryptionVector(kat, katBobPair, "SM9", SM9Cipher.EN_TYPE_SM4, "modeB");

        // SM9 KEM (GM/T 0044.4) through KeyGenerator.SM9-KEM - the same recipient
        // public key the cipher encrypts to
        KeyGenerator kemGen = KeyGenerator.getInstance("SM9-KEM", "BC");
        kemGen.init(new KEMGenerateSpec(bobPublic, "AES", 128));
        SecretKeyWithEncapsulation kemEnc = (SecretKeyWithEncapsulation)kemGen.generateKey();

        KeyGenerator kemExt = KeyGenerator.getInstance("SM9-KEM", "BC");
        kemExt.init(new KEMExtractSpec(bobKey, kemEnc.getEncapsulation(), "AES", 128));
        SecretKeyWithEncapsulation kemDec = (SecretKeyWithEncapsulation)kemExt.generateKey();
        isTrue("SM9-KEM encapsulate/decapsulate agree on a 128-bit key",
            kemEnc.getEncoded().length == 16 && Arrays.areEqual(kemEnc.getEncoded(), kemDec.getEncoded()));

        // a different recipient identity must not recover the same key
        PrivateKey mallory = masterPriv.generateUserKeyPair("Mallory".getBytes("US-ASCII"), SM9EncMasterPrivateKeyParameters.HID).getPrivate();
        KeyGenerator kemBad = KeyGenerator.getInstance("SM9-KEM", "BC");
        kemBad.init(new KEMExtractSpec(mallory, kemEnc.getEncapsulation(), "AES", 128));
        isTrue("SM9-KEM wrong identity yields a different key",
            !Arrays.areEqual(kemEnc.getEncoded(), ((SecretKeyWithEncapsulation)kemBad.generateKey()).getEncoded()));

        // a truncated encapsulation must be rejected cleanly
        try
        {
            KeyGenerator kemShort = KeyGenerator.getInstance("SM9-KEM", "BC");
            kemShort.init(new KEMExtractSpec(bobKey, new byte[10], "AES", 128));
            kemShort.generateKey();
            fail("SM9-KEM did not reject a truncated encapsulation");
        }
        catch (IllegalArgumentException e)
        {
            // expected - invalid SM9 KEM encapsulation
        }

        // a stored user private key round-trips through the KeyFactory without the master
        // private key, using only the encoding, the published master public key, the
        // identity and hid
        userKeySpecRoundTrip(kf, (SM9EncMasterPublicKey)masterPair.getPublic(), bobKey, bob,
            SM9EncMasterPrivateKeyParameters.HID, plaintext);
    }

    /**
     * A user's encryption private key does not carry the master public key, identity or hid
     * decryption needs, so it cannot be rebuilt from its bare PKCS#8 encoding the way a master
     * key can - SM9EncUserPrivateKeySpec supplies that context, letting a stored user key be
     * reconstituted with only the published master public key, never the master private key.
     */
    private void userKeySpecRoundTrip(KeyFactory kf, SM9EncMasterPublicKey masterPub, PrivateKey bobKey,
                                      byte[] identity, byte hid, byte[] plaintext)
        throws Exception
    {
        byte[] stored = bobKey.getEncoded();

        PrivateKey rebuilt = kf.generatePrivate(new SM9EncUserPrivateKeySpec(stored, masterPub, identity, hid));
        isTrue("SM9 user private key spec round-trip", Arrays.areEqual(stored, rebuilt.getEncoded()));
        isTrue("SM9 spec-rebuilt user key identity",
            Arrays.areEqual(identity, ((SM9EncUserPrivateKey)rebuilt).getIdentity()));

        Cipher enc = Cipher.getInstance("SM9", "BC");
        enc.init(Cipher.ENCRYPT_MODE, masterPub.getUserPublicKey(identity));
        byte[] ct = enc.doFinal(plaintext);

        Cipher dec = Cipher.getInstance("SM9", "BC");
        dec.init(Cipher.DECRYPT_MODE, rebuilt);
        isTrue("SM9 decryption with a spec-rebuilt user key round-trips",
            Arrays.areEqual(dec.doFinal(ct), plaintext));

        // the factory hands the same spec back for a user key
        SM9EncUserPrivateKeySpec roundTripSpec = (SM9EncUserPrivateKeySpec)kf.getKeySpec(
            bobKey, SM9EncUserPrivateKeySpec.class);
        isTrue("SM9 getKeySpec round-trip encoding", Arrays.areEqual(stored, roundTripSpec.getEncoded()));
        isTrue("SM9 getKeySpec round-trip master public key",
            Arrays.areEqual(masterPub.getEncoded(), roundTripSpec.getMasterPublicKey().getEncoded()));
        isTrue("SM9 getKeySpec round-trip identity", Arrays.areEqual(identity, roundTripSpec.getIdentity()));
        isTrue("SM9 getKeySpec round-trip hid", hid == roundTripSpec.getHid());
    }

    private void checkEncryptionVector(Map kat, KeyPair recipient, String transformation,
                                       int enType, String fieldPrefix)
        throws Exception
    {
        byte[] c1 = Arrays.concatenate(new byte[]{0x04}, hex(kat, "C1_x"), hex(kat, "C1_y"));
        byte[] expectedC2 = hex(kat, fieldPrefix + "_C2");
        byte[] expectedC3 = hex(kat, fieldPrefix + "_C3");
        byte[] message = hex(kat, "M");

        Cipher katEnc = Cipher.getInstance(transformation, "BC");
        katEnc.init(Cipher.ENCRYPT_MODE, recipient.getPublic(),
            new TestRandomBigInteger(256, hex(kat, "r")));
        SM9Cipher actual = SM9Cipher.getInstance(katEnc.doFinal(message));
        isTrue(fieldPrefix + " GM/T 0044.5 enType", actual.getEnType() == enType);
        isTrue(fieldPrefix + " GM/T 0044.5 C1", Arrays.areEqual(actual.getC1(), c1));
        isTrue(fieldPrefix + " GM/T 0044.5 C2", Arrays.areEqual(actual.getC2(), expectedC2));
        isTrue(fieldPrefix + " GM/T 0044.5 C3", Arrays.areEqual(actual.getC3(), expectedC3));

        byte[] officialCiphertext = new SM9Cipher(enType, c1, expectedC3, expectedC2).getEncoded();
        Cipher katDec = Cipher.getInstance(transformation, "BC");
        katDec.init(Cipher.DECRYPT_MODE, recipient.getPrivate());
        isTrue(fieldPrefix + " GM/T 0044.5 decrypt",
            Arrays.areEqual(katDec.doFinal(officialCiphertext), message));
    }

    private Map loadVectors(String fileName)
        throws Exception
    {
        Map vectors = new HashMap();
        BufferedReader br = new BufferedReader(
            new InputStreamReader(TestResourceFinder.findTestResource("crypto/sm9", fileName)));
        try
        {
            String line;
            while ((line = br.readLine()) != null)
            {
                line = line.trim();
                if (line.length() == 0 || line.startsWith("#"))
                {
                    continue;
                }

                int equals = line.indexOf('=');
                if (equals > 0)
                {
                    vectors.put(line.substring(0, equals).trim(), line.substring(equals + 1).trim());
                }
            }
        }
        finally
        {
            br.close();
        }
        return vectors;
    }

    private byte[] hex(Map vectors, String key)
    {
        return Hex.decode((String)vectors.get(key));
    }

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());
        runTest(new SM9CipherTest());
    }
}
