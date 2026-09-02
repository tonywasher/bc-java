package org.bouncycastle.crypto.signers.xmss;

import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.util.Arrays;

/**
 * WOTS+ (RFC 8391 sec. 3), the one-time signature XMSS is built on. It is package-private, so this
 * is the only place its verification relation - that the public key recovered from a signature
 * equals the signer's own public key, and only for the digest that was signed - can be asserted
 * directly rather than through a whole XMSS signature.
 */
public class WOTSPlusTests
    extends TestCase
{
    private static final int N = 32;

    private WOTSPlus newWOTSPlus()
    {
        return new WOTSPlus(new WOTSPlusParameters(NISTObjectIdentifiers.id_sha256, N));
    }

    public void testPublicKeyFromSignatureMatchesSigner()
    {
        SecureRandom random = new SecureRandom();
        byte[] secretKeySeed = new byte[N];
        byte[] publicSeed = new byte[N];
        byte[] messageDigest = new byte[N];
        random.nextBytes(secretKeySeed);
        random.nextBytes(publicSeed);
        random.nextBytes(messageDigest);

        OTSHashAddress otsHashAddress = (OTSHashAddress)new OTSHashAddress.Builder().withOTSAddress(3).build();

        WOTSPlus wotsPlus = newWOTSPlus();
        wotsPlus.importKeys(secretKeySeed, publicSeed);

        WOTSPlusSignature signature = wotsPlus.sign(messageDigest, otsHashAddress);

        assertEquals(wotsPlus.getParams().getLen(), signature.toByteArray().length);

        WOTSPlusPublicKeyParameters expected = wotsPlus.getPublicKey(otsHashAddress);
        WOTSPlusPublicKeyParameters recovered =
            wotsPlus.getPublicKeyFromSignature(messageDigest, signature, otsHashAddress);

        // XMSSUtil.areEqual, not org.bouncycastle.util.Arrays.areEqual: the latter has no
        // byte[][] overload, so it binds to areEqual(Object[], Object[]) and compares the rows by
        // reference - which makes the assertion below trivially true whatever the keys are
        assertTrue("public key recovered from signature does not match signer",
            XMSSUtil.areEqual(expected.toByteArray(), recovered.toByteArray()));
    }

    public void testPublicKeyFromSignatureDiffersForOtherDigest()
    {
        byte[] secretKeySeed = new byte[N];
        byte[] publicSeed = new byte[N];
        byte[] messageDigest = new byte[N];
        byte[] otherDigest = new byte[N];
        Arrays.fill(secretKeySeed, (byte)0x01);
        Arrays.fill(publicSeed, (byte)0x02);
        Arrays.fill(messageDigest, (byte)0x03);
        Arrays.fill(otherDigest, (byte)0x04);

        OTSHashAddress otsHashAddress = (OTSHashAddress)new OTSHashAddress.Builder().build();

        WOTSPlus wotsPlus = newWOTSPlus();
        wotsPlus.importKeys(secretKeySeed, publicSeed);

        WOTSPlusSignature signature = wotsPlus.sign(messageDigest, otsHashAddress);

        WOTSPlusPublicKeyParameters expected = wotsPlus.getPublicKey(otsHashAddress);
        WOTSPlusPublicKeyParameters recovered =
            wotsPlus.getPublicKeyFromSignature(otherDigest, signature, otsHashAddress);

        assertFalse("a signature verified against the wrong digest",
            XMSSUtil.areEqual(expected.toByteArray(), recovered.toByteArray()));
    }

    /**
     * The one-time secret key is derived from the seed and the OTS hash address, so two leaves of
     * the same tree must not share it.
     */
    public void testSecretKeyIsPerAddress()
    {
        byte[] secretKeySeed = new byte[N];
        Arrays.fill(secretKeySeed, (byte)0x05);

        WOTSPlus wotsPlus = newWOTSPlus();

        byte[] first = wotsPlus.getWOTSPlusSecretKey(secretKeySeed,
            (OTSHashAddress)new OTSHashAddress.Builder().withOTSAddress(0).build());
        byte[] second = wotsPlus.getWOTSPlusSecretKey(secretKeySeed,
            (OTSHashAddress)new OTSHashAddress.Builder().withOTSAddress(1).build());

        assertFalse("two leaves share a WOTS+ secret key", Arrays.areEqual(first, second));
    }

    /**
     * len = len1 + len2 (RFC 8391 sec. 3.1.1) for w = 16: 67 for n = 32, 131 for n = 64.
     */
    public void testLenForStandardParameterSets()
    {
        assertEquals(67, XMSSEngine.getWOTSPlusLen(NISTObjectIdentifiers.id_sha256, 32));
        assertEquals(131, XMSSEngine.getWOTSPlusLen(NISTObjectIdentifiers.id_sha512, 64));
        assertEquals(16, XMSSEngine.getWinternitzParameter());
    }

    /**
     * A WOTS+ secret key, public key and signature are the same len-by-n array, and the three
     * classes carrying one had a copy each of the check on that shape. They had drifted: the
     * secret key called a wrong element count a "format" problem where the other two called it a
     * "size" one. Written as a pair of tables so the two halves have to keep agreeing.
     */
    public void testWOTSPlusShapeRejectionsAgree()
    {
        WOTSPlusParameters params = new WOTSPlusParameters(NISTObjectIdentifiers.id_sha256);
        int len = params.getLen();
        int n = params.getTreeDigestSize();

        byte[][] shortArray = new byte[len - 1][n];
        byte[][] shortElement = new byte[len][n];
        byte[][] nullElement = new byte[len][];

        shortElement[len - 1] = new byte[n - 1];
        nullElement[0] = new byte[n];

        byte[][][] bad = new byte[][][]{null, nullElement, shortArray, shortElement};
        String[] expected = new String[]{" == null", " byte array == null", " size", " format"};

        for (int i = 0; i != bad.length; i++)
        {
            assertEquals("privateKey" + expected[i], rejection(params, bad[i], 0));
            assertEquals("publicKey" + expected[i], rejection(params, bad[i], 1));
            assertEquals("signature" + expected[i], rejection(params, bad[i], 2));
        }
    }

    /**
     * The message the class at {@code which} rejects {@code value} with, with the leading "wrong "
     * of the size and format messages dropped so all four read as a suffix of the field's name.
     */
    private static String rejection(WOTSPlusParameters params, byte[][] value, int which)
    {
        try
        {
            switch (which)
            {
            case 0:
                new WOTSPlusPrivateKeyParameters(params, value);
                break;
            case 1:
                new WOTSPlusPublicKeyParameters(params, value);
                break;
            default:
                new WOTSPlusSignature(params, value);
                break;
            }
        }
        catch (NullPointerException e)
        {
            return e.getMessage();
        }
        catch (IllegalArgumentException e)
        {
            return e.getMessage().substring("wrong ".length());
        }

        return "accepted";
    }
}
