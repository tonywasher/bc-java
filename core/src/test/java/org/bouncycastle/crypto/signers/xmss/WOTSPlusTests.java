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
    }

    /**
     * A WOTS+ public key and signature are the same len-by-n array, and the classes carrying one
     * had a copy each of the check on that shape. They had drifted, one calling a wrong element
     * count a "format" problem where the others called it a "size" one, so the check now lives
     * once in {@link WOTSPlusParameters#checkedClone}. Written as a pair of tables so the two
     * halves have to keep agreeing.
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
            assertEquals("publicKey" + expected[i], rejection(params, bad[i], 0));
            assertEquals("signature" + expected[i], rejection(params, bad[i], 1));
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
            if (which == 0)
            {
                new WOTSPlusPublicKeyParameters(params, value);
            }
            else
            {
                new WOTSPlusSignature(params, value);
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

    /**
     * importKeys is the one place a WOTS+ instance takes key material, and the two things it has
     * to say about a wrong argument are that a wrong length is a wrong length - the message the
     * rest of the package uses for it - and that an absent one is not a field to be filled in.
     * The second is what stops the shared check's allocate-when-absent branch being taken here,
     * where it would import an all-zero one-time key instead of failing.
     */
    public void testImportKeysRejectsWrongSizeAndAbsentSeeds()
    {
        String[] names = new String[]{"secretKeySeed", "publicSeed"};
        int[] lengths = new int[]{0, N - 1, N + 1};

        for (int i = 0; i != names.length; i++)
        {
            for (int j = 0; j != lengths.length; j++)
            {
                byte[] secretKeySeed = new byte[i == 0 ? lengths[j] : N];
                byte[] publicSeed = new byte[i == 0 ? N : lengths[j]];

                try
                {
                    newWOTSPlus().importKeys(secretKeySeed, publicSeed);
                    fail(names[i] + " of " + lengths[j] + " bytes accepted");
                }
                catch (IllegalArgumentException e)
                {
                    assertEquals("size of " + names[i] + " needs to be equal to size of digest",
                        e.getMessage());
                }
            }

            try
            {
                newWOTSPlus().importKeys(i == 0 ? null : new byte[N], i == 0 ? new byte[N] : null);
                fail("an absent " + names[i] + " was accepted");
            }
            catch (NullPointerException e)
            {
                // an absent seed is a caller error here, not an optional field: it must not be
                // quietly replaced by an all-zero one
            }
        }
    }
}
