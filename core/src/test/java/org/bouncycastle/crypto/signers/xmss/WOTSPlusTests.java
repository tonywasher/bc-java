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

        byte[][] signature = wotsPlus.sign(messageDigest, otsHashAddress);

        assertEquals(wotsPlus.getParams().getLen(), signature.length);

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

        byte[][] signature = wotsPlus.sign(messageDigest, otsHashAddress);

        WOTSPlusPublicKeyParameters expected = wotsPlus.getPublicKey(otsHashAddress);
        WOTSPlusPublicKeyParameters recovered =
            wotsPlus.getPublicKeyFromSignature(otherDigest, signature, otsHashAddress);

        assertFalse("a signature verified against the wrong digest",
            XMSSUtil.areEqual(expected.toByteArray(), recovered.toByteArray()));
    }

    /**
     * {@link WOTSPlusPublicKeyParameters} holds the blocks its caller built rather than copies of
     * them, and {@link WOTSPlusPublicKeyParameters#toNodes()} hands those same blocks to the
     * L-tree walk. What makes that safe is that the walk only reads them - it overwrites the array
     * of nodes it is given, never the value inside one - so compressing a key leaves the key as it
     * was.
     */
    public void testCompressingAPublicKeyDoesNotDisturbIt()
    {
        byte[] secretKeySeed = new byte[N];
        byte[] publicSeed = new byte[N];
        Arrays.fill(secretKeySeed, (byte)0x06);
        Arrays.fill(publicSeed, (byte)0x07);

        WOTSPlus wotsPlus = newWOTSPlus();
        wotsPlus.importKeys(secretKeySeed, publicSeed);

        OTSHashAddress otsHashAddress = (OTSHashAddress)new OTSHashAddress.Builder().withOTSAddress(3).build();
        WOTSPlusPublicKeyParameters publicKey = wotsPlus.getPublicKey(otsHashAddress);
        byte[][] before = publicKey.toByteArray();

        byte[] lTreeAddress = new LTreeAddress.Builder().withLTreeAddress(3).build().toByteArray();
        XMSSNodeUtil.lTree(wotsPlus, publicKey, lTreeAddress, new byte[N], new byte[2 * N]);

        assertTrue("compressing a public key changed the key",
            XMSSUtil.areEqual(before, publicKey.toByteArray()));
    }

    /**
     * A WOTS+ signature is the len blocks its caller built, and
     * {@link WOTSPlusPublicKeyParameters} likewise holds those blocks rather than copies of them,
     * so each has to be an array of its own. That is chain()'s doing: it copies its starting value
     * out rather than handing it back when it takes no steps at all. Signing takes none for every
     * base-w digit of the message that is zero, chaining each from one buffer it reuses across the
     * len chains; recovery takes none for every digit equal to w - 1, chaining those from the
     * signature's own blocks. A digest of 0x0f bytes is every digit alternately 0 and 15, so each
     * of the len positions is a zero-step chain on one of the two sides.
     */
    public void testChainedBlocksAreArraysOfTheirOwn()
    {
        byte[] secretKeySeed = new byte[N];
        byte[] publicSeed = new byte[N];
        byte[] messageDigest = new byte[N];
        Arrays.fill(secretKeySeed, (byte)0x08);
        Arrays.fill(publicSeed, (byte)0x09);
        Arrays.fill(messageDigest, (byte)0x0f);

        OTSHashAddress otsHashAddress = (OTSHashAddress)new OTSHashAddress.Builder().build();

        WOTSPlus wotsPlus = newWOTSPlus();
        wotsPlus.importKeys(secretKeySeed, publicSeed);

        int len = wotsPlus.getParams().getLen();
        byte[][] signature = wotsPlus.sign(messageDigest, otsHashAddress);
        for (int i = 0; i != len; i++)
        {
            for (int j = i + 1; j != len; j++)
            {
                assertNotSame("two blocks of one signature are the same array",
                    signature[i], signature[j]);
            }
        }

        WOTSPlusPublicKeyParameters recovered =
            wotsPlus.getPublicKeyFromSignature(messageDigest, signature, otsHashAddress);
        byte[][] before = recovered.toByteArray();
        for (int i = 0; i != len; i++)
        {
            signature[i][0] ^= 0x01;
        }

        assertTrue("a recovered public key shares storage with the signature it came from",
            XMSSUtil.areEqual(before, recovered.toByteArray()));
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
