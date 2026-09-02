package org.bouncycastle.crypto.signers.xmss;

import java.io.IOException;
import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.generators.XMSSKeyPairGenerator;
import org.bouncycastle.crypto.params.XMSSKeyGenerationParameters;
import org.bouncycastle.crypto.params.XMSSParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
import org.bouncycastle.pqc.asn1.XMSSKeyParams;
import org.bouncycastle.pqc.asn1.XMSSPrivateKey;
import org.bouncycastle.pqc.asn1.XMSSPublicKey;

/**
 * A tree height is only meaningful up to the point where an int index can still count the tree's
 * leaves, and the parameter classes take one from whoever asks - including, through the ASN.1 key
 * parameters, from a key that arrived from somewhere else.
 */
public class ParameterBoundsTests
    extends TestCase
{
    public void testHeightAboveMaximumRefused()
    {
        // 31 above a multiple of 32 wraps (1 << height) to a negative, which left key generation
        // with no leaves to build from; the rest wrap to a small positive, which built a shorter
        // tree than the one asked for
        int[] heights = new int[]{31, 32, 33, 62, 63, 64, 95, 96, Integer.MAX_VALUE};

        for (int i = 0; i != heights.length; i++)
        {
            try
            {
                new XMSSParameters(heights[i], NISTObjectIdentifiers.id_sha256);
                fail("height " + heights[i] + " accepted");
            }
            catch (IllegalArgumentException e)
            {
                assertEquals("height must be <= 30", e.getMessage());
            }
        }
    }

    public void testHeightBelowMinimumRefused()
    {
        int[] heights = new int[]{Integer.MIN_VALUE, -1, 0, 1};

        for (int i = 0; i != heights.length; i++)
        {
            try
            {
                new XMSSParameters(heights[i], NISTObjectIdentifiers.id_sha256);
                fail("height " + heights[i] + " accepted");
            }
            catch (IllegalArgumentException e)
            {
                assertEquals("height must be >= 2", e.getMessage());
            }
        }
    }

    /**
     * The height in an XMSSKeyParams is whatever the encoded key said it was, so it reaches the
     * parameter set straight off the wire and has to be reported the way the rest of a malformed
     * key is - as an IOException out of the factory, not as an unchecked exception through it.
     */
    public void testHeightFromEncodedKeyReported()
        throws Exception
    {
        AlgorithmIdentifier treeDigest = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);
        AlgorithmIdentifier algId = new AlgorithmIdentifier(PQCObjectIdentifiers.xmss,
            new XMSSKeyParams(31, treeDigest));

        try
        {
            PublicKeyFactory.createKey(new SubjectPublicKeyInfo(algId,
                new XMSSPublicKey(new byte[32], new byte[32])));
            fail("height 31 in public key parameters accepted");
        }
        catch (IOException e)
        {
            assertEquals("malformed XMSS public key: height must be <= 30", e.getMessage());
        }

        try
        {
            PrivateKeyFactory.createKey(new PrivateKeyInfo(algId,
                new XMSSPrivateKey(0, new byte[32], new byte[32], new byte[32], new byte[32], null)));
            fail("height 31 in private key parameters accepted");
        }
        catch (IOException e)
        {
            assertEquals("malformed XMSS private key: height must be <= 30", e.getMessage());
        }
    }

    /**
     * The bound is the tallest tree the traversal state will validate, not something narrower:
     * a height BDS accepts has to remain constructible.
     */
    public void testMaximumHeightStillConstructs()
    {
        XMSSParameters params = new XMSSParameters(XMSSParameters.MAX_HEIGHT,
            NISTObjectIdentifiers.id_sha256);

        assertEquals(30, params.getHeight());

        // and the smallest tree, generated through to a usable key pair
        XMSSKeyPairGenerator kpg = new XMSSKeyPairGenerator();

        kpg.init(new XMSSKeyGenerationParameters(
            new XMSSParameters(2, NISTObjectIdentifiers.id_sha256), new SecureRandom()));

        assertNotNull(kpg.generateKeyPair().getPrivate());
    }
}
