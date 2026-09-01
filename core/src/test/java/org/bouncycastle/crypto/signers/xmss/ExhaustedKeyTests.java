package org.bouncycastle.crypto.signers.xmss;

import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.ExhaustedPrivateKeyException;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.XMSSKeyPairGenerator;
import org.bouncycastle.crypto.generators.XMSSMTKeyPairGenerator;
import org.bouncycastle.crypto.params.XMSSKeyGenerationParameters;
import org.bouncycastle.crypto.params.XMSSMTKeyGenerationParameters;
import org.bouncycastle.crypto.params.XMSSMTParameters;
import org.bouncycastle.crypto.params.XMSSMTPrivateKeyParameters;
import org.bouncycastle.crypto.params.XMSSParameters;
import org.bouncycastle.crypto.params.XMSSPrivateKeyParameters;
import org.bouncycastle.crypto.signers.XMSSMTSigner;
import org.bouncycastle.crypto.signers.XMSSSigner;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

/**
 * A used-up XMSS / XMSS^MT private key has to survive being written out and read back. It is the
 * one state that most needs to persist - a key restored from an earlier saved state would sign
 * again with a one-time key it has already used - and it is the state the index bound is widest
 * for: an exhausted key carries the index one past its last leaf, which is the placeholder
 * traversal state BDS installs when the final one-time key is consumed.
 */
public class ExhaustedKeyTests
    extends TestCase
{
    private static final int HEIGHT = 4;
    private static final int LAYERS = 2;

    private XMSSParameters xmssParams()
    {
        return new XMSSParameters(HEIGHT, new SHA256Digest());
    }

    private XMSSMTParameters xmssMTParams()
    {
        return new XMSSMTParameters(HEIGHT, LAYERS, new SHA256Digest());
    }

    private XMSSPrivateKeyParameters exhaustedXMSS(XMSSParameters params)
    {
        XMSSKeyPairGenerator kpg = new XMSSKeyPairGenerator();

        kpg.init(new XMSSKeyGenerationParameters(params, new SecureRandom()));

        XMSSPrivateKeyParameters privKey = (XMSSPrivateKeyParameters)kpg.generateKeyPair().getPrivate();

        for (int i = 0; i != (1 << HEIGHT); i++)
        {
            privKey.rollKey();
        }

        assertEquals(0, privKey.getUsagesRemaining());

        return privKey;
    }

    private XMSSMTPrivateKeyParameters exhaustedXMSSMT(XMSSMTParameters params)
    {
        XMSSMTKeyPairGenerator kpg = new XMSSMTKeyPairGenerator();

        kpg.init(new XMSSMTKeyGenerationParameters(params, new SecureRandom()));

        XMSSMTPrivateKeyParameters privKey = (XMSSMTPrivateKeyParameters)kpg.generateKeyPair().getPrivate();

        for (int i = 0; i != (1 << HEIGHT); i++)
        {
            privKey.rollKey();
        }

        assertEquals(0, privKey.getUsagesRemaining());

        return privKey;
    }

    /**
     * The encoding of a used-up key can be read back, and what comes back is still used up.
     */
    public void testExhaustedKeyRoundTripsAndStaysExhausted()
        throws Exception
    {
        XMSSParameters params = xmssParams();
        XMSSPrivateKeyParameters privKey = exhaustedXMSS(params);

        XMSSPrivateKeyParameters restored = new XMSSPrivateKeyParameters.Builder(params)
            .withPrivateKey(privKey.getEncoded()).build();

        assertEquals(0, restored.getUsagesRemaining());
        assertEquals(privKey.getIndex(), restored.getIndex());
        assertEquals((1 << HEIGHT) - 1, restored.getBDSState().getMaxIndex());
        assertTrue(Arrays.areEqual(privKey.getEncoded(), restored.getEncoded()));

        XMSSMTParameters mtParams = xmssMTParams();
        XMSSMTPrivateKeyParameters mtPrivKey = exhaustedXMSSMT(mtParams);

        XMSSMTPrivateKeyParameters mtRestored = new XMSSMTPrivateKeyParameters.Builder(mtParams)
            .withPrivateKey(mtPrivKey.getEncoded()).build();

        assertEquals(0, mtRestored.getUsagesRemaining());
        assertEquals(mtPrivKey.getIndex(), mtRestored.getIndex());
        assertTrue(Arrays.areEqual(mtPrivKey.getEncoded(), mtRestored.getEncoded()));
    }

    /**
     * The same through PKCS#8, which is the path a key takes into and out of a keystore.
     */
    public void testExhaustedKeyRoundTripsThroughPrivateKeyInfo()
        throws Exception
    {
        XMSSPrivateKeyParameters privKey = exhaustedXMSS(xmssParams());

        XMSSPrivateKeyParameters restored = (XMSSPrivateKeyParameters)PrivateKeyFactory.createKey(
            PrivateKeyInfoFactory.createPrivateKeyInfo(privKey).getEncoded());

        assertEquals(0, restored.getUsagesRemaining());
        assertEquals(privKey.getIndex(), restored.getIndex());

        XMSSMTPrivateKeyParameters mtPrivKey = exhaustedXMSSMT(xmssMTParams());

        XMSSMTPrivateKeyParameters mtRestored = (XMSSMTPrivateKeyParameters)PrivateKeyFactory.createKey(
            PrivateKeyInfoFactory.createPrivateKeyInfo(mtPrivKey).getEncoded());

        assertEquals(0, mtRestored.getUsagesRemaining());
        assertEquals(mtPrivKey.getIndex(), mtRestored.getIndex());
    }

    /**
     * A restored exhausted key refuses to sign, in both families. Restoring one that could sign
     * again would reuse a one-time key, which is the failure RFC 8391 sec. 1.1 exists to prevent.
     */
    public void testRestoredExhaustedKeyRefusesToSign()
        throws Exception
    {
        XMSSParameters params = xmssParams();
        XMSSPrivateKeyParameters restored = new XMSSPrivateKeyParameters.Builder(params)
            .withPrivateKey(exhaustedXMSS(params).getEncoded()).build();

        XMSSSigner signer = new XMSSSigner();

        signer.init(true, restored);
        try
        {
            signer.generateSignature(new byte[]{ 1, 2, 3 });
            fail("no exception");
        }
        catch (ExhaustedPrivateKeyException e)
        {
            assertEquals("no usages of private key remaining", e.getMessage());
        }

        XMSSMTParameters mtParams = xmssMTParams();
        XMSSMTPrivateKeyParameters mtRestored = new XMSSMTPrivateKeyParameters.Builder(mtParams)
            .withPrivateKey(exhaustedXMSSMT(mtParams).getEncoded()).build();

        XMSSMTSigner mtSigner = new XMSSMTSigner();

        mtSigner.init(true, mtRestored);
        try
        {
            mtSigner.generateSignature(new byte[]{ 1, 2, 3 });
            fail("no exception");
        }
        catch (ExhaustedPrivateKeyException e)
        {
            assertEquals("no usages of private key remaining", e.getMessage());
        }
    }

    /**
     * A key is also left at its one-past-the-end index by handing out its last usages as a shard,
     * rather than by rolling to the end, and the shard itself carries a maximum index short of the
     * tree's. Both encodings have to survive the round trip.
     */
    public void testKeyExhaustedByShardExtractionRoundTrips()
        throws Exception
    {
        XMSSParameters params = xmssParams();
        XMSSKeyPairGenerator kpg = new XMSSKeyPairGenerator();

        kpg.init(new XMSSKeyGenerationParameters(params, new SecureRandom()));

        XMSSPrivateKeyParameters privKey = (XMSSPrivateKeyParameters)kpg.generateKeyPair().getPrivate();

        XMSSPrivateKeyParameters shard = privKey.extractKeyShard((int)privKey.getUsagesRemaining());

        assertEquals(0, privKey.getUsagesRemaining());
        assertEquals(1 << HEIGHT, shard.getUsagesRemaining());

        XMSSPrivateKeyParameters restored = new XMSSPrivateKeyParameters.Builder(params)
            .withPrivateKey(privKey.getEncoded()).build();

        assertEquals(0, restored.getUsagesRemaining());

        // the shard covers the whole tree here, so take a smaller one to reach a maximum index
        // short of the tree's, exhaust that, and round trip it too
        kpg.init(new XMSSKeyGenerationParameters(params, new SecureRandom()));

        XMSSPrivateKeyParameters parent = (XMSSPrivateKeyParameters)kpg.generateKeyPair().getPrivate();
        XMSSPrivateKeyParameters smallShard = parent.extractKeyShard(2);

        assertEquals(1, smallShard.getBDSState().getMaxIndex());

        smallShard.rollKey();
        smallShard.rollKey();

        assertEquals(0, smallShard.getUsagesRemaining());

        XMSSPrivateKeyParameters restoredShard = new XMSSPrivateKeyParameters.Builder(params)
            .withPrivateKey(smallShard.getEncoded()).build();

        assertEquals(0, restoredShard.getUsagesRemaining());
        assertEquals(smallShard.getIndex(), restoredShard.getIndex());
    }

    /**
     * The index bound is one leaf wider than the signing bound, not open: one past the exhausted
     * index is still out of bounds, so is a negative index, and an index that does not match the
     * traversal state it arrived with is still caught.
     */
    public void testIndexBeyondExhaustionStillRejected()
        throws Exception
    {
        XMSSParameters params = xmssParams();
        byte[] encoded = exhaustedXMSS(params).getEncoded();

        checkRejected(params, withIndex(encoded, (1 << HEIGHT) + 1), "index out of bounds");
        checkRejected(params, withIndex(encoded, -1), "index out of bounds");
        checkRejected(params, withIndex(encoded, Integer.MAX_VALUE), "index out of bounds");
        checkRejected(params, withIndex(encoded, 3), "BDS state has wrong index");
    }

    private byte[] withIndex(byte[] encoded, int index)
    {
        byte[] altered = Arrays.clone(encoded);

        Pack.intToBigEndian(index, altered, 0);

        return altered;
    }

    private void checkRejected(XMSSParameters params, byte[] encoded, String message)
    {
        try
        {
            new XMSSPrivateKeyParameters.Builder(params).withPrivateKey(encoded).build();
            fail("no exception");
        }
        catch (IllegalArgumentException e)
        {
            assertEquals(message, e.getMessage());
        }
    }
}
