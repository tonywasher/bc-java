package org.bouncycastle.crypto.signers.xmss;

import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
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

/**
 * getUpdatedPrivateKey() is how a caller collects the advanced state it is obliged to persist, so
 * it is reached in situations where there is no state to collect: a signer that was never
 * initialised for signing, one initialised only for verification, and one whose key a previous
 * call has already taken. All three report an absent key the same way, in both families.
 */
public class SignerStateHandoverTests
    extends TestCase
{
    private static final int HEIGHT = 4;
    private static final int LAYERS = 2;

    private AsymmetricCipherKeyPair xmssKeyPair(XMSSParameters params)
    {
        XMSSKeyPairGenerator kpg = new XMSSKeyPairGenerator();

        kpg.init(new XMSSKeyGenerationParameters(params, new SecureRandom()));

        return kpg.generateKeyPair();
    }

    private AsymmetricCipherKeyPair xmssMTKeyPair(XMSSMTParameters params)
    {
        XMSSMTKeyPairGenerator kpg = new XMSSMTKeyPairGenerator();

        kpg.init(new XMSSMTKeyGenerationParameters(params, new SecureRandom()));

        return kpg.generateKeyPair();
    }

    /**
     * Having signed, the first call hands the advanced key over and the second reports that there
     * is nothing left to hand over - rather than raising a NullPointerException on the way in.
     */
    public void testKeyCollectedOnlyOnceAfterSigning()
    {
        AsymmetricCipherKeyPair kp = xmssKeyPair(new XMSSParameters(HEIGHT, new SHA256Digest()));
        XMSSSigner signer = new XMSSSigner();

        signer.init(true, kp.getPrivate());
        signer.generateSignature(new byte[]{ 1, 2, 3 });

        assertSame(kp.getPrivate(), signer.getUpdatedPrivateKey());
        assertNull(signer.getUpdatedPrivateKey());

        AsymmetricCipherKeyPair mtKp = xmssMTKeyPair(new XMSSMTParameters(HEIGHT, LAYERS, new SHA256Digest()));
        XMSSMTSigner mtSigner = new XMSSMTSigner();

        mtSigner.init(true, mtKp.getPrivate());
        mtSigner.generateSignature(new byte[]{ 1, 2, 3 });

        assertSame(mtKp.getPrivate(), mtSigner.getUpdatedPrivateKey());
        assertNull(mtSigner.getUpdatedPrivateKey());
    }

    /**
     * A signer with no signing key to give back says so, whether it was never initialised at all
     * or initialised for verification.
     */
    public void testNoKeyToCollectReportedAsAbsent()
    {
        AsymmetricCipherKeyPair kp = xmssKeyPair(new XMSSParameters(HEIGHT, new SHA256Digest()));

        assertNull(new XMSSSigner().getUpdatedPrivateKey());

        XMSSSigner verifier = new XMSSSigner();

        verifier.init(false, kp.getPublic());
        assertNull(verifier.getUpdatedPrivateKey());

        AsymmetricCipherKeyPair mtKp = xmssMTKeyPair(new XMSSMTParameters(HEIGHT, LAYERS, new SHA256Digest()));

        assertNull(new XMSSMTSigner().getUpdatedPrivateKey());

        XMSSMTSigner mtVerifier = new XMSSMTSigner();

        mtVerifier.init(false, mtKp.getPublic());
        assertNull(mtVerifier.getUpdatedPrivateKey());
    }

    /**
     * Initialised but not yet used, the key stays with the caller and the signer keeps the shard
     * covering the usage it has not spent - the "leave it in place" half of the contract.
     */
    public void testInitialisedButUnusedSignerHandsBackTheKeyItWasGiven()
    {
        AsymmetricCipherKeyPair kp = xmssKeyPair(new XMSSParameters(HEIGHT, new SHA256Digest()));
        XMSSPrivateKeyParameters privKey = (XMSSPrivateKeyParameters)kp.getPrivate();
        XMSSSigner signer = new XMSSSigner();

        signer.init(true, privKey);

        assertSame(privKey, signer.getUpdatedPrivateKey());
        assertEquals((1 << HEIGHT) - 1, privKey.getUsagesRemaining());
        assertEquals(1, signer.getUsagesRemaining());   // the shard covers the one unspent usage

        AsymmetricCipherKeyPair mtKp = xmssMTKeyPair(new XMSSMTParameters(HEIGHT, LAYERS, new SHA256Digest()));
        XMSSMTPrivateKeyParameters mtPrivKey = (XMSSMTPrivateKeyParameters)mtKp.getPrivate();
        XMSSMTSigner mtSigner = new XMSSMTSigner();

        mtSigner.init(true, mtPrivKey);

        assertSame(mtPrivKey, mtSigner.getUpdatedPrivateKey());
        assertEquals((1 << HEIGHT) - 1, mtPrivKey.getUsagesRemaining());
        assertEquals(1, mtSigner.getUsagesRemaining());   // the shard covers the one unspent usage
    }

    /**
     * A signer given a key with nothing left to spend still has state its caller has to store, and
     * asking for it used to report the shard API's own "usageCount exceeds usages remaining" to a
     * caller that never asked for a shard. There is no next usage to leave behind, so the spent key
     * itself is what comes back - twice over, since nothing was consumed handing it over.
     */
    public void testSpentKeyHandedBackRatherThanShardedAgain()
    {
        AsymmetricCipherKeyPair kp = xmssKeyPair(new XMSSParameters(HEIGHT, new SHA256Digest()));
        XMSSPrivateKeyParameters privKey = (XMSSPrivateKeyParameters)kp.getPrivate();

        privKey.extractKeyShard(1 << HEIGHT);          // takes every usage the key had

        assertEquals(0, privKey.getUsagesRemaining());

        XMSSSigner signer = new XMSSSigner();

        signer.init(true, privKey);

        assertSame(privKey, signer.getUpdatedPrivateKey());
        assertSame(privKey, signer.getUpdatedPrivateKey());
        assertEquals(0, privKey.getUsagesRemaining());

        AsymmetricCipherKeyPair mtKp = xmssMTKeyPair(new XMSSMTParameters(HEIGHT, LAYERS, new SHA256Digest()));
        XMSSMTPrivateKeyParameters mtPrivKey = (XMSSMTPrivateKeyParameters)mtKp.getPrivate();

        mtPrivKey.extractKeyShard(1 << HEIGHT);

        assertEquals(0, mtPrivKey.getUsagesRemaining());

        XMSSMTSigner mtSigner = new XMSSMTSigner();

        mtSigner.init(true, mtPrivKey);

        assertSame(mtPrivKey, mtSigner.getUpdatedPrivateKey());
        assertSame(mtPrivKey, mtSigner.getUpdatedPrivateKey());
        assertEquals(0, mtPrivKey.getUsagesRemaining());
    }

    /**
     * An argument that was never supplied is the caller's mistake, not a signature that failed to
     * verify - bytes that will not decode are reported as false, but there are no bytes here. The
     * XMSS signer used to answer a null message with a NullPointerException raised from inside the
     * hash function, and a null signature with false; XMSS^MT has always named both.
     */
    public void testVerifyNamesAnAbsentArgument()
    {
        AsymmetricCipherKeyPair kp = xmssKeyPair(new XMSSParameters(HEIGHT, new SHA256Digest()));
        XMSSSigner signer = new XMSSSigner();

        signer.init(true, kp.getPrivate());

        byte[] message = new byte[]{ 1, 2, 3 };
        byte[] signature = signer.generateSignature(message);
        XMSSSigner verifier = new XMSSSigner();

        verifier.init(false, kp.getPublic());

        assertTrue(verifier.verifySignature(message, signature));
        checkAbsentArgument(verifier, null, signature, "message == null");
        checkAbsentArgument(verifier, message, null, "signature == null");

        AsymmetricCipherKeyPair mtKp = xmssMTKeyPair(new XMSSMTParameters(HEIGHT, LAYERS, new SHA256Digest()));
        XMSSMTSigner mtSigner = new XMSSMTSigner();

        mtSigner.init(true, mtKp.getPrivate());

        byte[] mtSignature = mtSigner.generateSignature(message);
        XMSSMTSigner mtVerifier = new XMSSMTSigner();

        mtVerifier.init(false, mtKp.getPublic());

        assertTrue(mtVerifier.verifySignature(message, mtSignature));
        checkAbsentArgument(mtVerifier, null, mtSignature, "message == null");
        checkAbsentArgument(mtVerifier, message, null, "signature == null");

        // a signature that is present but will not decode is still an answer, not an error
        assertFalse(verifier.verifySignature(message, new byte[0]));
        assertFalse(mtVerifier.verifySignature(message, new byte[0]));
    }

    private void checkAbsentArgument(XMSSSigner verifier, byte[] message, byte[] signature, String expected)
    {
        try
        {
            verifier.verifySignature(message, signature);
            fail("absent argument accepted: " + expected);
        }
        catch (NullPointerException e)
        {
            assertEquals(expected, e.getMessage());
        }
    }

    private void checkAbsentArgument(XMSSMTSigner verifier, byte[] message, byte[] signature, String expected)
    {
        try
        {
            verifier.verifySignature(message, signature);
            fail("absent argument accepted: " + expected);
        }
        catch (NullPointerException e)
        {
            assertEquals(expected, e.getMessage());
        }
    }

    /**
     * getUsagesRemaining() answers for the key the signer is holding, so the three states that
     * leave it holding none - never initialised, initialised for verification, and key already
     * collected - all report zero signatures left rather than raising on the absent key.
     */
    public void testUsagesRemainingReportedAsZeroWhenNoKeyHeld()
    {
        AsymmetricCipherKeyPair kp = xmssKeyPair(new XMSSParameters(HEIGHT, new SHA256Digest()));

        assertEquals(0, new XMSSSigner().getUsagesRemaining());

        XMSSSigner verifier = new XMSSSigner();

        verifier.init(false, kp.getPublic());
        assertEquals(0, verifier.getUsagesRemaining());

        XMSSSigner signer = new XMSSSigner();

        signer.init(true, kp.getPrivate());

        // the positive control: while the signer holds the key it reports the key's own count,
        // which for a freshly generated key is one signature per leaf of the tree
        assertEquals(1 << HEIGHT, signer.getUsagesRemaining());

        signer.generateSignature(new byte[]{ 1, 2, 3 });
        signer.getUpdatedPrivateKey();

        assertEquals(0, signer.getUsagesRemaining());

        AsymmetricCipherKeyPair mtKp = xmssMTKeyPair(new XMSSMTParameters(HEIGHT, LAYERS, new SHA256Digest()));

        assertEquals(0, new XMSSMTSigner().getUsagesRemaining());

        XMSSMTSigner mtVerifier = new XMSSMTSigner();

        mtVerifier.init(false, mtKp.getPublic());
        assertEquals(0, mtVerifier.getUsagesRemaining());

        XMSSMTSigner mtSigner = new XMSSMTSigner();

        mtSigner.init(true, mtKp.getPrivate());

        assertEquals(1 << HEIGHT, mtSigner.getUsagesRemaining());

        mtSigner.generateSignature(new byte[]{ 1, 2, 3 });
        mtSigner.getUpdatedPrivateKey();

        assertEquals(0, mtSigner.getUsagesRemaining());
    }
}
