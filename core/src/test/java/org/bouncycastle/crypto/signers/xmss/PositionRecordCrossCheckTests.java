package org.bouncycastle.crypto.signers.xmss;

import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.XMSSMTKeyPairGenerator;
import org.bouncycastle.crypto.params.XMSSMTKeyGenerationParameters;
import org.bouncycastle.crypto.params.XMSSMTParameters;
import org.bouncycastle.crypto.params.XMSSMTPrivateKeyParameters;
import org.bouncycastle.crypto.params.XMSSMTPublicKeyParameters;
import org.bouncycastle.crypto.signers.XMSSMTSigner;

/**
 * An XMSS^MT private key records where it has got to twice - in its own index field, and in the
 * per-layer BDS traversal states beside it - and the two are advanced by separate statements, so
 * only the author of those statements holds them together. The constructor compares them, which
 * catches a key arriving desynchronised; nothing was comparing them again while the key was held,
 * so a roll that advanced one record and not the other would have gone unnoticed until the key was
 * next read back, and a key that has been rolled back in one record but not the other signs a
 * second message under a one-time key it has already used (RFC 8391 sec. 1.1).
 * <p>
 * These exercise the two ends of that: that a desynchronised pair is now refused where it moves and
 * where it is written out, and - the half that matters more - that a key going about its business
 * across every index it can reach is not.
 * </p>
 */
public class PositionRecordCrossCheckTests
    extends TestCase
{
    private static final int HEIGHT = 6;
    private static final int LAYERS = 3;

    /**
     * The compatibility half. Walk a key across every index it has, encoding at each one, and
     * confirm the encoding still decodes to a key that signs verifiably. A cross-check that is too
     * strict rejects legitimate keys, which is worse than the divergence it is there to find - the
     * boundary at a leaf index of 0, where a layer legitimately still shows the previous subtree's
     * last leaf, is the case that makes that a real risk here.
     */
    public void testEveryIndexOfAKeyStillEncodesAndSigns()
        throws Exception
    {
        XMSSMTParameters params = new XMSSMTParameters(HEIGHT, LAYERS, new SHA256Digest());
        XMSSMTKeyPairGenerator kpg = new XMSSMTKeyPairGenerator();

        kpg.init(new XMSSMTKeyGenerationParameters(params, new SecureRandom()));

        org.bouncycastle.crypto.AsymmetricCipherKeyPair kp = kpg.generateKeyPair();
        XMSSMTPrivateKeyParameters privKey = (XMSSMTPrivateKeyParameters)kp.getPrivate();
        XMSSMTPublicKeyParameters pubKey = (XMSSMTPublicKeyParameters)kp.getPublic();

        long maxIndex = privKey.getBDSState().getMaxIndex();

        for (long index = 0; index <= maxIndex; index++)
        {
            assertEquals("key is not where the walk expects it", index, privKey.getIndex());

            byte[] encoded = privKey.getEncoded();
            XMSSMTPrivateKeyParameters decoded = new XMSSMTPrivateKeyParameters.Builder(params)
                .withPrivateKey(encoded).build();

            assertEquals("decoded key sits at a different index", index, decoded.getIndex());

            byte[] message = new byte[]{(byte)index, (byte)(index >>> 8)};

            XMSSMTSigner signer = new XMSSMTSigner();
            signer.init(true, decoded);
            signer.update(message, 0, message.length);
            byte[] signature = signer.generateSignature();

            XMSSMTSigner verifier = new XMSSMTSigner();
            verifier.init(false, pubKey);
            verifier.update(message, 0, message.length);
            assertTrue("signature at index " + index + " does not verify",
                verifier.verifySignature(signature));

            privKey.rollKey();
        }

        // and the exhausted key past the end, whose state map is empty and so has no layer to
        // disagree with anything
        assertEquals(maxIndex + 1, privKey.getIndex());
        assertEquals(0, privKey.getUsagesRemaining());
    }

    /**
     * A layer zero state left behind where the index has moved on - what a partial write or a
     * storage layer that restored half a key produces - must not be written out as a key, because
     * decoding it back is refused and because the position it describes is one the key has already
     * signed at.
     */
    public void testEncodingRefusesAStateThatLagsTheIndex()
        throws Exception
    {
        XMSSMTPrivateKeyParameters privKey = desynchronised();

        try
        {
            privKey.getEncoded();
            fail("a key whose two records of its position disagree was encoded");
        }
        catch (IllegalStateException e)
        {
            assertTrue("wrong message: " + e.getMessage(),
                e.getMessage().startsWith("BDS state has wrong index for layer 0"));
        }
    }

    /**
     * The same pair, refused where it next moves rather than where it is written: a roll carries a
     * lagging state forward rather than repairing it, so the key would go on signing at positions
     * its state says it has already been to.
     */
    public void testRollRefusesAStateThatLagsTheIndex()
        throws Exception
    {
        XMSSMTPrivateKeyParameters privKey = desynchronised();

        try
        {
            privKey.rollKey();
            fail("a key whose two records of its position disagree was rolled");
        }
        catch (IllegalStateException e)
        {
            assertTrue("wrong message: " + e.getMessage(),
                e.getMessage().startsWith("BDS state has wrong index for layer 0"));
        }
    }

    /**
     * The same pair again, refused where it would be spent. Encoding and rolling are where a
     * desynchronised key is written down or moved on; signing is where it consumes a one-time key,
     * and that is the step RFC 8391 sec. 1.1 is about.
     * <p>
     * Refusing it here rather than leaving the roll to catch it is not just an earlier message. The
     * roll runs from the finally the signature is built inside, so the one-time key is spent and
     * the key advanced before the exception the caller sees is raised: what that caller then knows
     * is that something went wrong, not that its key has moved. The assertion on the index is
     * therefore the one that matters - measured against the engine without the check, the key
     * comes back one position further on than it went in.
     * </p>
     */
    public void testSigningRefusesAStateThatLagsTheIndex()
        throws Exception
    {
        XMSSMTPrivateKeyParameters privKey = desynchronised();

        long index = privKey.getIndex();

        XMSSMTSigner signer = new XMSSMTSigner();

        signer.init(true, privKey);
        signer.update(new byte[]{0x01}, 0, 1);

        try
        {
            signer.generateSignature();
            fail("a key whose two records of its position disagree signed");
        }
        catch (IllegalStateException e)
        {
            assertTrue("wrong message: " + e.getMessage(),
                e.getMessage().startsWith("BDS state has wrong index for layer 0"));
        }

        assertEquals("a refused signature must not move the key", index, privKey.getIndex());
    }

    /**
     * A key sitting at an index its own layer zero state does not agree with, built the way the
     * failure actually arises: the state map handed out by getBDSState() is the live one, so a
     * layer zero state kept from before a roll can be put back into it afterwards, which is what
     * a half-restored key looks like from the inside.
     */
    private XMSSMTPrivateKeyParameters desynchronised()
        throws Exception
    {
        XMSSMTParameters params = new XMSSMTParameters(HEIGHT, LAYERS, new SHA256Digest());
        XMSSMTKeyPairGenerator kpg = new XMSSMTKeyPairGenerator();

        kpg.init(new XMSSMTKeyGenerationParameters(params, new SecureRandom()));

        XMSSMTPrivateKeyParameters privKey =
            (XMSSMTPrivateKeyParameters)kpg.generateKeyPair().getPrivate();

        // sign twice so layer zero exists and is off the subtree boundary the cross-check allows
        XMSSMTSigner signer = new XMSSMTSigner();
        signer.init(true, privKey);
        for (int i = 0; i != 2; i++)
        {
            signer.update(new byte[]{(byte)i}, 0, 1);
            signer.generateSignature();
        }

        BDS stale = privKey.getBDSState().get(0);
        assertNotNull("no layer zero state to keep", stale);

        privKey.rollKey();
        assertTrue("layer zero already agrees with the index after the roll",
            stale.getIndex() != XMSSUtil.getLeafIndex(privKey.getIndex(), HEIGHT / LAYERS));

        privKey.getBDSState().put(0, stale);

        return privKey;
    }
}
