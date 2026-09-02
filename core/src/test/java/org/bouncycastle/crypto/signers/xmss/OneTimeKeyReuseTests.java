package org.bouncycastle.crypto.signers.xmss;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.XMSSKeyPairGenerator;
import org.bouncycastle.crypto.generators.XMSSMTKeyPairGenerator;
import org.bouncycastle.crypto.params.XMSSKeyGenerationParameters;
import org.bouncycastle.crypto.params.XMSSMTKeyGenerationParameters;
import org.bouncycastle.crypto.params.XMSSMTParameters;
import org.bouncycastle.crypto.params.XMSSMTPrivateKeyParameters;
import org.bouncycastle.crypto.params.XMSSMTPublicKeyParameters;
import org.bouncycastle.crypto.params.XMSSParameters;
import org.bouncycastle.crypto.params.XMSSPrivateKeyParameters;
import org.bouncycastle.crypto.params.XMSSPublicKeyParameters;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Longs;

/**
 * RFC 8391 sec. 1.1: each one-time key must be used exactly once. A WOTS+ key used twice discloses
 * enough of itself to forge, so two verifying signatures at the same index are a private key
 * compromise, not a merely surprising result.
 * <p>
 * XMSSEngine.generateSignature / generateMTSignature both read the key's index and roll the key
 * past it, which is only safe as one atomic sequence. They are public entry points reachable
 * without going through XMSSSigner / XMSSMTSigner, so they take the lock on the key themselves
 * rather than relying on the caller to hold it; these tests drive them directly, the way a caller
 * using the lightweight API would, and assert no index is ever spent twice.
 * </p>
 */
public class OneTimeKeyReuseTests
    extends TestCase
{
    private static final int HEIGHT = 4;
    private static final int LAYERS = 2;
    private static final int THREADS = 4;
    private static final int TRIALS = 8;

    /**
     * The signatures produced by a set of threads racing on one key, ignoring the threads that
     * failed - a signature that was never produced spends nothing.
     */
    private static List sign(final Object privKey, final boolean multiTree)
        throws InterruptedException
    {
        final List sigs = new ArrayList();
        final Object lock = new Object();
        Thread[] threads = new Thread[THREADS];

        for (int i = 0; i != THREADS; i++)
        {
            final byte[] message = new byte[]{(byte)i, 0x5a};

            threads[i] = new Thread()
            {
                public void run()
                {
                    byte[] sig;
                    try
                    {
                        sig = multiTree
                            ? XMSSEngine.generateMTSignature((XMSSMTPrivateKeyParameters)privKey, message)
                            : XMSSEngine.generateSignature((XMSSPrivateKeyParameters)privKey, message);
                    }
                    catch (RuntimeException e)
                    {
                        // key exhausted, or this thread lost the race: nothing was spent
                        return;
                    }

                    synchronized (lock)
                    {
                        sigs.add(new Object[]{message, sig});
                    }
                }
            };
        }

        for (int i = 0; i != THREADS; i++)
        {
            threads[i].start();
        }
        for (int i = 0; i != THREADS; i++)
        {
            threads[i].join();
        }

        return sigs;
    }

    public void testXMSSConcurrentSigningSpendsEachOneTimeKeyOnce()
        throws Exception
    {
        for (int trial = 0; trial != TRIALS; trial++)
        {
            XMSSParameters params = new XMSSParameters(HEIGHT, new SHA256Digest());
            XMSSKeyPairGenerator kpg = new XMSSKeyPairGenerator();

            kpg.init(new XMSSKeyGenerationParameters(params, new SecureRandom()));

            AsymmetricCipherKeyPair kp = kpg.generateKeyPair();
            XMSSPrivateKeyParameters privKey = (XMSSPrivateKeyParameters)kp.getPrivate();
            XMSSPublicKeyParameters pubKey = (XMSSPublicKeyParameters)kp.getPublic();

            List sigs = sign(privKey, false);
            Set seen = new HashSet();

            for (int i = 0; i != sigs.size(); i++)
            {
                Object[] pair = (Object[])sigs.get(i);
                byte[] message = (byte[])pair[0];
                byte[] sig = (byte[])pair[1];

                // only a signature that verifies represents a one-time key that was actually spent
                if (!XMSSEngine.verifySignature(pubKey, message, sig))
                {
                    continue;
                }

                // an XMSS signature leads with its 4-byte big-endian index (RFC 8391 sec. 4.1.8)
                Integer index = Integers.valueOf((int)XMSSEngine.bytesToXBigEndian(sig, 0, 4));

                assertTrue("one-time key at index " + index + " signed twice", seen.add(index));
            }
        }
    }

    public void testXMSSMTConcurrentSigningSpendsEachOneTimeKeyOnce()
        throws Exception
    {
        int indexSize = (HEIGHT + 7) / 8;

        for (int trial = 0; trial != TRIALS; trial++)
        {
            XMSSMTParameters params = new XMSSMTParameters(HEIGHT, LAYERS, new SHA256Digest());
            XMSSMTKeyPairGenerator kpg = new XMSSMTKeyPairGenerator();

            kpg.init(new XMSSMTKeyGenerationParameters(params, new SecureRandom()));

            AsymmetricCipherKeyPair kp = kpg.generateKeyPair();
            XMSSMTPrivateKeyParameters privKey = (XMSSMTPrivateKeyParameters)kp.getPrivate();
            XMSSMTPublicKeyParameters pubKey = (XMSSMTPublicKeyParameters)kp.getPublic();

            List sigs = sign(privKey, true);
            Set seen = new HashSet();

            for (int i = 0; i != sigs.size(); i++)
            {
                Object[] pair = (Object[])sigs.get(i);
                byte[] message = (byte[])pair[0];
                byte[] sig = (byte[])pair[1];

                if (!XMSSEngine.verifyMTSignature(pubKey, message, sig))
                {
                    continue;
                }

                // an XMSS^MT signature leads with its ceil(h/8)-byte index (RFC 8391 sec. 4.2.5)
                Long index = Longs.valueOf(XMSSEngine.bytesToXBigEndian(sig, 0, indexSize));

                assertTrue("one-time key at index " + index + " signed twice", seen.add(index));
            }
        }
    }

    /**
     * Both paths record on the traversal state that its one-time key has signed. The record is
     * only still there to see where the roll leaves that state in place, which is the last leaf
     * of a subtree: everywhere else the roll installs a fresh state, sitting on a leaf that has
     * not signed yet. The XMSS^MT path did not make the record at all, so its state said no leaf
     * had ever signed.
     */
    public void testSignatureMarksTheOneTimeKeyItSpent()
        throws Exception
    {
        XMSSMTParameters mtParams = new XMSSMTParameters(HEIGHT, LAYERS, new SHA256Digest());
        XMSSMTKeyPairGenerator mtKpg = new XMSSMTKeyPairGenerator();

        mtKpg.init(new XMSSMTKeyGenerationParameters(mtParams, new SecureRandom()));

        XMSSMTPrivateKeyParameters mtKey =
            (XMSSMTPrivateKeyParameters)mtKpg.generateKeyPair().getPrivate();
        int leaves = 1 << mtParams.getXMSSParameters().getHeight();

        for (int i = 1; i <= leaves; i++)
        {
            XMSSEngine.generateMTSignature(mtKey, new byte[]{(byte)i});

            assertEquals("XMSS^MT layer zero after signature " + i, i == leaves,
                mtKey.getBDSState().get(0).isUsed());
        }

        // the XMSS twin, whose record this was mirrored from: its whole tree is the subtree, so
        // the state is left in place only on the very last leaf, where it is the exhausted key
        // placeholder
        XMSSParameters params = new XMSSParameters(HEIGHT, new SHA256Digest());
        XMSSKeyPairGenerator kpg = new XMSSKeyPairGenerator();

        kpg.init(new XMSSKeyGenerationParameters(params, new SecureRandom()));

        XMSSPrivateKeyParameters key = (XMSSPrivateKeyParameters)kpg.generateKeyPair().getPrivate();

        for (int i = 1; i <= (1 << HEIGHT); i++)
        {
            XMSSEngine.generateSignature(key, new byte[]{(byte)i});

            assertEquals("XMSS after signature " + i, i == (1 << HEIGHT),
                key.getBDSState().isUsed());
        }
    }
}
