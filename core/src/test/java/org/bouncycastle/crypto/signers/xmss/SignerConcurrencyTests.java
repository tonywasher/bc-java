package org.bouncycastle.crypto.signers.xmss;

import java.security.SecureRandom;
import java.util.concurrent.CountDownLatch;

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
 * A signer's private key field is not the monitor to lock on, because the signer itself replaces
 * it: getUpdatedPrivateKey() installs the shard the signer keeps and init() installs a new key
 * outright. Both signers used to read that field into a local and only then synchronize on what
 * they had read, so a call that had read the old key and a call that had read the new one held two
 * different monitors and excluded each other from nothing.
 * <p>
 * What comes out of that is the failure a stateful scheme cannot have. getUpdatedPrivateKey() hands
 * the caller the key to persist, having rolled it past the index the signer will spend; a signature
 * that had already read the same object then spends the index the caller has just been told is
 * still unused. Storing that key and restoring it signs a second message under one WOTS+ one-time
 * key, and both signatures verify - RFC 8391 sec. 1.1.
 * </p>
 * <p>
 * So the invariant asserted here is a range one, not a timing one: whatever order the two calls
 * take, the key handed back for storage must sit strictly past every index the signer has spent.
 * Before the fix this failed on roughly a third of the trials below; it cannot fail by chance.
 * </p>
 */
public class SignerConcurrencyTests
    extends TestCase
{
    private static final int HEIGHT = 4;
    private static final int LAYERS = 2;
    private static final int TRIALS = 120;

    public void testStoredXMSSKeyNeverSitsOnASignedIndex()
        throws Exception
    {
        XMSSParameters params = new XMSSParameters(HEIGHT, new SHA256Digest());
        SecureRandom random = new SecureRandom();

        for (int trial = 0; trial != TRIALS; trial++)
        {
            XMSSKeyPairGenerator kpg = new XMSSKeyPairGenerator();

            kpg.init(new XMSSKeyGenerationParameters(params, random));

            AsymmetricCipherKeyPair kp = kpg.generateKeyPair();
            final XMSSSigner signer = new XMSSSigner();

            signer.init(true, kp.getPrivate());
            signer.update(new byte[]{1, 2, 3}, 0, 3);

            final long[] signed = {-1L};
            final long[] stored = {-1L};
            final CountDownLatch go = new CountDownLatch(1);

            Thread signing = new Thread()
            {
                public void run()
                {
                    try
                    {
                        go.await();
                        signed[0] = indexOf(signer.generateSignature(), 4);
                    }
                    catch (Exception e)
                    {
                        // a key already handed over is a legitimate outcome of the other ordering
                    }
                }
            };

            Thread collecting = new Thread()
            {
                public void run()
                {
                    try
                    {
                        go.await();

                        XMSSPrivateKeyParameters key =
                            (XMSSPrivateKeyParameters)signer.getUpdatedPrivateKey();

                        if (key != null)
                        {
                            // as a caller persisting it does. The encode takes the key's own
                            // monitor, so it lands either side of a signature but never inside one
                            stored[0] = indexOf(key.getEncoded(), 4);
                        }
                    }
                    catch (Exception e)
                    {
                    }
                }
            };

            run(signing, collecting, go);

            if (signed[0] >= 0 && stored[0] >= 0)
            {
                assertTrue("XMSS key stored at index " + stored[0] + " after index " + signed[0]
                    + " was signed", stored[0] > signed[0]);
            }
        }
    }

    public void testStoredXMSSMTKeyNeverSitsOnASignedIndex()
        throws Exception
    {
        XMSSMTParameters params = new XMSSMTParameters(HEIGHT, LAYERS, new SHA256Digest());
        SecureRandom random = new SecureRandom();
        final int indexSize = (HEIGHT + 7) / 8;

        for (int trial = 0; trial != TRIALS; trial++)
        {
            XMSSMTKeyPairGenerator kpg = new XMSSMTKeyPairGenerator();

            kpg.init(new XMSSMTKeyGenerationParameters(params, random));

            AsymmetricCipherKeyPair kp = kpg.generateKeyPair();
            final XMSSMTSigner signer = new XMSSMTSigner();

            signer.init(true, kp.getPrivate());
            signer.update(new byte[]{1, 2, 3}, 0, 3);

            final long[] signed = {-1L};
            final long[] stored = {-1L};
            final CountDownLatch go = new CountDownLatch(1);

            Thread signing = new Thread()
            {
                public void run()
                {
                    try
                    {
                        go.await();
                        signed[0] = indexOf(signer.generateSignature(), indexSize);
                    }
                    catch (Exception e)
                    {
                    }
                }
            };

            Thread collecting = new Thread()
            {
                public void run()
                {
                    try
                    {
                        go.await();

                        XMSSMTPrivateKeyParameters key =
                            (XMSSMTPrivateKeyParameters)signer.getUpdatedPrivateKey();

                        if (key != null)
                        {
                            stored[0] = indexOf(key.getEncoded(), indexSize);
                        }
                    }
                    catch (Exception e)
                    {
                    }
                }
            };

            run(signing, collecting, go);

            if (signed[0] >= 0 && stored[0] >= 0)
            {
                assertTrue("XMSS^MT key stored at index " + stored[0] + " after index " + signed[0]
                    + " was signed", stored[0] > signed[0]);
            }
        }
    }

    private static void run(Thread signing, Thread collecting, CountDownLatch go)
        throws InterruptedException
    {
        signing.start();
        collecting.start();
        go.countDown();
        signing.join();
        collecting.join();
    }

    /**
     * The index both encodings open with, big-endian in the width the parameter set fixes: four
     * bytes for XMSS, ceil(h / 8) for XMSS^MT.
     */
    private static long indexOf(byte[] encoding, int indexSize)
    {
        long index = 0;

        for (int i = 0; i != indexSize; i++)
        {
            index = (index << 8) | (encoding[i] & 0xffL);
        }

        return index;
    }
}
