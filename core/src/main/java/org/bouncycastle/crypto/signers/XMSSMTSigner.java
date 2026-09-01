package org.bouncycastle.crypto.signers;

import java.io.ByteArrayOutputStream;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.ExhaustedPrivateKeyException;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.XMSSMTPrivateKeyParameters;
import org.bouncycastle.crypto.params.XMSSMTPublicKeyParameters;
import org.bouncycastle.crypto.signers.xmss.XMSSEngine;

/**
 * XMSS^MT Signer class.
 */
public class XMSSMTSigner
    implements Signer
{
    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    private XMSSMTPrivateKeyParameters privateKey;
    private XMSSMTPublicKeyParameters publicKey;

    private boolean hasGenerated;
    private boolean initSign;

    public void init(boolean forSigning, CipherParameters param)
    {
        if (forSigning)
        {
            initSign = true;
            hasGenerated = false;
            privateKey = (XMSSMTPrivateKeyParameters)param;

            // the public key from a previous verification init must not stay behind, or this signer
            // still verifies against it. The private key is deliberately NOT cleared on a
            // verification init: sign then verify then collect the advanced state is a legitimate
            // sequence, and clearing would drop state the caller is obliged to persist.
            publicKey = null;
        }
        else
        {
            initSign = false;
            publicKey = (XMSSMTPublicKeyParameters)param;

        }
    }

    public byte[] generateSignature(byte[] message)
    {
        if (message == null)
        {
            throw new NullPointerException("message == null");
        }

        // take the key once, the way getUpdatedPrivateKey() does: that method can clear the field,
        // and re-reading it below would then synchronize on null rather than report an absent key
        XMSSMTPrivateKeyParameters privKey = privateKey;

        if (initSign)
        {
            if (privKey == null)
            {
                throw new IllegalStateException("signing key no longer usable");
            }
        }
        else
        {
            throw new IllegalStateException("signer not initialized for signature generation");
        }

        synchronized (privKey)
        {
            if (privKey.getUsagesRemaining() <= 0)
            {
                throw new ExhaustedPrivateKeyException("no usages of private key remaining");
            }
            if (!XMSSEngine.hasTraversalState(privKey))
            {
                throw new IllegalStateException("not initialized");
            }

            // set once the guards above have passed, as the key is rolled from here on whatever
            // happens: getUpdatedPrivateKey() has to hand back this key rather than advance again
            hasGenerated = true;

            return XMSSEngine.generateMTSignature(privKey, message);
        }
    }

    public boolean verifySignature(byte[] message, byte[] signature)
    {
        // covers both a signer initialised for signing and one never initialised at all, and comes
        // ahead of the argument checks: not being initialised is the caller's first problem. This
        // replaces the NullPointerException the absent public key used to raise.
        if (initSign || publicKey == null)
        {
            throw new IllegalStateException("signer not initialized for verification");
        }
        if (message == null)
        {
            throw new NullPointerException("message == null");
        }
        if (signature == null)
        {
            throw new NullPointerException("signature == null");
        }

        return XMSSEngine.verifyMTSignature(publicKey, message, signature);
    }

    /**
     * Return the number of signatures the key this signer holds can still produce. A signer
     * initialised for verification, or one whose key has already been handed back by
     * {@link #getUpdatedPrivateKey()}, holds no key and so reports zero - reading the absent key
     * would otherwise raise a NullPointerException.
     */
    public long getUsagesRemaining()
    {
        XMSSMTPrivateKeyParameters privKey = privateKey;

        if (privKey == null)
        {
            return 0;
        }

        return privKey.getUsagesRemaining();
    }

    /**
     * Absorb a byte of the message to be signed or verified. The buffered message is consumed by
     * {@link #generateSignature()} / {@link #verifySignature(byte[])}, which reset the buffer.
     */
    public void update(byte b)
    {
        buffer.write(b);
    }

    public void update(byte[] in, int off, int len)
    {
        buffer.write(in, off, len);
    }

    public byte[] generateSignature()
    {
        byte[] message = buffer.toByteArray();

        reset();

        return generateSignature(message);
    }

    public boolean verifySignature(byte[] signature)
    {
        byte[] message = buffer.toByteArray();

        reset();

        return verifySignature(message, signature);
    }

    public void reset()
    {
        buffer.reset();
    }

    public AsymmetricKeyParameter getUpdatedPrivateKey()
    {
        // if we've generated a signature return the last private key generated
        // if we've only initialised leave it in place and return the next one instead.
        XMSSMTPrivateKeyParameters privKey = privateKey;

        // nothing to hand back: this signer was never initialised for signing, or a previous call
        // has already taken the key. Reported as an absent key rather than as the
        // NullPointerException synchronizing on the field below would raise.
        if (privKey == null)
        {
            return null;
        }

        synchronized (privKey)
        {
            if (hasGenerated)
            {
                privateKey = null;
            }
            else if (privKey.getUsagesRemaining() > 0)
            {
                privateKey = privKey.getNextKey();
            }
            // else: a key with nothing left to spend has no next usage to leave behind, and asking
            // for one reported the shard API's own "usageCount exceeds usages remaining" to a caller
            // that never asked for a shard. Hand the spent key back so it can still be stored.

            return privKey;
        }
    }
}
