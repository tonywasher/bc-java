package org.bouncycastle.crypto.signers;

import java.io.ByteArrayOutputStream;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.ExhaustedPrivateKeyException;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.XMSSPrivateKeyParameters;
import org.bouncycastle.crypto.params.XMSSPublicKeyParameters;
import org.bouncycastle.crypto.signers.xmss.XMSSEngine;

public class XMSSSigner
    implements Signer
{
    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    private XMSSPrivateKeyParameters privateKey;
    private XMSSPublicKeyParameters publicKey;

    private boolean initSign;
    private boolean hasGenerated;

    public void init(boolean forSigning, CipherParameters param)
    {
        if (forSigning)
        {
            initSign = true;
            hasGenerated = false;
            // the randomizer is derived from the key itself - r = PRF(SK_PRF, toByte(idx, 32)),
            // RFC 8391 sec. 4.1.9 - so a SecureRandom supplied here has nothing to drive and is
            // discarded, the way SPHINCS256Signer discards it. Accepting the wrapper is what
            // matters: XMSSSignatureSpi.engineInitSign(PrivateKey, SecureRandom) wraps the key
            // whenever a random is supplied, so initSign(key, random) used to fail on the cast.
            if (param instanceof ParametersWithRandom)
            {
                privateKey = (XMSSPrivateKeyParameters)((ParametersWithRandom)param).getParameters();
            }
            else
            {
                privateKey = (XMSSPrivateKeyParameters)param;
            }
            // the public key from a previous verification init must not stay behind, or this signer
            // still verifies against it. The private key is deliberately NOT cleared on a
            // verification init: sign then verify then collect the advanced state is a legitimate
            // sequence, and clearing would drop state the caller is obliged to persist.
            publicKey = null;
        }
        else
        {
            initSign = false;
            publicKey = (XMSSPublicKeyParameters)param;

        }

        // a message absorbed before this call belongs to the operation that has just ended:
        // carrying it into the new one would sign or verify bytes the caller never presented for
        // it, and on the signing side would spend a one-time key doing so. Ed25519Signer,
        // Ed448Signer and DSADigestSigner all reset here for the same reason.
        reset();
    }

    public byte[] generateSignature()
    {
        byte[] message = buffer.toByteArray();

        // the buffered message is consumed whether or not a signature is produced: a call that
        // fails one of the checks below must not leave bytes behind for the next one to sign
        reset();

        // take the key once, the way getUpdatedPrivateKey() does: that method can clear the field,
        // and re-reading it below would then synchronize on null rather than report an absent key
        XMSSPrivateKeyParameters privKey = privateKey;

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

            return XMSSEngine.generateSignature(privKey, message);
        }
    }

    /**
     * Return the number of signatures the key this signer holds can still produce. A signer
     * initialised for verification, or one whose key has already been handed back by
     * {@link #getUpdatedPrivateKey()}, holds no key and so reports zero - reading the absent key
     * would otherwise raise a NullPointerException.
     */
    public long getUsagesRemaining()
    {
        XMSSPrivateKeyParameters privKey = privateKey;

        if (privKey == null)
        {
            return 0;
        }

        return privKey.getUsagesRemaining();
    }

    public boolean verifySignature(byte[] signature)
    {
        byte[] message = buffer.toByteArray();

        // consumed whatever the outcome, so a failed verification cannot poison the next one
        reset();

        // covers both a signer initialised for signing and one never initialised at all: the latter
        // used to fall through and report the absent public key as "signature did not verify",
        // because the NullPointerException it caused was swallowed by the malformed-signature catch
        if (initSign || publicKey == null)
        {
            throw new IllegalStateException("signer not initialized for verification");
        }
        // a missing argument is the caller's mistake rather than a signature that failed to verify:
        // bytes that will not decode are reported as false further down, but there are no bytes
        // here. The XMSS^MT signer has always answered a null signature this way.
        if (signature == null)
        {
            throw new NullPointerException("signature == null");
        }

        return XMSSEngine.verifySignature(publicKey, message, signature);
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

    public void reset()
    {
        buffer.reset();
    }

    public AsymmetricKeyParameter getUpdatedPrivateKey()
    {
        // if we've generated a signature return the last private key generated
        // if we've only initialised leave it in place and return the next one instead.
        XMSSPrivateKeyParameters privKey = privateKey;

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
