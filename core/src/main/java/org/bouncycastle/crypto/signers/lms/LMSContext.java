package org.bouncycastle.crypto.signers.lms;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.params.LMOtsParameters;
import org.bouncycastle.crypto.params.LMSigParameters;

/**
 * The digest an LMS or HSS message is absorbed into before it is signed or verified, carrying the
 * one-time key or signature the operation will use. Obtain one from
 * {@link org.bouncycastle.crypto.signers.LMSContextBasedSigner#generateLMSContext()} or
 * {@link org.bouncycastle.crypto.signers.LMSContextBasedVerifier#generateLMSContext(byte[])},
 * feed it the message through the {@link Digest} methods, then hand it back to the key. Its
 * contents are read by {@link LMSEngine} only.
 */
public class LMSContext
    implements Digest
{
    private final byte[] C;
    private final LMOtsPrivateKey key;
    private final LMSigParameters sigParams;
    private final byte[][] path;
    private final LMOtsPublicKey publicKey;
    private final Object signature;

    private LMSSignedPubKey[] signedPubKeys;
    private volatile Digest digest;

    LMSContext(LMOtsPrivateKey key, LMSigParameters sigParams, Digest digest, byte[] C, byte[][] path)
    {
        this.key = key;
        this.sigParams = sigParams;
        this.digest = digest;
        this.C = C;
        this.path = path;
        this.publicKey = null;
        this.signature = null;
    }

    LMSContext(LMOtsPublicKey publicKey, Object signature, Digest digest)
    {
        this.publicKey = publicKey;
        this.signature = signature;
        this.digest = digest;
        this.C = null;
        this.key = null;
        this.sigParams = null;
        this.path = null;
    }

    byte[] getC()
    {
        return C;
    }

    /**
     * Write Q, the message hash, to the given buffer. The context cannot be used afterwards.
     * <p>
     * A caller that goes on to append the LM-OTS checksum needs two bytes beyond the value written here.
     * </p>
     *
     * @param output the byte array Q is to be copied into.
     * @param outOff the offset into the byte array Q is to start at.
     * @return the number of bytes written.
     */
    public int outputQ(byte[] output, int outOff)
    {
        Digest digest = this.digest;
        int qLen = digest.getDigestSize();
        if (outOff > output.length - qLen)
        {
            throw new OutputLengthException("output buffer too short");
        }

        digest.doFinal(output, outOff);
        this.digest = null;
        return qLen;
    }

    /**
     * Take Q, the message hash, in the buffer shape the LM-OTS chaining expects: the N bytes of Q,
     * followed by room for the two bytes of {@link LM_OTS#cksm(byte[], int, LMOtsParameters)} that the
     * caller appends (RFC 8554 sec. 4.5). The context cannot be used afterwards.
     */
    byte[] collectQ(LMOtsParameters otsParameters)
    {
        byte[] Q = new byte[otsParameters.getN() + 2];
        outputQ(Q, 0);
        return Q;
    }

    /**
     * Kc, the LM-OTS public key the signature this context carries computes for itself over the
     * message absorbed into it. The context cannot be used afterwards.
     */
    byte[] calculateKc()
    {
        // Either an LMS signature, whose LM-OTS part this verifies, or a bare LM-OTS one
        LMOtsSignature otsSignature = (signature instanceof LMSSignature)
            ? ((LMSSignature)signature).getOtsSignature()
            : (LMOtsSignature)signature;

        return LM_OTS.calculateKc(publicKey, otsSignature, collectQ(publicKey.getParameter()));
    }

    /**
     * Complete the LMS signature of the one-time key this context was opened on, over the message
     * absorbed into it (RFC 8554 sec. 5.4.1). The context cannot be used afterwards.
     */
    LMSSignature generateSignature()
    {
        byte[] Q = collectQ(key.getParameter());

        LMOtsSignature otsSignature = LM_OTS.lm_ots_generate_signature(key, Q, C);

        return new LMSSignature(key.getQ(), otsSignature, sigParams, path);
    }

    byte[][] getPath()
    {
        return path;
    }

    LMOtsPrivateKey getPrivateKey()
    {
        return key;
    }

    LMOtsPublicKey getPublicKey()
    {
        return publicKey;
    }

    LMSigParameters getSigParams()
    {
        return sigParams;
    }

    Object getSignature()
    {
        return signature;
    }

    LMSSignedPubKey[] getSignedPubKeys()
    {
        return signedPubKeys;
    }

    LMSContext withSignedPublicKeys(LMSSignedPubKey[] signedPubKeys)
    {
        this.signedPubKeys = signedPubKeys;

        return this;
    }

    public String getAlgorithmName()
    {
        return digest.getAlgorithmName();
    }

    public int getDigestSize()
    {
        return digest.getDigestSize();
    }

    public void update(byte in)
    {
        digest.update(in);
    }

    public void update(byte[] in, int inOff, int len)
    {
        digest.update(in, inOff, len);
    }

    public int doFinal(byte[] out, int outOff)
    {
        return digest.doFinal(out, outOff);
    }

    public void reset()
    {
        digest.reset();
    }
}
