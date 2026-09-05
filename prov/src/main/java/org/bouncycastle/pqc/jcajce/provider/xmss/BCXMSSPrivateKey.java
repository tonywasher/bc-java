package org.bouncycastle.pqc.jcajce.provider.xmss;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PrivateKey;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.XMSSPrivateKeyParameters;
import org.bouncycastle.crypto.params.XMSSPublicKeyParameters;
import org.bouncycastle.crypto.signers.xmss.XMSSEngine;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.pqc.jcajce.interfaces.XMSSPrivateKey;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Exceptions;

public class BCXMSSPrivateKey
    implements PrivateKey, XMSSPrivateKey
{
    private static final long serialVersionUID = 8568701712864512338L;

    private transient XMSSPrivateKeyParameters keyParams;
    private transient ASN1ObjectIdentifier treeDigest;
    private transient ASN1Set attributes;

    public BCXMSSPrivateKey(
        ASN1ObjectIdentifier treeDigest,
        XMSSPrivateKeyParameters keyParams)
    {
        this(treeDigest, keyParams, null);
    }

    /**
     * As above, carrying the PKCS#8 attributes of the key this one was derived from.
     * <p>
     * The two-argument form is for a key that has no such origin - key pair generation - and the
     * attributes it leaves null are what {@link #getEncoded()} writes. Every other caller is
     * re-wrapping a key that already exists, and had been reaching this class through that form:
     * {@code extractKeyShard} below and the {@code getUpdatedPrivateKey()} of the signature SPI,
     * which is the StateAwareSignature contract's own way of taking the key back after signing.
     * So a key loaded from a PKCS#8 carrying attributes lost them on being signed with once, or
     * on being sharded once, with nothing to say so.
     * </p>
     */
    BCXMSSPrivateKey(
        ASN1ObjectIdentifier treeDigest,
        XMSSPrivateKeyParameters keyParams,
        ASN1Set attributes)
    {
        this.treeDigest = treeDigest;
        this.keyParams = keyParams;
        this.attributes = attributes;
    }

    public BCXMSSPrivateKey(PrivateKeyInfo keyInfo)
        throws IOException
    {
        init(keyInfo);
    }

    private void init(PrivateKeyInfo keyInfo)
        throws IOException
    {
        this.attributes = keyInfo.getAttributes();
        // Derive the tree digest from the recovered key rather than the AlgorithmIdentifier
        // parameters: the RFC 9802 form (id-alg-xmss-hashsig) carries no XMSSKeyParams, so reading
        // them would NPE. Mirrors BCXMSSPublicKey.init.
        this.keyParams = (XMSSPrivateKeyParameters)PrivateKeyFactory.createKey(keyInfo);
        this.treeDigest = DigestUtil.getDigestOID(keyParams.getTreeDigest());
    }

    public long getIndex()
    {
        // both reads under the key's own monitor, so a signature in between cannot split them
        synchronized (keyParams)
        {
            if (keyParams.getUsagesRemaining() == 0)
            {
                throw new IllegalStateException("key exhausted");
            }

            return keyParams.getIndex();
        }
    }

    public long getUsagesRemaining()
    {
        return keyParams.getUsagesRemaining();
    }

    public XMSSPrivateKey extractKeyShard(int usageCount)
    {
        return new BCXMSSPrivateKey(this.treeDigest, keyParams.extractKeyShard(usageCount), this.attributes);
    }

    public String getAlgorithm()
    {
        return "XMSS";
    }

    public String getFormat()
    {
        return "PKCS#8";
    }

    /**
     * The PKCS#8 attributes this key carries, for the signature SPI to put on the key it hands
     * back from getUpdatedPrivateKey().
     */
    ASN1Set getAttributes()
    {
        return attributes;
    }

    public byte[] getEncoded()
    {
        try
        {
            PrivateKeyInfo pki = PrivateKeyInfoFactory.createPrivateKeyInfo(keyParams, attributes);

            return pki.getEncoded();
        }
        catch (IOException e)
        {
            return null;
        }
    }

    /**
     * Whether these are the same key at the same position, which for a stateful key means the same
     * traversal state too - so the tail of this is a constant time comparison of the two traversal
     * states as encoded, everything else about the two keys having been compared field by field
     * ahead of it.
     * <p>
     * What is in front of it is the part of the answer that does not need them. Producing an
     * encoding means re-encoding the whole BDS traversal state - the authentication path, the
     * retain queues, the stack, every tree hash and every kept node, and a SHA-256 checksum over
     * the result - and every call did that twice, on both keys, whatever the two keys were. The
     * fields tested first are all written into that encoding, so two keys differing in any of them
     * cannot have equal encodings and the answer is the same one for none of the work: the tree
     * digest, the index, the usages remaining - which is the maximum index, the two indices being
     * equal by the time it is read - and the two public n-byte fields. hashCode() is the public
     * key's, so keys taken from one key pair all land in the same bucket of a Set or a Map and are
     * told apart there by their index, which is the first of these to be looked at.
     * </p><p>
     * The root and the public seed are compared in constant time even though they are the public
     * key - they are what {@code XMSSPublicKeyParameters} publishes, root then SEED, RFC 8391
     * sec. 4.1.7 - because this is a private key's equals(), where every array comparison in the
     * method being constant time is what stops the next field added to this chain from being
     * compared the other way. The two secret seeds are the next fields added to it, and they are
     * why the tail can be the traversal state alone: the encoding it used to compare is the index,
     * those two seeds, the public seed, the root and the state, and the first five are now all
     * above. So the same six things decide the answer, in the same constant time, and the four
     * n-byte comparisons that replace the encoding of a whole key cost nothing against it.
     * </p><p>
     * The chain is joined with {@code |} rather than {@code ||}, so all of it is evaluated
     * whatever the two keys are. Short circuited it answers a key differing in its tree digest
     * after one comparison and a key differing only in its secretKeyPRF after seven, so how long
     * the method takes says which of the fields the two keys first disagree on - and two of those
     * fields are secret material, which is the thing the constant time comparisons above are there
     * to keep out of the timing. It is why the single comparison this chain replaced was joined
     * with {@code &} rather than {@code &&}, as every other secret bearing equals() in the
     * provider is. Every operand is safe to evaluate unconditionally: a constructed key always
     * carries a tree digest, and {@code Arrays.constantTimeAreEqual} answers false for a null
     * argument rather than raising.
     * </p>
     */
    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }

        if (o instanceof BCXMSSPrivateKey)
        {
            BCXMSSPrivateKey otherKey = (BCXMSSPrivateKey)o;

            if (!treeDigest.equals(otherKey.treeDigest)
                | keyParams.getIndex() != otherKey.keyParams.getIndex()
                | keyParams.getUsagesRemaining() != otherKey.keyParams.getUsagesRemaining()
                | !Arrays.constantTimeAreEqual(keyParams.getPublicSeed(), otherKey.keyParams.getPublicSeed())
                | !Arrays.constantTimeAreEqual(keyParams.getRoot(), otherKey.keyParams.getRoot())
                | !Arrays.constantTimeAreEqual(keyParams.getSecretKeySeed(), otherKey.keyParams.getSecretKeySeed())
                | !Arrays.constantTimeAreEqual(keyParams.getSecretKeyPRF(), otherKey.keyParams.getSecretKeyPRF()))
            {
                return false;
            }

            return Arrays.constantTimeAreEqual(encodedState(keyParams), encodedState(otherKey.keyParams));
        }

        return false;
    }

    /**
     * The traversal state of a key, as an encoding of that key would carry it. This is the one
     * part of a key's content the field comparisons in equals() cannot reach: a state carries a
     * mark saying the one-time key at its index has already signed, and no accessor reports it.
     * <p>
     * Under the key's own monitor, which is what its {@code toByteArray()} took to read the same
     * two things: a signature landing between the state and the public seed would encode a state
     * under a seed that no longer goes with it.
     * </p>
     */
    private static byte[] encodedState(XMSSPrivateKeyParameters keyParams)
    {
        synchronized (keyParams)
        {
            try
            {
                return XMSSEngine.getEncodedBDSState(keyParams.getBDSState(), keyParams.getPublicSeed());
            }
            catch (IOException e)
            {
                throw Exceptions.illegalStateException("error encoding BDS state", e);
            }
        }
    }

    public int hashCode()
    {
        return getPublicKey().hashCode();
    }

    private BCXMSSPublicKey getPublicKey()
    {
        XMSSPublicKeyParameters pubParams = new XMSSPublicKeyParameters.Builder(keyParams.getParameters())
            .withRoot(keyParams.getRoot())
            .withPublicSeed(keyParams.getPublicSeed())
            .build();
        return new BCXMSSPublicKey(treeDigest, pubParams);
    }

    CipherParameters getKeyParams()
    {
        return keyParams;
    }

    ASN1ObjectIdentifier getTreeDigestOID()
    {
        return treeDigest;
    }

    public int getHeight()
    {
        return keyParams.getParameters().getHeight();
    }

    public String getTreeDigest()
    {
        return DigestUtil.getXMSSDigestName(treeDigest, keyParams.getParameters().getTreeDigestSize());
    }

    private void readObject(
        ObjectInputStream in)
        throws IOException, ClassNotFoundException
    {
        in.defaultReadObject();

        byte[] enc = (byte[])in.readObject();

        init(PrivateKeyInfo.getInstance(enc));
    }

    private void writeObject(
        ObjectOutputStream out)
        throws IOException
    {
        out.defaultWriteObject();

        out.writeObject(this.getEncoded());
    }
}
