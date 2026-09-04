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
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.pqc.jcajce.interfaces.XMSSPrivateKey;
import org.bouncycastle.util.Arrays;

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
        this.treeDigest = treeDigest;
        this.keyParams = keyParams;
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
        return new BCXMSSPrivateKey(this.treeDigest, keyParams.extractKeyShard(usageCount));
    }

    public String getAlgorithm()
    {
        return "XMSS";
    }

    public String getFormat()
    {
        return "PKCS#8";
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
     * traversal state too - so the tail of this is still a comparison of the two encodings, and
     * still in constant time, since that is what reaches the secret seeds.
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
     * compared the other way. At n bytes it costs nothing against the encoding it avoids.
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
                || keyParams.getIndex() != otherKey.keyParams.getIndex()
                || keyParams.getUsagesRemaining() != otherKey.keyParams.getUsagesRemaining()
                || !Arrays.constantTimeAreEqual(keyParams.getPublicSeed(), otherKey.keyParams.getPublicSeed())
                || !Arrays.constantTimeAreEqual(keyParams.getRoot(), otherKey.keyParams.getRoot()))
            {
                return false;
            }

            return Arrays.constantTimeAreEqual(keyParams.toByteArray(), otherKey.keyParams.toByteArray());
        }

        return false;
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
