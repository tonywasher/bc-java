package org.bouncycastle.pqc.jcajce.provider.xmss;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PrivateKey;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.pqc.crypto.util.PrivateKeyFactory;
import org.bouncycastle.pqc.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTPublicKeyParameters;
import org.bouncycastle.pqc.jcajce.interfaces.XMSSMTPrivateKey;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Exceptions;

public class BCXMSSMTPrivateKey
    implements PrivateKey, XMSSMTPrivateKey
{
    private static final long serialVersionUID = 7682140473044521395L;

    private transient ASN1ObjectIdentifier treeDigest;
    private transient XMSSMTPrivateKeyParameters keyParams;
    private transient ASN1Set attributes;

    public BCXMSSMTPrivateKey(
        ASN1ObjectIdentifier treeDigest,
        XMSSMTPrivateKeyParameters keyParams)
    {
        this.treeDigest = treeDigest;
        this.keyParams = keyParams;
    }

    public BCXMSSMTPrivateKey(PrivateKeyInfo keyInfo)
        throws IOException
    {
        init(keyInfo);
    }

    private void init(PrivateKeyInfo keyInfo)
        throws IOException
    {
        this.attributes = keyInfo.getAttributes();
        // Derive the tree digest from the recovered key rather than the AlgorithmIdentifier
        // parameters: the RFC 9802 form (id-alg-xmssmt-hashsig) carries no XMSSMTKeyParams, so
        // reading them would NPE. Mirrors BCXMSSMTPublicKey.init.
        this.keyParams = (XMSSMTPrivateKeyParameters)PrivateKeyFactory.createKey(keyInfo);
        this.treeDigest = DigestUtil.getDigestOID(keyParams.getTreeDigest());
    }

    public long getIndex()
    {
        if (getUsagesRemaining() == 0)
        {
            throw new IllegalStateException("key exhausted");
        }

        return keyParams.getIndex();
    }

    public long getUsagesRemaining()
    {
        return keyParams.getUsagesRemaining();
    }

    public XMSSMTPrivateKey extractKeyShard(int usageCount)
    {
        return new BCXMSSMTPrivateKey(this.treeDigest, keyParams.extractKeyShard(usageCount));
    }

    public String getAlgorithm()
    {
        return "XMSSMT";
    }

    public String getFormat()
    {
        return "PKCS#8";
    }

    public byte[] getEncoded()
    {
        if (keyParams.isDestroyed())
        {
            throw new IllegalStateException("key destroyed");
        }

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

    CipherParameters getKeyParams()
    {
        return keyParams;
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }

        if (o instanceof BCXMSSMTPrivateKey)
        {
            BCXMSSMTPrivateKey otherKey = (BCXMSSMTPrivateKey)o;

            // a destroyed key no longer exposes its value, so it is only equal to itself.
            if (isDestroyed() || otherKey.isDestroyed())
            {
                return false;
            }

            return treeDigest.equals(otherKey.treeDigest) & Arrays.constantTimeAreEqual(keyParams.toByteArray(), otherKey.keyParams.toByteArray());
        }

        return false;
    }

    public int hashCode()
    {
        return getPublicKey().hashCode();
    }

    private BCXMSSMTPublicKey getPublicKey()
    {
        XMSSMTPublicKeyParameters pubParams = new XMSSMTPublicKeyParameters.Builder(keyParams.getParameters())
            .withRoot(keyParams.getRoot())
            .withPublicSeed(keyParams.getPublicSeed())
            .build();
        return new BCXMSSMTPublicKey(treeDigest, pubParams);
    }

    ASN1ObjectIdentifier getTreeDigestOID()
    {
        return treeDigest;
    }

    public int getHeight()
    {
        return keyParams.getParameters().getHeight();
    }

    public int getLayers()
    {
        return keyParams.getParameters().getLayers();
    }

    public String getTreeDigest()
    {
        return DigestUtil.getXMSSDigestName(treeDigest, keyParams.getParameters().getTreeDigestSize());
    }

    /**
     * Destroy this key, zeroizing the secret key material it holds.
     * <p>
     * The secret key seed, the PRF key and the WOTS+ secrets retained by the per-layer BDS
     * traversal states are zeroized; the public seed, root, index and tree nodes are retained, so
     * {@link #getIndex()}, {@link #getUsagesRemaining()}, {@link #getHeight()},
     * {@link #getLayers()} and {@link #getTreeDigest()} keep working and {@link #hashCode()} is
     * stable. After destruction {@link #isDestroyed()} returns true, {@link #getEncoded()} and
     * {@link #extractKeyShard(int)} throw {@link IllegalStateException}, the key can no longer be
     * serialized, and a Signature refuses it at initSign. Shards extracted before destruction hold
     * their own copies of the seeds and are unaffected. As the underlying
     * {@link XMSSMTPrivateKeyParameters} object is destroyed, keys sharing it are invalidated too.
     */
    public synchronized void destroy()
    {
        keyParams.destroy();
    }

    public boolean isDestroyed()
    {
        return keyParams.isDestroyed();
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

        try
        {
            out.writeObject(this.getEncoded());
        }
        catch (IllegalStateException e)
        {
            throw Exceptions.ioException(e.getMessage(), e);
        }
    }
}
