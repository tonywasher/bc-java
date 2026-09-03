package org.bouncycastle.crypto.params;

import java.io.IOException;

import org.bouncycastle.crypto.signers.xmss.XMSSEngine;
import org.bouncycastle.util.Encodable;

/**
 * XMSS Public Key.
 */
public final class XMSSPublicKeyParameters
    extends XMSSKeyParameters
    implements Encodable
{

    /**
     * XMSS parameters object.
     */
    private final XMSSParameters params;
    private final int oid;
    private final byte[] root;
    private final byte[] publicSeed;

    private XMSSPublicKeyParameters(Builder builder)
    {
        super(false, builder.params.getTreeDigest());
        params = builder.params;
        int n = params.getTreeDigestSize();
        byte[] publicKey = builder.publicKey;
        if (publicKey != null)
        {
            /* import */
            XMSSPublicKeyCodec decoded = XMSSPublicKeyCodec.decode(publicKey, n);

            oid = decoded.getOid();
            root = decoded.getRoot();
            publicSeed = decoded.getPublicSeed();
        }
        else
        {
            /* set */
            this.oid = params.getParameterSetOID();
            root = XMSSEngine.validateOrAllocate(builder.root, n, "root");
            publicSeed = XMSSEngine.validateOrAllocate(builder.publicSeed, n, "publicSeed");
        }
    }

    public byte[] getEncoded()
        throws IOException
    {
        return toByteArray();
    }

    public static class Builder
    {

        /* mandatory */
        private final XMSSParameters params;
        /* optional */
        private byte[] root = null;
        private byte[] publicSeed = null;
        private byte[] publicKey = null;

        public Builder(XMSSParameters params)
        {
            if (params == null)
            {
                throw new NullPointerException("params == null");
            }
            this.params = params;
        }

        public Builder withRoot(byte[] val)
        {
            root = XMSSEngine.cloneArray(val);
            return this;
        }

        public Builder withPublicSeed(byte[] val)
        {
            publicSeed = XMSSEngine.cloneArray(val);
            return this;
        }

        public Builder withPublicKey(byte[] val)
        {
            publicKey = XMSSEngine.cloneArray(val);
            return this;
        }

        public XMSSPublicKeyParameters build()
        {
            return new XMSSPublicKeyParameters(this);
        }
    }

    /**
     * @deprecated use getEncoded() - this method will become private.
     */
    @Deprecated
    public byte[] toByteArray()
    {
        return XMSSPublicKeyCodec.encode(oid, root, publicSeed);
    }

    public byte[] getRoot()
    {
        return XMSSEngine.cloneArray(root);
    }

    public byte[] getPublicSeed()
    {
        return XMSSEngine.cloneArray(publicSeed);
    }

    public XMSSParameters getParameters()
    {
        return params;
    }
}
