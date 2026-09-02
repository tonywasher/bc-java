package org.bouncycastle.crypto.params;

import java.io.IOException;

import org.bouncycastle.crypto.signers.xmss.XMSSEngine;
import org.bouncycastle.util.Encodable;
import org.bouncycastle.util.Pack;

/**
 * XMSS^MT Public Key.
 */
public final class XMSSMTPublicKeyParameters
    extends XMSSMTKeyParameters
    implements Encodable
{
    private final XMSSMTParameters params;
    private final int oid;
    private final byte[] root;
    private final byte[] publicSeed;

    private XMSSMTPublicKeyParameters(Builder builder)
    {
        super(false, builder.params.getTreeDigest());
        params = builder.params;
        int n = params.getTreeDigestSize();
        byte[] publicKey = builder.publicKey;
        if (publicKey != null)
        {
            /* import */
            int oidSize = 4;
            int position = 0;
            // pre-rfc final key without OID.
            if (publicKey.length == n + n)
            {
                oid = 0;
                root = XMSSEngine.extractBytesAtOffset(publicKey, position, n);
                position += n;
                publicSeed = XMSSEngine.extractBytesAtOffset(publicKey, position, n);
            }
            else if (publicKey.length == oidSize + n + n)
            {
                oid = Pack.bigEndianToInt(publicKey, 0);
                position += oidSize;
                root = XMSSEngine.extractBytesAtOffset(publicKey, position, n);
                position += n;
                publicSeed = XMSSEngine.extractBytesAtOffset(publicKey, position, n);
            }
            else
            {
                throw new IllegalArgumentException("public key has wrong size");
            }
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
        private final XMSSMTParameters params;
        /* optional */
        private byte[] root = null;
        private byte[] publicSeed = null;
        private byte[] publicKey = null;

        public Builder(XMSSMTParameters params)
        {
            super();
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

        public XMSSMTPublicKeyParameters build()
        {
            return new XMSSMTPublicKeyParameters(this);
        }
    }

    /**
     * @deprecated use getEncoded() - this method will become private.
     */
    @Deprecated
    public byte[] toByteArray()
    {
        /* oid || root || seed */
        int n = params.getTreeDigestSize();
        int oidSize = 4;
        int rootSize = n;
        int publicSeedSize = n;
        byte[] out;
        int position = 0;
        /* copy oid */
        if (oid != 0)
        {
            out = new byte[oidSize + rootSize + publicSeedSize];
            Pack.intToBigEndian(oid, out, position);
            position += oidSize;
        }
        else
        {
            out = new byte[rootSize + publicSeedSize];
        }
        /* copy root */
        XMSSEngine.copyBytesAtOffset(out, root, position);
        position += rootSize;
        /* copy public seed */
        XMSSEngine.copyBytesAtOffset(out, publicSeed, position);
        return out;
    }

    public byte[] getRoot()
    {
        return XMSSEngine.cloneArray(root);
    }

    public byte[] getPublicSeed()
    {
        return XMSSEngine.cloneArray(publicSeed);
    }

    public XMSSMTParameters getParameters()
    {
        return params;
    }
}
