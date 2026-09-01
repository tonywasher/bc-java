package org.bouncycastle.crypto.params;

import java.io.IOException;

import org.bouncycastle.crypto.signers.xmss.BDSStateMap;
import org.bouncycastle.crypto.signers.xmss.XMSSEngine;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Encodable;
import org.bouncycastle.util.Exceptions;

/**
 * XMSS^MT Private Key.
 */
public final class XMSSMTPrivateKeyParameters
    extends XMSSMTKeyParameters
    implements Encodable
{
    private final XMSSMTParameters params;
    private final byte[] secretKeySeed;
    private final byte[] secretKeyPRF;
    private final byte[] publicSeed;
    private final byte[] root;

    private volatile long index;
    private volatile BDSStateMap bdsState;
    private volatile boolean used;

    private XMSSMTPrivateKeyParameters(Builder builder)
    {
        super(true, builder.params.getTreeDigest());
        params = builder.params;

        int n = params.getTreeDigestSize();
        byte[] privateKey = builder.privateKey;
        if (privateKey != null)
        {
            if (builder.xmss == null)
            {
                throw new NullPointerException("xmss == null");
            }
            /* import */
            int totalHeight = params.getHeight();
            int indexSize = (totalHeight + 7) / 8;
            int secretKeySize = n;
            int secretKeyPRFSize = n;
            int publicSeedSize = n;
            int rootSize = n;
            /*
            int totalSize = indexSize + secretKeySize + secretKeyPRFSize + publicSeedSize + rootSize;
            if (privateKey.length != totalSize) {
                throw new ParseException("private key has wrong size", 0);
            }
            */
            int position = 0;
            index = XMSSEngine.bytesToXBigEndian(privateKey, position, indexSize);
            if (!XMSSEngine.isStoredIndexValid(totalHeight, index))
            {
                throw new IllegalArgumentException("index out of bounds");
            }
            position += indexSize;
            secretKeySeed = XMSSEngine.extractBytesAtOffset(privateKey, position, secretKeySize);
            position += secretKeySize;
            secretKeyPRF = XMSSEngine.extractBytesAtOffset(privateKey, position, secretKeyPRFSize);
            position += secretKeyPRFSize;
            publicSeed = XMSSEngine.extractBytesAtOffset(privateKey, position, publicSeedSize);
            position += publicSeedSize;
            root = XMSSEngine.extractBytesAtOffset(privateKey, position, rootSize);
            position += rootSize;
            /* import BDS state */
            byte[] bdsStateBinary = XMSSEngine.extractBytesAtOffset(privateKey, position, privateKey.length - position);

            try
            {
                BDSStateMap bdsImport = XMSSEngine.getBDSStateMapFromEncoding(bdsStateBinary, publicSeed);

                // the WOTS+ parameters are not part of what was serialized, and the copy the
                // legacy fixup below makes of each state needs them, so put the digest back first
                bdsImport = bdsImport.withWOTSDigest(builder.xmss.getTreeDigestOID(), builder.xmss.getTreeDigestSize());

                if (bdsImport.getMaxIndex() < 0)   // check for legacy state maps
                {
                    bdsImport = new BDSStateMap(bdsImport, (1L << totalHeight) - 1);
                }

                bdsState = bdsImport;
                bdsState.validate(params, index);
                bdsState.validateRoot(params, root);
            }
            catch (IOException e)
            {
                throw Exceptions.illegalArgumentException(e.getMessage(), e);
            }
            catch (ClassNotFoundException e)
            {
                throw Exceptions.illegalArgumentException(e.getMessage(), e);
            }
            catch (IllegalStateException e)
            {
                throw Exceptions.illegalArgumentException(e.getMessage(), e);
            }
        }
        else
        {
            /* set */
            index = builder.index;
            byte[] tmpSecretKeySeed = builder.secretKeySeed;
            secretKeySeed = validateOrAllocate(tmpSecretKeySeed, n, "secretKeySeed");
            byte[] tmpSecretKeyPRF = builder.secretKeyPRF;
            secretKeyPRF = validateOrAllocate(tmpSecretKeyPRF, n, "secretKeyPRF");
            byte[] tmpPublicSeed = builder.publicSeed;
            publicSeed = validateOrAllocate(tmpPublicSeed, n, "publicSeed");
            byte[] tmpRoot = builder.root;
            root = validateOrAllocate(tmpRoot, n, "root");
            BDSStateMap tmpBDSState = builder.bdsState;
            if (tmpBDSState != null)
            {
                bdsState = tmpBDSState;
            }
            else
            {
                long globalIndex = builder.index;
                int totalHeight = params.getHeight();

                if (XMSSEngine.isIndexValid(totalHeight, globalIndex) && tmpPublicSeed != null && tmpSecretKeySeed != null)
                {
                    bdsState = new BDSStateMap(params, builder.index, tmpPublicSeed, tmpSecretKeySeed);
                }
                else
                {
                    bdsState = new BDSStateMap(builder.maxIndex + 1);
                }
            }
            if (builder.maxIndex >= 0 && builder.maxIndex != bdsState.getMaxIndex())
            {
                throw new IllegalArgumentException("maxIndex set but not reflected in state");
            }
            try
            {
                bdsState.validate(params, builder.index);
                if (builder.bdsState != null)
                {
                    // only a restored state carries a root worth comparing: one built here is
                    // computed from the seeds, and a key built without a root carries zeros
                    bdsState.validateRoot(params, builder.root);
                }
            }
            catch (IllegalStateException e)
            {
                throw Exceptions.illegalArgumentException(e.getMessage(), e);
            }
        }
    }

    public byte[] getEncoded()
        throws IOException
    {
        synchronized (this)
        {
            return toByteArray();
        }
    }

    public static class Builder
    {
        /* mandatory */
        private final XMSSMTParameters params;
        /* optional */
        private long index = 0L;
        private long maxIndex = -1L;
        private byte[] secretKeySeed = null;
        private byte[] secretKeyPRF = null;
        private byte[] publicSeed = null;
        private byte[] root = null;
        private BDSStateMap bdsState = null;
        private byte[] privateKey = null;
        private XMSSParameters xmss = null;

        public Builder(XMSSMTParameters params)
        {
            super();
            if (params == null)
            {
                throw new NullPointerException("params == null");
            }
            this.params = params;
        }

        public Builder withIndex(long val)
        {
            index = val;
            return this;
        }

        public Builder withMaxIndex(long val)
        {
            maxIndex = val;
            return this;
        }

        public Builder withSecretKeySeed(byte[] val)
        {
            secretKeySeed = XMSSEngine.cloneArray(val);
            return this;
        }

        public Builder withSecretKeyPRF(byte[] val)
        {
            secretKeyPRF = XMSSEngine.cloneArray(val);
            return this;
        }

        public Builder withPublicSeed(byte[] val)
        {
            publicSeed = XMSSEngine.cloneArray(val);
            return this;
        }

        public Builder withRoot(byte[] val)
        {
            root = XMSSEngine.cloneArray(val);
            return this;
        }

        public Builder withBDSState(BDSStateMap val)
        {
            if (val.getMaxIndex() < 0)   // check for legacy state maps
            {
                bdsState = new BDSStateMap(val, (1L << params.getHeight()) - 1);
            }
            else
            {
                bdsState = val;
            }
            return this;
        }

        public Builder withPrivateKey(byte[] privateKeyVal)
        {
            privateKey = XMSSEngine.cloneArray(privateKeyVal);
            xmss = params.getXMSSParameters();
            return this;
        }

        public XMSSMTPrivateKeyParameters build()
        {
            if (!((privateKey != null) || (publicSeed != null && secretKeySeed != null)))
            {
                throw new IllegalStateException("publicSeed or secretKeySeed is null");
            }
            return new XMSSMTPrivateKeyParameters(this);
        }
    }

    /**
     * @deprecated use getEncoded() - this method will become private.
     */
    @Deprecated
    public byte[] toByteArray()
    {
        synchronized (this)
        {
            /* index || secretKeySeed || secretKeyPRF || publicSeed || root */
            int n = params.getTreeDigestSize();
            int indexSize = (params.getHeight() + 7) / 8;
            int secretKeySize = n;
            int secretKeyPRFSize = n;
            int publicSeedSize = n;
            int rootSize = n;
            int totalSize = indexSize + secretKeySize + secretKeyPRFSize + publicSeedSize + rootSize;
            byte[] out = new byte[totalSize];
            int position = 0;
            /* copy index */
            byte[] indexBytes = XMSSEngine.toBytesBigEndian(index, indexSize);
            XMSSEngine.copyBytesAtOffset(out, indexBytes, position);
            position += indexSize;
            /* copy secretKeySeed */
            XMSSEngine.copyBytesAtOffset(out, secretKeySeed, position);
            position += secretKeySize;
            /* copy secretKeyPRF */
            XMSSEngine.copyBytesAtOffset(out, secretKeyPRF, position);
            position += secretKeyPRFSize;
            /* copy publicSeed */
            XMSSEngine.copyBytesAtOffset(out, publicSeed, position);
            position += publicSeedSize;
            /* copy root */
            XMSSEngine.copyBytesAtOffset(out, root, position);
            /* concatenate bdsState */
            try
            {
                return Arrays.concatenate(out, XMSSEngine.getEncodedBDSState(bdsState, publicSeed));
            }
            catch (IOException e)
            {
                throw Exceptions.illegalStateException("error encoding BDS state map", e);
            }
        }
    }

    public long getIndex()
    {
        return index;
    }

    public long getUsagesRemaining()
    {
        synchronized (this)
        {
            return this.bdsState.getMaxIndex() - this.getIndex() + 1;
        }
    }

    public byte[] getSecretKeySeed()
    {
        return XMSSEngine.cloneArray(secretKeySeed);
    }

    public byte[] getSecretKeyPRF()
    {
        return XMSSEngine.cloneArray(secretKeyPRF);
    }

    public byte[] getPublicSeed()
    {
        return XMSSEngine.cloneArray(publicSeed);
    }

    public byte[] getRoot()
    {
        return XMSSEngine.cloneArray(root);
    }

    public BDSStateMap getBDSState()
    {
        return bdsState;
    }

    public XMSSMTParameters getParameters()
    {
        return params;
    }

    public XMSSMTPrivateKeyParameters getNextKey()
    {
        synchronized (this)
        {
            return this.extractKeyShard(1);
        }
    }

    public XMSSMTPrivateKeyParameters rollKey()
    {
        synchronized (this)
        {
            if (this.getIndex() < bdsState.getMaxIndex())
            {
                bdsState.updateState(params, index, publicSeed, secretKeySeed);
                index = index + 1;
                used = false;
            }
            else
            {
                index = bdsState.getMaxIndex() + 1;
                bdsState = new BDSStateMap(bdsState.getMaxIndex());
                used = false;
            }

            return this;
        }
    }

    /**
     * Return a key that can be used usageCount times.
     * <p>
     * Note: this will use the range [index...index + usageCount) for the current key.
     * </p>
     * @param usageCount the number of usages the key should have.
     * @return a key based on the current key that can be used usageCount times.
     */
    public XMSSMTPrivateKeyParameters extractKeyShard(int usageCount)
    {
        if (usageCount < 1)
        {
            throw new IllegalArgumentException("cannot ask for a shard with 0 keys");
        }
        synchronized (this)
        {
            /* prepare authentication path for next leaf */
            if (usageCount <= this.getUsagesRemaining())
            {
                XMSSMTPrivateKeyParameters keyParams = new XMSSMTPrivateKeyParameters.Builder(params)
                                    .withSecretKeySeed(secretKeySeed).withSecretKeyPRF(secretKeyPRF)
                                    .withPublicSeed(publicSeed).withRoot(root)
                                    .withIndex(getIndex())
                                    .withBDSState(new BDSStateMap(this.bdsState, getIndex() + usageCount - 1)).build();

                for (int i = 0; i != usageCount; i++)
                {
                    this.rollKey();
                }

                return keyParams;
            }
            else
            {
                throw new IllegalArgumentException("usageCount exceeds usages remaining");
            }
        }
    }
}
