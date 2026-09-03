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
            /* index || secretKeySeed || secretKeyPRF || publicSeed || root || BDS state map. As
             * for XMSS, only the head is fixed, so what can be checked here is that the head is all
             * there - and it has to be, since the five reads below take their bytes at computed
             * offsets and nothing on the way in from PrivateKeyFactory looks at the length. */
            if (privateKey.length < indexSize + 4 * n)
            {
                throw new IllegalArgumentException("private key has wrong size");
            }
            int position = 0;
            index = XMSSEngine.bytesToXBigEndian(privateKey, position, indexSize);
            if (!XMSSEngine.isStoredIndexValid(totalHeight, index))
            {
                throw new IllegalArgumentException("index out of bounds");
            }
            position += indexSize;
            secretKeySeed = Arrays.copyOfRange(privateKey, position, position + n);
            position += n;
            secretKeyPRF = Arrays.copyOfRange(privateKey, position, position + n);
            position += n;
            publicSeed = Arrays.copyOfRange(privateKey, position, position + n);
            position += n;
            root = Arrays.copyOfRange(privateKey, position, position + n);
            position += n;
            /* import BDS state */
            byte[] bdsStateBinary = Arrays.copyOfRange(privateKey, position, privateKey.length);

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
            secretKeySeed = XMSSEngine.validateOrAllocate(tmpSecretKeySeed, n, "secretKeySeed");
            byte[] tmpSecretKeyPRF = builder.secretKeyPRF;
            secretKeyPRF = XMSSEngine.validateOrAllocate(tmpSecretKeyPRF, n, "secretKeyPRF");
            byte[] tmpPublicSeed = builder.publicSeed;
            publicSeed = XMSSEngine.validateOrAllocate(tmpPublicSeed, n, "publicSeed");
            byte[] tmpRoot = builder.root;
            root = XMSSEngine.validateOrAllocate(tmpRoot, n, "root");
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
            //
            // Copy, do not adopt. Rolling the key replaces its state map rather than advancing the
            // one it holds, but signing still installs subtree states into that map as it descends
            // the layers, so a caller that keeps the map it passed - or passes one it took off
            // another key with getBDSState() - leaves two keys reading authentication paths out of
            // one map while each sits at its own index. The XMSS side needs no copy for this: its
            // state is a single BDS the signer only reads.
            //
            if (val.getMaxIndex() < 0)   // check for legacy state maps
            {
                bdsState = new BDSStateMap(val, (1L << params.getHeight()) - 1);
            }
            else
            {
                bdsState = new BDSStateMap(val, val.getMaxIndex());
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
            int totalSize = indexSize + n + n + n + n;
            byte[] out = new byte[totalSize];
            int position = 0;
            /* copy index */
            byte[] indexBytes = XMSSEngine.toBytesBigEndian(index, indexSize);
            System.arraycopy(indexBytes, 0, out, position, indexBytes.length);
            position += indexSize;
            /* copy secretKeySeed */
            System.arraycopy(secretKeySeed, 0, out, position, secretKeySeed.length);
            position += n;
            /* copy secretKeyPRF */
            System.arraycopy(secretKeyPRF, 0, out, position, secretKeyPRF.length);
            position += n;
            /* copy publicSeed */
            System.arraycopy(publicSeed, 0, out, position, publicSeed.length);
            position += n;
            /* copy root */
            System.arraycopy(root, 0, out, position, root.length);
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
                // the advanced state comes back rather than being applied to the one held, so the
                // index and the state move together: nothing is assigned unless the walk completed,
                // where advancing in place left a state part way to the next leaf under an index
                // that had not moved. XMSSPrivateKeyParameters.rollKey does the same with its BDS.
                bdsState = XMSSEngine.getNextBDSStateMap(bdsState, params, index, publicSeed, secretKeySeed);
                index = index + 1;
            }
            else
            {
                index = bdsState.getMaxIndex() + 1;
                bdsState = new BDSStateMap(bdsState.getMaxIndex());
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
