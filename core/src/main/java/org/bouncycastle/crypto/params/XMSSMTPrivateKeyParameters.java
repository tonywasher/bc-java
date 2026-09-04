package org.bouncycastle.crypto.params;

import java.io.IOException;

import org.bouncycastle.crypto.signers.xmss.BDSStateMap;
import org.bouncycastle.crypto.signers.xmss.XMSSEngine;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Encodable;
import org.bouncycastle.util.Exceptions;
import org.bouncycastle.util.Pack;

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
            index = Pack.bigEndianToLong_Low(privateKey, position, indexSize);
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

                // a state map written before the maximum index was recorded marks it with a value
                // no state map can carry, having no tree height of its own to resolve it against;
                // here the parameter set is known
                long stateMaxIndex = (bdsImport.getMaxIndex() < 0)
                    ? (1L << totalHeight) - 1 : bdsImport.getMaxIndex();

                // the WOTS+ parameters are not part of what was serialized, so the digest goes back
                // on - in the same copy that carries the maximum index, which used to be a second
                // one taken afterwards because copying a state before naming its digest threw
                bdsState = bdsImport.withMaxIndex(stateMaxIndex, builder.xmss.getTreeDigestOID(),
                    builder.xmss.getTreeDigestSize());
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
            secretKeySeed = Arrays.clone(val);
            return this;
        }

        public Builder withSecretKeyPRF(byte[] val)
        {
            secretKeyPRF = Arrays.clone(val);
            return this;
        }

        public Builder withPublicSeed(byte[] val)
        {
            publicSeed = Arrays.clone(val);
            return this;
        }

        public Builder withRoot(byte[] val)
        {
            root = Arrays.clone(val);
            return this;
        }

        public Builder withBDSState(BDSStateMap val)
        {
            //
            // Copy, do not adopt. Rolling the key replaces its state map rather than advancing the
            // one it holds, but signing still installs subtree states into that map as it descends
            // the layers, so a caller that keeps the map it passed - or passes one it took off
            // another key with getBDSState() - leaves two keys reading authentication paths out of
            // one map while each sits at its own index. The XMSS side copies for a narrower reason
            // of its own, given on its withBDSState: no layer states are installed into a single
            // BDS, but a signature still marks it.
            //
            // The copy names this key's tree digest, as the XMSS side's does. A state map's WOTS+
            // parameters are not part of what it is serialized as, so one that has just been
            // decoded carries none until a digest is named, and copying it any other way used to
            // be a NullPointerException out of the BDS copy constructor - an ordering this class
            // required of every caller and enforced on none. Naming it here also means a state map
            // installed in a key is always one this key's own parameter set built the WOTS+
            // parameters for, rather than whatever the caller had named them with.
            //
            bdsState = val.withMaxIndex(maxIndexFor(val), params.getTreeDigestOID(),
                params.getTreeDigestSize());
            return this;
        }

        /**
         * As {@link #withBDSState(BDSStateMap)}, for a state map the caller has just built and
         * shares with nothing: it is adopted rather than copied a second time.
         * <p>
         * Package private, and deliberately: the copy the public setter makes is what stops a
         * caller keeping the map it handed over, and a way of asking the key to adopt one is the
         * same defect offered as an option. The callers that can use this are the ones inside the
         * class, where the map being handed over was built by the expression handing it over and
         * is provably shared with nothing. Key generation and the two key decode factories build
         * an exclusive map too, but they are in other packages and so go on paying for the copy -
         * once per key pair and once per key read, against a shard that can be taken once per
         * signature.
         * </p>
         */
        Builder withOwnedBDSState(BDSStateMap val)
        {
            long maxIndex = maxIndexFor(val);

            // a legacy state map cannot be given a maximum index in place without changing the map
            // that was handed over, so that one is copied even here
            bdsState = (maxIndex == val.getMaxIndex()) ? val : new BDSStateMap(val, maxIndex);
            return this;
        }

        /**
         * The maximum index a state map handed to this builder should end up with: its own, or -
         * for one written before the maximum index was recorded, which marks itself with a
         * negative value it cannot resolve for itself - the last leaf of the key's own tree.
         */
        private long maxIndexFor(BDSStateMap val)
        {
            return (val.getMaxIndex() < 0) ? (1L << params.getHeight()) - 1 : val.getMaxIndex();
        }

        public Builder withPrivateKey(byte[] privateKeyVal)
        {
            privateKey = Arrays.clone(privateKeyVal);
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
            /* index || secretKeySeed || secretKeyPRF || publicSeed || root || bdsState */
            int n = params.getTreeDigestSize();
            int indexSize = (params.getHeight() + 7) / 8;
            int totalSize = indexSize + n + n + n + n;
            // the two records of the position are about to be written out beside each other, and a
            // stored key that disagrees with itself is refused on the way back in, so say so here
            // rather than persisting one that cannot be read
            bdsState.validateIndex(params, index);
            // the state is encoded first so the rest can be written straight into the array that is
            // returned: appending it with Arrays.concatenate meant allocating the fixed part on its
            // own and then copying both halves into a second array of the full size
            byte[] bdsStateOut;
            try
            {
                bdsStateOut = XMSSEngine.getEncodedBDSState(bdsState, publicSeed);
            }
            catch (IOException e)
            {
                throw Exceptions.illegalStateException("error encoding BDS state map", e);
            }

            byte[] out = new byte[totalSize + bdsStateOut.length];
            int position = 0;
            /* copy index - indexSize is 1..8 for every height the parameters admit (2..62) */
            Pack.longToBigEndian_Low(index, out, position, indexSize);
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
            position += n;
            /* copy bdsState */
            System.arraycopy(bdsStateOut, 0, out, position, bdsStateOut.length);

            return out;
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
        return Arrays.clone(secretKeySeed);
    }

    public byte[] getSecretKeyPRF()
    {
        return Arrays.clone(secretKeyPRF);
    }

    public byte[] getPublicSeed()
    {
        return Arrays.clone(publicSeed);
    }

    public byte[] getRoot()
    {
        return Arrays.clone(root);
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

            //
            // The key's position is recorded twice - here and in each layer's traversal state - and
            // the two are carried by separate statements, so nothing but the author of those
            // statements holds them together. The constructor compares them, which covers a key
            // arriving desynchronised; this covers one going that way while it is held, so a roll
            // that advanced one record and not the other is refused here rather than surfacing as
            // a one-time key signing twice. It is the walk down the layers and d integer
            // comparisons, not the structural check the constructor also runs.
            //
            bdsState.validateIndex(params, index);

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
                                    .withOwnedBDSState(new BDSStateMap(this.bdsState,
                                        getIndex() + usageCount - 1)).build();

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
