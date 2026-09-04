package org.bouncycastle.crypto.params;

import java.io.IOException;

import org.bouncycastle.crypto.signers.xmss.BDS;
import org.bouncycastle.crypto.signers.xmss.XMSSEngine;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Encodable;
import org.bouncycastle.util.Exceptions;
import org.bouncycastle.util.Pack;

/**
 * XMSS Private Key.
 */
public final class XMSSPrivateKeyParameters
    extends XMSSKeyParameters
    implements Encodable
{

    /**
     * XMSS parameters object.
     */
    private final XMSSParameters params;
    /**
     * Secret for the derivation of WOTS+ secret keys.
     */
    private final byte[] secretKeySeed;
    /**
     * Secret for the randomization of message digests during signature
     * creation.
     */
    private final byte[] secretKeyPRF;
    /**
     * Public seed for the randomization of hashes.
     */
    private final byte[] publicSeed;
    /**
     * Public root of binary tree.
     */
    private final byte[] root;
    /**
     * BDS state.
     */
    private volatile BDS bdsState;

    private XMSSPrivateKeyParameters(Builder builder)
    {
        super(true, builder.params.getTreeDigest());
        params = builder.params;
        int n = params.getTreeDigestSize();
        byte[] privateKey = builder.privateKey;
        if (privateKey != null)
        {
            /* import */
            int height = params.getHeight();
            int indexSize = 4;
            /* index || secretKeySeed || secretKeyPRF || publicSeed || root || BDS state. Only the
             * head is fixed - the serialized BDS state that follows it is variable-length - so what
             * can be checked here is that the head is all there. It has to be checked somewhere:
             * the five reads below take their bytes at computed offsets, and nothing else on the
             * way in from PrivateKeyFactory looks at the length at all. */
            if (privateKey.length < indexSize + 4 * n)
            {
                throw new IllegalArgumentException("private key has wrong size");
            }
            int position = 0;
            int index = Pack.bigEndianToInt(privateKey, position);
            if (!XMSSEngine.isStoredIndexValid(height, index))
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
                BDS bdsImport = XMSSEngine.getBDSFromEncoding(bdsStateBinary, publicSeed);
                bdsState = bdsImport.withWOTSDigest(builder.params.getTreeDigestOID(), builder.params.getTreeDigestSize());
                bdsState.validate(params, index);
                bdsState.validateRoot(root);
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
            byte[] tmpSecretKeySeed = builder.secretKeySeed;
            secretKeySeed = XMSSEngine.validateOrAllocate(tmpSecretKeySeed, n, "secretKeySeed");
            byte[] tmpSecretKeyPRF = builder.secretKeyPRF;
            secretKeyPRF = XMSSEngine.validateOrAllocate(tmpSecretKeyPRF, n, "secretKeyPRF");
            byte[] tmpPublicSeed = builder.publicSeed;
            publicSeed = XMSSEngine.validateOrAllocate(tmpPublicSeed, n, "publicSeed");
            byte[] tmpRoot = builder.root;
            root = XMSSEngine.validateOrAllocate(tmpRoot, n, "root");
            BDS tmpBDSState = builder.bdsState;
            if (tmpBDSState != null)
            {
                bdsState = tmpBDSState;
            }
            else
            {
                bdsState = XMSSEngine.createBDS(params, tmpPublicSeed, tmpSecretKeySeed, builder.index);
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
                    bdsState.validateRoot(builder.root);
                }
            }
            catch (IllegalStateException e)
            {
                throw Exceptions.illegalArgumentException(e.getMessage(), e);
            }
        }
    }

    public long getUsagesRemaining()
    {
        synchronized (this)
        {
            return this.bdsState.getMaxIndex() - this.getIndex() + 1;
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

    public XMSSPrivateKeyParameters rollKey()
    {
        synchronized (this)
        {
            /* prepare authentication path for next leaf */
            if (bdsState.getIndex() < bdsState.getMaxIndex())
            {
                bdsState = XMSSEngine.getNextBDSState(bdsState, publicSeed, secretKeySeed);
            }
            else
            {
                bdsState = new BDS(params, bdsState.getMaxIndex(), bdsState.getMaxIndex() + 1); // no more nodes left.
            }

            return this;
        }
    }

    public XMSSPrivateKeyParameters getNextKey()
    {
        synchronized (this)
        {
            return this.extractKeyShard(1);
        }
    }

    /**
     * Return a key that can be used usageCount times.
     * <p>
     * Note: this will use the range [index...index + usageCount) for the current key.
     * </p>
     *
     * @param usageCount the number of usages the key should have.
     * @return a key based on the current key that can be used usageCount times.
     */
    public XMSSPrivateKeyParameters extractKeyShard(int usageCount)
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
                XMSSPrivateKeyParameters keyParams = new XMSSPrivateKeyParameters.Builder(params)
                    .withSecretKeySeed(secretKeySeed).withSecretKeyPRF(secretKeyPRF)
                    .withPublicSeed(publicSeed).withRoot(root)
                    .withIndex(getIndex())
                    .withOwnedBDSState(bdsState.withMaxIndex(bdsState.getIndex() + usageCount - 1,
                        params.getTreeDigestOID(), params.getTreeDigestSize())).build();

                if (usageCount == this.getUsagesRemaining())
                {
                    this.bdsState = new BDS(params, bdsState.getMaxIndex(), getIndex() + usageCount);   // we're finished.
                }
                else
                {
                    // update the tree to the new index.
                    for (int i = 0; i != usageCount; i++)
                    {
                        this.bdsState = XMSSEngine.getNextBDSState(bdsState, publicSeed, secretKeySeed);
                    }
                }

                return keyParams;
            }
            else
            {
                throw new IllegalArgumentException("usageCount exceeds usages remaining");
            }
        }
    }

    public static class Builder
    {

        /* mandatory */
        private final XMSSParameters params;
        /* optional */
        private int index = 0;
        private int maxIndex = -1;
        private byte[] secretKeySeed = null;
        private byte[] secretKeyPRF = null;
        private byte[] publicSeed = null;
        private byte[] root = null;
        private BDS bdsState = null;
        private byte[] privateKey = null;

        public Builder(XMSSParameters params)
        {
            if (params == null)
            {
                throw new NullPointerException("params == null");
            }
            this.params = params;
        }

        public Builder withIndex(int val)
        {
            index = val;
            return this;
        }

        public Builder withMaxIndex(int val)
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

        public Builder withBDSState(BDS valBDS)
        {
            //
            // Copy, do not adopt, as the XMSS^MT builder does. Rolling the key replaces its state
            // rather than advancing the one it holds, but a signature still marks the state it
            // spent in place - XMSSEngine's markUsed() - so two keys sharing one BDS share that
            // record: one key's signature marks the other's state, and the other is then refused
            // by the check that reads the mark, having signed nothing. It travels the other way
            // too, a caller keeping the state it passed in seeing its own copy marked by a key it
            // has handed it to.
            //
            bdsState = valBDS.withMaxIndex(valBDS.getMaxIndex(), params.getTreeDigestOID(),
                params.getTreeDigestSize());
            return this;
        }

        /**
         * As {@link #withBDSState(BDS)}, for a state the caller has just built and shares with
         * nothing: it is adopted rather than copied a second time. Package private for the reason
         * the XMSS^MT sibling gives - a public way of asking the key to adopt a state is the
         * sharing defect the copy prevents, offered as an option.
         */
        Builder withOwnedBDSState(BDS valBDS)
        {
            bdsState = valBDS;
            return this;
        }

        public Builder withPrivateKey(byte[] privateKeyVal)
        {
            privateKey = XMSSEngine.cloneArray(privateKeyVal);
            return this;
        }

        public XMSSPrivateKeyParameters build()
        {
            if (!((privateKey != null) || (publicSeed != null && secretKeySeed != null)))
            {
                throw new IllegalStateException("publicSeed or secretKeySeed is null");
            }
            return new XMSSPrivateKeyParameters(this);
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
            int indexSize = 4;
            int totalSize = indexSize + n + n + n + n;
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
                throw Exceptions.illegalStateException("error encoding BDS state", e);
            }

            byte[] out = new byte[totalSize + bdsStateOut.length];
            int position = 0;
            /* copy index */
            Pack.intToBigEndian(bdsState.getIndex(), out, position);
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

    public int getIndex()
    {
        return bdsState.getIndex();
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

    public BDS getBDSState()
    {
        return bdsState;
    }

    public XMSSParameters getParameters()
    {
        return params;
    }
}
