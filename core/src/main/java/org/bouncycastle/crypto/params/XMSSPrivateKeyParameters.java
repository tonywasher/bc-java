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
            int index = Pack.bigEndianToInt(privateKey, position);
            if (!XMSSEngine.isStoredIndexValid(height, index))
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
            secretKeySeed = validateOrAllocate(tmpSecretKeySeed, n, "secretKeySeed");
            byte[] tmpSecretKeyPRF = builder.secretKeyPRF;
            secretKeyPRF = validateOrAllocate(tmpSecretKeyPRF, n, "secretKeyPRF");
            byte[] tmpPublicSeed = builder.publicSeed;
            publicSeed = validateOrAllocate(tmpPublicSeed, n, "publicSeed");
            byte[] tmpRoot = builder.root;
            root = validateOrAllocate(tmpRoot, n, "root");
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
            XMSSPrivateKeyParameters keyParameters = this.extractKeyShard(1);

            return keyParameters;
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
                    .withBDSState(bdsState.withMaxIndex(bdsState.getIndex() + usageCount - 1,
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
            super();
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
            /* index || secretKeySeed || secretKeyPRF || publicSeed || root */
            int n = params.getTreeDigestSize();
            int indexSize = 4;
            int secretKeySize = n;
            int secretKeyPRFSize = n;
            int publicSeedSize = n;
            int rootSize = n;
            int totalSize = indexSize + secretKeySize + secretKeyPRFSize + publicSeedSize + rootSize;
            byte[] out = new byte[totalSize];
            int position = 0;
            /* copy index */
            Pack.intToBigEndian(bdsState.getIndex(), out, position);
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
            byte[] bdsStateOut = null;
            try
            {
                bdsStateOut = XMSSEngine.getEncodedBDSState(bdsState, publicSeed);
            }
            catch (IOException e)
            {
                throw Exceptions.illegalStateException("error encoding BDS state", e);
            }

            return Arrays.concatenate(out, bdsStateOut);
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
