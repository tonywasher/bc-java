package org.bouncycastle.crypto.signers.xmss;

class XMSSNodeUtil
{
    /**
     * Compresses a WOTS+ public key to a single n-byte string.
     *
     * @param publicKey WOTS+ public key to compress.
     * @param address   Address.
     * @return Compressed n-byte string of public key.
     */
    public static XMSSNode lTree(WOTSPlus wotsPlus, WOTSPlusPublicKeyParameters publicKey, LTreeAddress address)
    {
        if (publicKey == null)
        {
            throw new NullPointerException("publicKey == null");
        }
        if (address == null)
        {
            throw new NullPointerException("address == null");
        }
        int len = wotsPlus.getParams().getLen();
            /* duplicate public key to XMSSNode Array */
        byte[][] publicKeyBytes = publicKey.toByteArray();
        XMSSNode[] publicKeyNodes = new XMSSNode[publicKeyBytes.length];
        for (int i = 0; i < publicKeyBytes.length; i++)
        {
            publicKeyNodes[i] = new XMSSNode(0, publicKeyBytes[i]);
        }
        address = withTreeHeight(address, 0);
        while (len > 1)
        {
            for (int i = 0; i < (int)Math.floor(len / 2); i++)
            {
                address = withTreeIndex(address, i);
                publicKeyNodes[i] = randomizeHash(wotsPlus, publicKeyNodes[2 * i], publicKeyNodes[(2 * i) + 1], address);
            }
            if (len % 2 == 1)
            {
                publicKeyNodes[(int)Math.floor(len / 2)] = publicKeyNodes[len - 1];
            }
            len = (int)Math.ceil((double)len / 2);
            address = withTreeHeight(address, address.getTreeHeight() + 1);
        }
        return publicKeyNodes[0];
    }

    /**
     * Randomization of nodes in binary tree.
     *
     * @param left    Left node.
     * @param right   Right node.
     * @param address Address.
     * @return Randomized hash of parent of left / right node.
     */
    public static XMSSNode randomizeHash(WOTSPlus wotsPlus, XMSSNode left, XMSSNode right, XMSSAddress address)
    {
        if (left == null)
        {
            throw new NullPointerException("left == null");
        }
        if (right == null)
        {
            throw new NullPointerException("right == null");
        }
        if (left.getHeight() != right.getHeight())
        {
            throw new IllegalStateException("height of both nodes must be equal");
        }
        if (address == null)
        {
            throw new NullPointerException("address == null");
        }
        byte[] publicSeed = wotsPlus.getPublicSeed();

        address = withKeyAndMask(address, 0);
        byte[] key = wotsPlus.getKhf().PRF(publicSeed, address.toByteArray());

        address = withKeyAndMask(address, 1);
        byte[] bitmask0 = wotsPlus.getKhf().PRF(publicSeed, address.toByteArray());

        address = withKeyAndMask(address, 2);
        byte[] bitmask1 = wotsPlus.getKhf().PRF(publicSeed, address.toByteArray());

        int n = wotsPlus.getParams().getTreeDigestSize();
        byte[] leftValue = left.getValue();
        byte[] rightValue = right.getValue();
        byte[] tmpMask = new byte[2 * n];
        for (int i = 0; i < n; i++)
        {
            tmpMask[i] = (byte)(leftValue[i] ^ bitmask0[i]);
        }
        for (int i = 0; i < n; i++)
        {
            tmpMask[i + n] = (byte)(rightValue[i] ^ bitmask1[i]);
        }
        byte[] out = wotsPlus.getKhf().H(key, tmpMask);
        return new XMSSNode(left.getHeight(), out);
    }

    /*
     * An XMSS address is immutable, so setting one of its fields means rebuilding the whole
     * address and carrying the others over by hand. The helpers below are that rebuild, written
     * once for each (address type, field) pair the tree walks step, so a caller cannot leave a
     * field out by accident.
     *
     * They are NOT a substitute for every builder call in the package: a rebuild that drops a
     * field on purpose - BDS.initialize resetting treeHeight for each new leaf, or the ones that
     * change two fields at once - has to stay written out, and says so where it stands.
     */

    /**
     * The given address with its OTS address replaced and every other field carried over, as the
     * leaf walks in BDS and BDSTreeHash need when they step to the next one-time key.
     *
     * @param address    OTS hash address to copy.
     * @param otsAddress OTS address to set.
     * @return address with the given OTS address.
     */
    static OTSHashAddress withOTSAddress(OTSHashAddress address, int otsAddress)
    {
        return (OTSHashAddress)new OTSHashAddress.Builder()
            .withLayerAddress(address.getLayerAddress()).withTreeAddress(address.getTreeAddress())
            .withOTSAddress(otsAddress).withChainAddress(address.getChainAddress())
            .withHashAddress(address.getHashAddress()).withKeyAndMask(address.getKeyAndMask())
            .build();
    }

    /**
     * The given address with its tree height replaced and every other field carried over, as the
     * tree walks need when they move up a level.
     *
     * @param address    Hash tree address to copy.
     * @param treeHeight Tree height to set.
     * @return address with the given tree height.
     */
    static HashTreeAddress withTreeHeight(HashTreeAddress address, int treeHeight)
    {
        return (HashTreeAddress)new HashTreeAddress.Builder()
            .withLayerAddress(address.getLayerAddress()).withTreeAddress(address.getTreeAddress())
            .withTreeHeight(treeHeight).withTreeIndex(address.getTreeIndex())
            .withKeyAndMask(address.getKeyAndMask()).build();
    }

    /**
     * The given address with its tree index replaced and every other field carried over, as the
     * tree walks need when they move to the parent node.
     *
     * @param address   Hash tree address to copy.
     * @param treeIndex Tree index to set.
     * @return address with the given tree index.
     */
    static HashTreeAddress withTreeIndex(HashTreeAddress address, int treeIndex)
    {
        return (HashTreeAddress)new HashTreeAddress.Builder()
            .withLayerAddress(address.getLayerAddress()).withTreeAddress(address.getTreeAddress())
            .withTreeHeight(address.getTreeHeight()).withTreeIndex(treeIndex)
            .withKeyAndMask(address.getKeyAndMask()).build();
    }

    /**
     * The given address with its tree height replaced and every other field carried over, for the
     * L-tree walk in lTree().
     *
     * @param address    L-tree address to copy.
     * @param treeHeight Tree height to set.
     * @return address with the given tree height.
     */
    private static LTreeAddress withTreeHeight(LTreeAddress address, int treeHeight)
    {
        return (LTreeAddress)new LTreeAddress.Builder()
            .withLayerAddress(address.getLayerAddress()).withTreeAddress(address.getTreeAddress())
            .withLTreeAddress(address.getLTreeAddress()).withTreeHeight(treeHeight)
            .withTreeIndex(address.getTreeIndex()).withKeyAndMask(address.getKeyAndMask()).build();
    }

    /**
     * The given address with its tree index replaced and every other field carried over, for the
     * L-tree walk in lTree().
     *
     * @param address   L-tree address to copy.
     * @param treeIndex Tree index to set.
     * @return address with the given tree index.
     */
    private static LTreeAddress withTreeIndex(LTreeAddress address, int treeIndex)
    {
        return (LTreeAddress)new LTreeAddress.Builder()
            .withLayerAddress(address.getLayerAddress()).withTreeAddress(address.getTreeAddress())
            .withLTreeAddress(address.getLTreeAddress()).withTreeHeight(address.getTreeHeight())
            .withTreeIndex(treeIndex).withKeyAndMask(address.getKeyAndMask()).build();
    }

    /**
     * The given address with its key-and-mask replaced and every other field carried over, as
     * randomizeHash() needs for the three PRF calls - key, then the two bitmasks - it makes per
     * node. Only the two address types that reach a tree hash are rebuilt; any other type is
     * returned unchanged, exactly as the code this replaces left it.
     *
     * @param address    Address to copy.
     * @param keyAndMask Key and mask to set.
     * @return address with the given key and mask.
     */
    private static XMSSAddress withKeyAndMask(XMSSAddress address, int keyAndMask)
    {
        if (address instanceof LTreeAddress)
        {
            LTreeAddress tmpAddress = (LTreeAddress)address;
            return new LTreeAddress.Builder().withLayerAddress(tmpAddress.getLayerAddress())
                .withTreeAddress(tmpAddress.getTreeAddress()).withLTreeAddress(tmpAddress.getLTreeAddress())
                .withTreeHeight(tmpAddress.getTreeHeight()).withTreeIndex(tmpAddress.getTreeIndex())
                .withKeyAndMask(keyAndMask).build();
        }
        if (address instanceof HashTreeAddress)
        {
            HashTreeAddress tmpAddress = (HashTreeAddress)address;
            return new HashTreeAddress.Builder().withLayerAddress(tmpAddress.getLayerAddress())
                .withTreeAddress(tmpAddress.getTreeAddress()).withTreeHeight(tmpAddress.getTreeHeight())
                .withTreeIndex(tmpAddress.getTreeIndex()).withKeyAndMask(keyAndMask).build();
        }
        return address;
    }
}
