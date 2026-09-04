package org.bouncycastle.crypto.signers.xmss;

import org.bouncycastle.util.Pack;

class XMSSNodeUtil
{
    /**
     * Compresses a WOTS+ public key to a single n-byte string.
     * <p>
     * The key and the length it is walked with arrive from two places - the array from publicKey,
     * len from wotsPlus - and nothing in the signature ties them together. They agree because every
     * caller takes the key from the same WOTSPlus instance it passes here, a line or two earlier:
     * BDS and BDSTreeHash from getPublicKey(), XMSSVerifierUtil from getPublicKeyFromSignature().
     * A key from another parameter set would index past the end of the array, or leave its tail
     * unread. That pairing is this method's real precondition and it is the caller's to keep.
     * </p>
     *
     * @param publicKey WOTS+ public key to compress.
     * @param address   Address.
     * @return Compressed n-byte string of public key.
     */
    static XMSSNode lTree(WOTSPlus wotsPlus, WOTSPlusPublicKeyParameters publicKey, LTreeAddress address)
    {
        int len = wotsPlus.getParams().getLen();
        /* the key's blocks as the leaves of the L-tree, and the walk overwrites the array, not them */
        XMSSNode[] publicKeyNodes = publicKey.toNodes();
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
     * <p>
     * Unlike the addresses, the nodes reaching here are not always built a line earlier: they come
     * from a BDS state's stack, authentication path, kept nodes or a tree hash's tail, and such a
     * state can have arrived by deserialization. That they are there at all is settled where the
     * state enters rather than here - BDS.readObject refuses a stream carrying null collections or
     * null entries, BDS.validate walks every node a state holds, and nextAuthenticationPath names
     * the one node it fetches by index ("missing keep node in BDS state") because an NPE out of the
     * hash below would not say what was wrong. The equal-height check is a different thing again:
     * the algorithm only ever hashes two nodes of the same height together.
     * </p>
     *
     * @param left    Left node.
     * @param right   Right node.
     * @param address Address.
     * @return Randomized hash of parent of left / right node.
     */
    static XMSSNode randomizeHash(WOTSPlus wotsPlus, XMSSNode left, XMSSNode right, XMSSAddress address)
    {
        if (left.getHeight() != right.getHeight())
        {
            throw new IllegalStateException("height of both nodes must be equal");
        }
        byte[] publicSeed = wotsPlus.getPublicSeed();
        KeyedHashFunctions khf = wotsPlus.getKhf();
        int n = wotsPlus.getParams().getTreeDigestSize();

        // The three PRFs differ in one word of the address, so they run over one encoding of it
        // taken once with that word written in, the way WOTSPlus.chain steps its two; the offset
        // is named on the class that lays the encoding out rather than copied here.
        //
        // This is where withKeyAndMask() was, and what it did with an address that was neither an
        // LTreeAddress nor a HashTreeAddress was return it unchanged - leaving key-and-mask at
        // whatever it already held, so the three PRFs would be three of the same hash. Writing the
        // word sets it for every address type. Nothing changes today, no caller passing anything
        // else - lTree an LTreeAddress, BDS, BDSTreeHash and XMSSVerifierUtil a HashTreeAddress -
        // but the rule is now the one RFC 8391 sec. 4.1.5 states rather than one about subtypes.
        //
        // The two bitmasks are produced straight into the 2n-byte buffer they are masked in, where
        // maskInto turns each half into the masked value. Only the key needs an array of its own,
        // being the one of the three that H reads as a key rather than as the data it hashes.
        byte[] addressBytes = address.toByteArray();
        byte[] key = new byte[n];
        byte[] tmpMask = new byte[2 * n];

        Pack.intToBigEndian(0, addressBytes, XMSSAddress.KEY_AND_MASK_OFFSET);
        khf.PRF(publicSeed, addressBytes, key);

        Pack.intToBigEndian(1, addressBytes, XMSSAddress.KEY_AND_MASK_OFFSET);
        khf.PRF(publicSeed, addressBytes, tmpMask, 0);

        Pack.intToBigEndian(2, addressBytes, XMSSAddress.KEY_AND_MASK_OFFSET);
        khf.PRF(publicSeed, addressBytes, tmpMask, n);

        left.maskInto(n, tmpMask, 0);
        right.maskInto(n, tmpMask, n);

        byte[] out = new byte[n];
        khf.H(key, tmpMask, out);
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
}
