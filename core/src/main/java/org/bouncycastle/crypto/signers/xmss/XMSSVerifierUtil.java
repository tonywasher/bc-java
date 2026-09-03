package org.bouncycastle.crypto.signers.xmss;

class XMSSVerifierUtil
{
    /**
     * Compute a root node from a tree signature.
     * <p>
     * The length check is the verifying half of the pair described on XMSSEngine.wotsSign: a digest
     * of the wrong length is not rejected downstream but silently truncated by convertToBaseW.
     * Every messageDigest reaching here is a khf output - HMsg at the two entry points, or a node
     * this method itself returned one layer down - so it holds a boundary rather than catching a
     * live path.
     *
     * @param messageDigest Message digest.
     * @param signature     XMSS signature.
     * @return Root node calculated from signature.
     */
    static XMSSNode getRootNodeFromSignature(WOTSPlus wotsPlus, int height, byte[] messageDigest, XMSSReducedSignature signature,
                                              OTSHashAddress otsHashAddress, int indexLeaf)
    {
        if (messageDigest.length != wotsPlus.getParams().getTreeDigestSize())
        {
            throw new IllegalArgumentException("size of messageDigest needs to be equal to size of digest");
        }

        /* prepare adresses */
        LTreeAddress lTreeAddress = (LTreeAddress)new LTreeAddress.Builder()
            .withLayerAddress(otsHashAddress.getLayerAddress()).withTreeAddress(otsHashAddress.getTreeAddress())
            .withLTreeAddress(otsHashAddress.getOTSAddress()).build();
        HashTreeAddress hashTreeAddress = (HashTreeAddress)new HashTreeAddress.Builder()
            .withLayerAddress(otsHashAddress.getLayerAddress()).withTreeAddress(otsHashAddress.getTreeAddress())
            .withTreeIndex(otsHashAddress.getOTSAddress()).build();
        /*
         * calculate WOTS+ public key and compress to obtain original leaf hash
         */
        WOTSPlusPublicKeyParameters wotsPlusPK = wotsPlus.getPublicKeyFromSignature(messageDigest,
            signature.getWOTSPlusSignature(), otsHashAddress);
        XMSSNode[] node = new XMSSNode[2];
        node[0] = XMSSNodeUtil.lTree(wotsPlus, wotsPlusPK, lTreeAddress);

        for (int k = 0; k < height; k++)
        {
            hashTreeAddress = XMSSNodeUtil.withTreeHeight(hashTreeAddress, k);
            if (Math.floor(indexLeaf / (1 << k)) % 2 == 0)
            {
                hashTreeAddress = XMSSNodeUtil.withTreeIndex(hashTreeAddress,
                    hashTreeAddress.getTreeIndex() / 2);
                node[1] = XMSSNodeUtil.randomizeHash(wotsPlus, node[0], signature.getAuthPath().get(k), hashTreeAddress);
            }
            else
            {
                hashTreeAddress = XMSSNodeUtil.withTreeIndex(hashTreeAddress,
                    (hashTreeAddress.getTreeIndex() - 1) / 2);
                node[1] = XMSSNodeUtil.randomizeHash(wotsPlus, signature.getAuthPath().get(k), node[0], hashTreeAddress);
            }
            node[1] = node[1].incrementHeight();
            node[0] = node[1];
        }
        return node[0];
    }
}
