package org.bouncycastle.crypto.signers.xmss;

/**
 * WOTS+ public key.
 */
final class WOTSPlusPublicKeyParameters
{
    private final byte[][] publicKey;

    public WOTSPlusPublicKeyParameters(WOTSPlusParameters params, byte[][] publicKey)
    {
        this.publicKey = params.checkedClone(publicKey, "publicKey");
    }

    public byte[][] toByteArray()
    {
        return XMSSUtil.cloneArray(publicKey);
    }

    /**
     * This key's blocks, each wrapped as a height-0 {@link XMSSNode}, as the L-tree walk in
     * {@link XMSSNodeUtil#lTree} starts from. A node only ever copies its value outwards -
     * getValue() clones it and encodeTo() writes it elsewhere - so wrapping the blocks themselves,
     * rather than the deep copy {@link #toByteArray()} makes, lets nothing escape that did not
     * before, and saves len + 1 arrays per one-time key compressed. That is one key per leaf of
     * every tree built, so at the SHA-256 parameter sets it is 68 arrays a leaf.
     */
    XMSSNode[] toNodes()
    {
        XMSSNode[] nodes = new XMSSNode[publicKey.length];
        for (int i = 0; i != publicKey.length; i++)
        {
            nodes[i] = new XMSSNode(0, publicKey[i]);
        }
        return nodes;
    }
}
