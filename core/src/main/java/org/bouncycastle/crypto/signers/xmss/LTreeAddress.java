package org.bouncycastle.crypto.signers.xmss;

/**
 * The words of an L-tree address, RFC 8391 sec. 2.5.
 * <p>
 * Nothing builds one. An L-tree address is the 32 bytes a walk carries, produced from the OTS hash
 * address of the leaf it belongs to by {@link XMSSAddress#subtreeAddressOf(byte[], int)}, and the
 * walk writes the words below into that encoding as it moves them. So what this type amounts to
 * here is where those words sit and what they are called; see {@link XMSSAddress}.
 * </p>
 */
final class LTreeAddress
{

    /**
     * The type word of an L-tree address, named for {@link XMSSAddress#subtreeAddressOf(byte[],
     * int)} to stamp on an encoding it takes the tree of from an address of another type.
     */
    static final int TYPE = 0x01;

    /**
     * Offset of the L-tree address word in the 32-byte encoding. One L-tree is walked per leaf of
     * a tree and the leaves differ in this word alone, so a caller that walks them all steps it
     * through one encoding rather than producing an encoding per leaf.
     */
    static final int LTREE_ADDRESS_OFFSET = 16;

    /**
     * Offsets of the tree height and tree index words in that encoding. These are the two words
     * the L-tree walk in XMSSNodeUtil.lTree moves as it climbs. {@link HashTreeAddress} lays the
     * same two fields out at the same two words - RFC 8391 sec. 2.5 gives every address type one
     * 32-byte frame and numbers the words the same way - and names them for itself, so the walks
     * above the leaves step them under their own type's name.
     */
    static final int TREE_HEIGHT_OFFSET = 20;
    static final int TREE_INDEX_OFFSET = 24;
}
