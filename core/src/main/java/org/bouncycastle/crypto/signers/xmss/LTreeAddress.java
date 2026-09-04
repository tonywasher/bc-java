package org.bouncycastle.crypto.signers.xmss;

import org.bouncycastle.util.Pack;

/**
 * L-tree address.
 */
final class LTreeAddress
    extends XMSSAddress
{

    /**
     * The type word of an L-tree address, named for {@link XMSSAddress#subtreeAddressOf(byte[],
     * int)} to stamp on an encoding it takes the tree of from an address of another type.
     */
    static final int TYPE = 0x01;

    /**
     * Offset of the L-tree address word in the 32-byte encoding {@link #toByteArray()} produces.
     * One L-tree is walked per leaf of a tree and the leaves differ in this word alone, so a
     * caller that walks them all steps it through one encoding rather than rebuilding an address
     * per leaf.
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

    private final int lTreeAddress;
    private final int treeHeight;
    private final int treeIndex;

    private LTreeAddress(Builder builder)
    {
        super(builder);
        lTreeAddress = builder.lTreeAddress;
        treeHeight = builder.treeHeight;
        treeIndex = builder.treeIndex;
    }

    public static class Builder
        extends XMSSAddress.Builder<Builder>
    {

        /* optional */
        private int lTreeAddress = 0;
        private int treeHeight = 0;
        private int treeIndex = 0;

        public Builder()
        {
            super(TYPE);
        }

        public Builder withLTreeAddress(int val)
        {
            lTreeAddress = val;
            return this;
        }

        public Builder withTreeHeight(int val)
        {
            treeHeight = val;
            return this;
        }

        public Builder withTreeIndex(int val)
        {
            treeIndex = val;
            return this;
        }

        @Override
        public XMSSAddress build()
        {
            return new LTreeAddress(this);
        }

        @Override
        public Builder getThis()
        {
            return this;
        }
    }

    @Override
    public byte[] toByteArray()
    {
        byte[] byteRepresentation = super.toByteArray();
        Pack.intToBigEndian(lTreeAddress, byteRepresentation, LTREE_ADDRESS_OFFSET);
        Pack.intToBigEndian(treeHeight, byteRepresentation, TREE_HEIGHT_OFFSET);
        Pack.intToBigEndian(treeIndex, byteRepresentation, TREE_INDEX_OFFSET);
        return byteRepresentation;
    }
}
