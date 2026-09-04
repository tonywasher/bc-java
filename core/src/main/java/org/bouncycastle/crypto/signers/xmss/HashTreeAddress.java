package org.bouncycastle.crypto.signers.xmss;

import org.bouncycastle.util.Pack;

/**
 * Hash tree address.
 */
final class HashTreeAddress
    extends XMSSAddress
{

    private static final int TYPE = 0x02;
    private static final int PADDING = 0x00;

    /**
     * Offsets of the tree height and tree index words in the 32-byte encoding
     * {@link #toByteArray()} produces. These are the two words a walk of the tree above the leaves
     * moves as it climbs - BDS, BDSTreeHash and XMSSVerifierUtil - so each of them steps one
     * encoding rather than rebuilding an address per node. {@link LTreeAddress} lays the same two
     * fields out at the same two words and names them for itself.
     */
    static final int TREE_HEIGHT_OFFSET = 20;
    static final int TREE_INDEX_OFFSET = 24;

    private final int padding;
    private final int treeHeight;
    private final int treeIndex;

    private HashTreeAddress(Builder builder)
    {
        super(builder);
        padding = PADDING;
        treeHeight = builder.treeHeight;
        treeIndex = builder.treeIndex;
    }

    public static class Builder
        extends XMSSAddress.Builder<Builder>
    {

        /* optional */
        private int treeHeight = 0;
        private int treeIndex = 0;

        public Builder()
        {
            super(TYPE);
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
            return new HashTreeAddress(this);
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
        Pack.intToBigEndian(padding, byteRepresentation,16);
        Pack.intToBigEndian(treeHeight, byteRepresentation, TREE_HEIGHT_OFFSET);
        Pack.intToBigEndian(treeIndex, byteRepresentation, TREE_INDEX_OFFSET);
        return byteRepresentation;
    }
}
