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
        Pack.intToBigEndian(treeHeight, byteRepresentation, 20);
        Pack.intToBigEndian(treeIndex, byteRepresentation, 24);
        return byteRepresentation;
    }

    public int getTreeHeight()
    {
        return treeHeight;
    }

    public int getTreeIndex()
    {
        return treeIndex;
    }
}
