package org.bouncycastle.crypto.signers.xmss;

import org.bouncycastle.util.Pack;

/**
 * L-tree address.
 */
final class LTreeAddress
    extends XMSSAddress
{

    private static final int TYPE = 0x01;

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
        Pack.intToBigEndian(lTreeAddress, byteRepresentation, 16);
        Pack.intToBigEndian(treeHeight, byteRepresentation, 20);
        Pack.intToBigEndian(treeIndex, byteRepresentation, 24);
        return byteRepresentation;
    }

    public int getLTreeAddress()
    {
        return lTreeAddress;
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
