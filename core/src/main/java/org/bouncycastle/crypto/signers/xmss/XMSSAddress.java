package org.bouncycastle.crypto.signers.xmss;

import org.bouncycastle.util.Pack;

/**
 * XMSS address.
 */
public abstract class XMSSAddress
{

    private final int layerAddress;
    private final long treeAddress;
    private final int type;
    private final int keyAndMask;

    public XMSSAddress(Builder builder)
    {
        layerAddress = builder.layerAddress;
        treeAddress = builder.treeAddress;
        type = builder.type;
        keyAndMask = builder.keyAndMask;
    }

    public static abstract class Builder<T extends Builder>
    {

        /* mandatory */
        private final int type;
        /* optional */
        private int layerAddress = 0;
        private long treeAddress = 0L;
        private int keyAndMask = 0;

        public Builder(int type)
        {
            super();
            this.type = type;
        }

        public T withLayerAddress(int val)
        {
            layerAddress = val;
            return getThis();
        }

        public T withTreeAddress(long val)
        {
            treeAddress = val;
            return getThis();
        }

        public T withKeyAndMask(int val)
        {
            keyAndMask = val;
            return getThis();
        }

        public abstract XMSSAddress build();

        public abstract T getThis();
    }

    public byte[] toByteArray()
    {
        byte[] byteRepresentation = new byte[32];
        Pack.intToBigEndian(layerAddress, byteRepresentation, 0);
        Pack.longToBigEndian(treeAddress, byteRepresentation, 4);
        Pack.intToBigEndian(type, byteRepresentation, 12);
        Pack.intToBigEndian(keyAndMask, byteRepresentation, 28);
        return byteRepresentation;
    }

    public final int getLayerAddress()
    {
        return layerAddress;
    }

    public final long getTreeAddress()
    {
        return treeAddress;
    }

    public final int getType()
    {
        return type;
    }

    public final int getKeyAndMask()
    {
        return keyAndMask;
    }
}
