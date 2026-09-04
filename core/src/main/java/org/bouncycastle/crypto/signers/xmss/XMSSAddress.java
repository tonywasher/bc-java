package org.bouncycastle.crypto.signers.xmss;

import org.bouncycastle.util.Pack;

/**
 * XMSS address.
 * <p>
 * An address is built in order to be encoded, and it is the 32 bytes {@link #toByteArray()}
 * produces that this package hands around and steps - so an address answers nothing about itself
 * beyond that method, and what a walk needs back off the encoding it was handed it reads from the
 * bytes: {@link #layerAddressOf(byte[])} and {@link #treeAddressOf(byte[])} here, and
 * {@link OTSHashAddress#otsAddressOf(byte[])} for the one further word that walk names a leaf by.
 * </p>
 */
abstract class XMSSAddress
{
    /**
     * Offset of the key-and-mask word in the 32-byte encoding {@link #toByteArray()} produces.
     * Named so that a caller stepping the field through an encoding of its own - WOTSPlus.chain
     * writes it twice per chain step - says so against the one place that lays the encoding out,
     * rather than against a copy of the number.
     */
    static final int KEY_AND_MASK_OFFSET = 28;

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
        Pack.intToBigEndian(keyAndMask, byteRepresentation, KEY_AND_MASK_OFFSET);
        return byteRepresentation;
    }

    /**
     * The layer address word of a 32-byte address encoding.
     * <p>
     * RFC 8391 sec. 2.5 gives every address type the same first four words, so this and
     * {@link #treeAddressOf(byte[])} read the same two fields whichever type produced the
     * encoding. They are what a walk carrying one address as bytes needs in order to name the
     * other two addresses of the same tree - an encoding is handed on where an address used to be,
     * and these are the only fields of it read back rather than written.
     * </p>
     *
     * @param address a 32-byte address encoding.
     * @return its layer address.
     */
    static int layerAddressOf(byte[] address)
    {
        return Pack.bigEndianToInt(address, 0);
    }

    /**
     * The tree address of a 32-byte address encoding; see {@link #layerAddressOf(byte[])}.
     *
     * @param address a 32-byte address encoding.
     * @return its tree address.
     */
    static long treeAddressOf(byte[] address)
    {
        return Pack.bigEndianToLong(address, 4);
    }
}
