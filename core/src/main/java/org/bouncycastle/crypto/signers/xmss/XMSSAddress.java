package org.bouncycastle.crypto.signers.xmss;

import org.bouncycastle.util.Pack;

/**
 * XMSS address.
 * <p>
 * An address is built in order to be encoded, and it is the 32 bytes {@link #toByteArray()}
 * produces that this package hands around and steps - so an address answers nothing about itself
 * beyond that method, and a walk holding one encoding names the other addresses of the same tree
 * out of the bytes rather than out of an address: {@link #subtreeAddressOf(byte[], int)} here, and
 * {@link OTSHashAddress#otsAddressOf(byte[])} for the one further word that names a leaf within it.
 * </p>
 */
abstract class XMSSAddress
{
    /**
     * Offset of the type word in the 32-byte encoding {@link #toByteArray()} produces, and so also
     * the length of what comes before it. RFC 8391 sec. 2.5 gives every address type the same
     * first three words - the layer address, and the two of the tree address - so those twelve
     * bytes say which tree an address is in, and the word after them says what the three below it
     * are going to mean.
     */
    static final int TYPE_OFFSET = 12;

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
        Pack.intToBigEndian(type, byteRepresentation, TYPE_OFFSET);
        Pack.intToBigEndian(keyAndMask, byteRepresentation, KEY_AND_MASK_OFFSET);
        return byteRepresentation;
    }

    /**
     * The encoding of the address of the given type in the same tree as the given encoding: the
     * twelve bytes before the type word copied across, that word set, and everything after it left
     * at zero. This is copy_subtree_addr followed by set_type of RFC 8391 sec. 2.5, and it is how a
     * walk carrying one address as bytes names the other two addresses of that tree - the L-tree
     * address of a leaf and the hash tree address of the climb over it - without taking the tree
     * apart into fields in order to build them back up.
     * <p>
     * Where the copy stops is the point of it. The three words below the type word mean something
     * different per type, and in the OTS hash address a walk hands in they are live - the OTS
     * address naming the leaf, and the chain and hash addresses the last chain of that leaf left
     * behind, with its key-and-mask in the last word of all. None of that may reach a sibling
     * address. Taking four bytes more than this does, so that the OTS address word carries into
     * the padding word a hash tree address keeps there, is caught by the compatibility oracle at
     * the ninth leaf of a tree.
     * </p>
     *
     * @param address a 32-byte address encoding.
     * @param type    the type word wanted, named by the class that lays out the three words below
     *                it.
     * @return a fresh 32-byte encoding of that address.
     */
    static byte[] subtreeAddressOf(byte[] address, int type)
    {
        byte[] subtreeAddress = new byte[32];
        System.arraycopy(address, 0, subtreeAddress, 0, TYPE_OFFSET);
        Pack.intToBigEndian(type, subtreeAddress, TYPE_OFFSET);
        return subtreeAddress;
    }
}
