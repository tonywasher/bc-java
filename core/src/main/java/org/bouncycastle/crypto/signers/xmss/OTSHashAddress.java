package org.bouncycastle.crypto.signers.xmss;

import org.bouncycastle.util.Pack;

/**
 * OTS hash address.
 * <p>
 * As with the other two address types, what this is for is producing the encoding a walk then
 * carries; see {@link XMSSAddress}.
 * </p>
 */
final class OTSHashAddress
    extends XMSSAddress
{

    /**
     * Offset of the OTS address word in the 32-byte encoding {@link #toByteArray()} produces.
     * The one-time keys of a tree differ in this word alone, so the leaf walks in {@link BDS} and
     * {@link BDSTreeHash} step it through one encoding rather than rebuilding an address per leaf.
     */
    static final int OTS_ADDRESS_OFFSET = 16;

    /**
     * Offset of the chain address word in the 32-byte encoding {@link #toByteArray()} produces.
     * The len chains of a WOTS+ key differ in this word alone, so the three loops that walk them
     * step it through one encoding rather than rebuilding an address per chain.
     */
    static final int CHAIN_ADDRESS_OFFSET = 20;

    /**
     * Offset of the hash address word in the 32-byte encoding {@link #toByteArray()} produces.
     * See {@link XMSSAddress#KEY_AND_MASK_OFFSET}: these are the two words a WOTS+ chain step
     * moves, and chain() writes them into the encoding its caller stepped rather than rebuilding
     * one.
     */
    static final int HASH_ADDRESS_OFFSET = 24;

    private static final int TYPE = 0x00;

    private final int otsAddress;

    private OTSHashAddress(Builder builder)
    {
        super(builder);
        otsAddress = builder.otsAddress;
    }

    /**
     * Builds the address a leaf's walk starts from, which is the OTS address word and the tree
     * the three words above it name.
     * <p>
     * The chain address and the hash address are not set here, because nothing sets them here: a
     * walk steps them through the encoding it already holds, at {@link #CHAIN_ADDRESS_OFFSET} and
     * {@link #HASH_ADDRESS_OFFSET}, rather than building an address per chain and per step. Both
     * are zero in what {@link #toByteArray()} produces, which is where a walk starts from and what
     * {@code WOTSPlus.getWOTSPlusSecretKey} puts them back to before each one-time key. Setters
     * for the two were kept when the walks stopped using them and were left with no caller outside
     * this package's own address test, which now writes the words the way the walks do.
     * </p>
     */
    public static class Builder
        extends XMSSAddress.Builder<Builder>
    {

        /* optional */
        private int otsAddress = 0;

        public Builder()
        {
            super(TYPE);
        }

        public Builder withOTSAddress(int val)
        {
            otsAddress = val;
            return this;
        }

        public XMSSAddress build()
        {
            return new OTSHashAddress(this);
        }

        public Builder getThis()
        {
            return this;
        }
    }

    public byte[] toByteArray()
    {
        byte[] byteRepresentation = super.toByteArray();
        Pack.intToBigEndian(otsAddress, byteRepresentation, OTS_ADDRESS_OFFSET);
        return byteRepresentation;
    }

    /**
     * The OTS address word of an OTS hash address encoding, for the verification walk that names
     * a leaf by it twice over - as the L-tree address of the leaf, and as where its climb through
     * the tree starts.
     *
     * @param address the 32-byte encoding of an OTS hash address.
     * @return its OTS address.
     */
    static int otsAddressOf(byte[] address)
    {
        return Pack.bigEndianToInt(address, OTS_ADDRESS_OFFSET);
    }
}
