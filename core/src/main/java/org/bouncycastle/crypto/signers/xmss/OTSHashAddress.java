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
    private final int chainAddress;
    private final int hashAddress;

    private OTSHashAddress(Builder builder)
    {
        super(builder);
        otsAddress = builder.otsAddress;
        chainAddress = builder.chainAddress;
        hashAddress = builder.hashAddress;
    }

    public static class Builder
        extends XMSSAddress.Builder<Builder>
    {

        /* optional */
        private int otsAddress = 0;
        private int chainAddress = 0;
        private int hashAddress = 0;

        public Builder()
        {
            super(TYPE);
        }

        public Builder withOTSAddress(int val)
        {
            otsAddress = val;
            return this;
        }

        public Builder withChainAddress(int val)
        {
            chainAddress = val;
            return this;
        }

        public Builder withHashAddress(int val)
        {
            hashAddress = val;
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
        Pack.intToBigEndian(chainAddress, byteRepresentation, CHAIN_ADDRESS_OFFSET);
        Pack.intToBigEndian(hashAddress, byteRepresentation, HASH_ADDRESS_OFFSET);
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
