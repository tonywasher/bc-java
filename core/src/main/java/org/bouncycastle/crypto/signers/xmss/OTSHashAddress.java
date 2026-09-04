package org.bouncycastle.crypto.signers.xmss;

import org.bouncycastle.util.Pack;

/**
 * OTS hash address.
 */
final class OTSHashAddress
    extends XMSSAddress
{

    /**
     * Offset of the hash address word in the 32-byte encoding {@link #toByteArray()} produces.
     * See {@link XMSSAddress#KEY_AND_MASK_OFFSET}: these are the two words a WOTS+ chain step
     * moves, and chain() writes them into an encoding it holds rather than rebuilding one.
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
        Pack.intToBigEndian(otsAddress, byteRepresentation,16);
        Pack.intToBigEndian(chainAddress, byteRepresentation, 20);
        Pack.intToBigEndian(hashAddress, byteRepresentation, HASH_ADDRESS_OFFSET);
        return byteRepresentation;
    }

    public int getOTSAddress()
    {
        return otsAddress;
    }

    public int getChainAddress()
    {
        return chainAddress;
    }

    public int getHashAddress()
    {
        return hashAddress;
    }
}
