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

    /**
     * The address a leaf's walk starts from, which is the OTS address word and the tree the three
     * words above it name.
     * <p>
     * The chain address and the hash address are not parameters, because nothing builds an address
     * to set them: a walk steps them through the encoding it already holds, at
     * {@link #CHAIN_ADDRESS_OFFSET} and {@link #HASH_ADDRESS_OFFSET}, rather than building an
     * address per chain and per step. Both are zero in what {@link #toByteArray()} produces, which
     * is where a walk starts from and what {@code WOTSPlus.getWOTSPlusSecretKey} puts them back to
     * before each one-time key - as is the key-and-mask word past them, for the reason given on
     * {@link XMSSAddress#XMSSAddress(int, long, int)}.
     * </p>
     *
     * @param layerAddress which layer of an XMSS^MT hypertree the leaf's tree is on; zero for
     *                     XMSS, and for the bottom layer of an XMSS^MT.
     * @param treeAddress  which tree of that layer; zero where the layer holds one.
     * @param otsAddress   which leaf of that tree.
     */
    OTSHashAddress(int layerAddress, long treeAddress, int otsAddress)
    {
        super(layerAddress, treeAddress, TYPE);
        this.otsAddress = otsAddress;
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
