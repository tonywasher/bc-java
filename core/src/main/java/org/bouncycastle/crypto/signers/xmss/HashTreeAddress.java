package org.bouncycastle.crypto.signers.xmss;

/**
 * The words of a hash tree address, RFC 8391 sec. 2.5.
 * <p>
 * Nothing builds one either; this is the other half of {@link LTreeAddress}, and the same applies.
 * A hash tree address is the 32 bytes the climb above the leaves carries, and what is here is
 * where its words sit.
 * </p>
 */
final class HashTreeAddress
{

    /**
     * The type word of a hash tree address, named for {@link XMSSAddress#subtreeAddressOf(byte[],
     * int)} to stamp on an encoding it takes the tree of from an address of another type. The
     * padding word this type puts where the other two put an index needs no naming at all: it is
     * zero, which is what that method leaves everything past the type word at, and no walk writes
     * it afterwards.
     */
    static final int TYPE = 0x02;

    /**
     * Offsets of the tree height and tree index words in the 32-byte encoding. These are the two
     * words a walk of the tree above the leaves moves as it climbs - BDS, BDSTreeHash and
     * XMSSVerifierUtil - so each of them steps one encoding rather than producing one per node.
     * {@link LTreeAddress} lays the same two fields out at the same two words and names them for
     * itself.
     */
    static final int TREE_HEIGHT_OFFSET = 20;
    static final int TREE_INDEX_OFFSET = 24;
}
