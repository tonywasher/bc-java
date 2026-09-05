package org.bouncycastle.crypto.signers.xmss;

import junit.framework.TestCase;
import org.bouncycastle.util.Pack;

/**
 * The RFC 8391 sec. 2.5 hash-address word layout. The address is the domain separation between
 * every hash call XMSS makes, so its byte layout is as much a part of the wire format as the
 * signature encoding is - but it is package-private, so nothing outside this package can assert
 * on it.
 */
public class AddressTests
    extends TestCase
{
    private static final int LAYER = 0;
    private static final int TREE = 4;
    private static final int TYPE = 12;
    private static final int WORD_4 = 16;
    private static final int WORD_5 = 20;
    private static final int WORD_6 = 24;
    private static final int KEY_AND_MASK = 28;

    /**
     * An OTS hash address with every word of it set to something distinguishable. It is the one
     * address type this package still builds, and the two below are derived from it the way a walk
     * derives them, so what does and does not carry across is visible.
     */
    private static byte[] otsHashAddress()
    {
        byte[] enc = new OTSHashAddress.Builder()
            .withOTSAddress(0x11223344)
            .withLayerAddress(7)
            .withTreeAddress(0x0102030405060708L)
            .withKeyAndMask(2)
            .build().toByteArray();

        // the chain address and the hash address are not builder fields: a walk steps them through
        // the encoding it holds, WOTSPlus.chain writing both once per chain step, so they are
        // written here the way the walk writes them. They have to hold something for the two tests
        // below to say anything - what those turn on is that neither carries past the twelve bytes
        // subtreeAddressOf copies - and writing them through the offset constants is also what
        // asserts the constants name words 5 and 6, which is the layout production depends on.
        Pack.intToBigEndian(0x55667788, enc, OTSHashAddress.CHAIN_ADDRESS_OFFSET);
        Pack.intToBigEndian(0x99aabbcc, enc, OTSHashAddress.HASH_ADDRESS_OFFSET);

        return enc;
    }

    public void testOTSHashAddressLayout()
    {
        byte[] enc = otsHashAddress();

        assertEquals(32, enc.length);
        assertEquals(7, Pack.bigEndianToInt(enc, LAYER));
        assertEquals(0x0102030405060708L, Pack.bigEndianToLong(enc, TREE));
        assertEquals(0x00, Pack.bigEndianToInt(enc, TYPE));
        assertEquals(0x11223344, Pack.bigEndianToInt(enc, WORD_4));
        assertEquals(0x55667788, Pack.bigEndianToInt(enc, WORD_5));
        assertEquals(0x99aabbcc, Pack.bigEndianToInt(enc, WORD_6));
        assertEquals(2, Pack.bigEndianToInt(enc, KEY_AND_MASK));
    }

    /**
     * An L-tree address is produced from the OTS hash address of the leaf it belongs to, and the
     * twelve bytes naming the tree are the whole of what comes across - RFC 8391 sec. 2.5's
     * copy_subtree_addr, which stops before the type word. The three words below that word mean
     * something else per type and belong to the walk, which writes its own into them; the last
     * word of all is the key-and-mask and is not the caller's to carry either.
     */
    public void testLTreeAddressLayout()
    {
        byte[] enc = XMSSAddress.subtreeAddressOf(otsHashAddress(), LTreeAddress.TYPE);

        assertEquals(32, enc.length);
        assertEquals(7, Pack.bigEndianToInt(enc, LAYER));
        assertEquals(0x0102030405060708L, Pack.bigEndianToLong(enc, TREE));
        assertEquals(0x01, Pack.bigEndianToInt(enc, TYPE));
        assertEquals(0, Pack.bigEndianToInt(enc, WORD_4));
        assertEquals(0, Pack.bigEndianToInt(enc, WORD_5));
        assertEquals(0, Pack.bigEndianToInt(enc, WORD_6));
        assertEquals(0, Pack.bigEndianToInt(enc, KEY_AND_MASK));

        Pack.intToBigEndian(0x11223344, enc, LTreeAddress.LTREE_ADDRESS_OFFSET);
        Pack.intToBigEndian(0x55667788, enc, LTreeAddress.TREE_HEIGHT_OFFSET);
        Pack.intToBigEndian(0x99aabbcc, enc, LTreeAddress.TREE_INDEX_OFFSET);

        assertEquals(0x11223344, Pack.bigEndianToInt(enc, WORD_4));
        assertEquals(0x55667788, Pack.bigEndianToInt(enc, WORD_5));
        assertEquals(0x99aabbcc, Pack.bigEndianToInt(enc, WORD_6));
    }

    /**
     * The same for the hash tree address, whose word 4 is a reserved padding word rather than an
     * index - so it is left where the copy leaves it, and nothing writes it.
     */
    public void testHashTreeAddressLayout()
    {
        byte[] enc = XMSSAddress.subtreeAddressOf(otsHashAddress(), HashTreeAddress.TYPE);

        assertEquals(32, enc.length);
        assertEquals(7, Pack.bigEndianToInt(enc, LAYER));
        assertEquals(0x0102030405060708L, Pack.bigEndianToLong(enc, TREE));
        assertEquals(0x02, Pack.bigEndianToInt(enc, TYPE));
        assertEquals(0, Pack.bigEndianToInt(enc, WORD_4));
        assertEquals(0, Pack.bigEndianToInt(enc, WORD_5));
        assertEquals(0, Pack.bigEndianToInt(enc, WORD_6));
        assertEquals(0, Pack.bigEndianToInt(enc, KEY_AND_MASK));

        Pack.intToBigEndian(0x55667788, enc, HashTreeAddress.TREE_HEIGHT_OFFSET);
        Pack.intToBigEndian(0x99aabbcc, enc, HashTreeAddress.TREE_INDEX_OFFSET);

        assertEquals(0, Pack.bigEndianToInt(enc, WORD_4));
        assertEquals(0x55667788, Pack.bigEndianToInt(enc, WORD_5));
        assertEquals(0x99aabbcc, Pack.bigEndianToInt(enc, WORD_6));
    }

    /**
     * The three address types differ only in their type word and the meaning of words 4 to 6, so a
     * type confusion would not show up as a length or a parse failure - only as a hash computed
     * over the wrong domain. Assert the three are distinct for the same leaf of the same tree: the
     * OTS hash address and the L-tree address below name that leaf in the same word, so between
     * those two it is the type word alone that separates them.
     */
    public void testAddressTypesAreDistinct()
    {
        byte[] ots = new OTSHashAddress.Builder().withOTSAddress(1).build().toByteArray();

        byte[] lTree = XMSSAddress.subtreeAddressOf(ots, LTreeAddress.TYPE);
        Pack.intToBigEndian(1, lTree, LTreeAddress.LTREE_ADDRESS_OFFSET);

        byte[] hashTree = XMSSAddress.subtreeAddressOf(ots, HashTreeAddress.TYPE);
        Pack.intToBigEndian(1, hashTree, HashTreeAddress.TREE_INDEX_OFFSET);

        assertFalse(org.bouncycastle.util.Arrays.areEqual(ots, lTree));
        assertFalse(org.bouncycastle.util.Arrays.areEqual(ots, hashTree));
        assertFalse(org.bouncycastle.util.Arrays.areEqual(lTree, hashTree));
    }
}
