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

    public void testOTSHashAddressLayout()
    {
        OTSHashAddress address = (OTSHashAddress)new OTSHashAddress.Builder()
            .withOTSAddress(0x11223344)
            .withChainAddress(0x55667788)
            .withHashAddress(0x99aabbcc)
            .withLayerAddress(7)
            .withTreeAddress(0x0102030405060708L)
            .withKeyAndMask(2)
            .build();

        byte[] enc = address.toByteArray();

        assertEquals(32, enc.length);
        assertEquals(7, Pack.bigEndianToInt(enc, LAYER));
        assertEquals(0x0102030405060708L, Pack.bigEndianToLong(enc, TREE));
        assertEquals(0x00, Pack.bigEndianToInt(enc, TYPE));
        assertEquals(0x11223344, Pack.bigEndianToInt(enc, WORD_4));
        assertEquals(0x55667788, Pack.bigEndianToInt(enc, WORD_5));
        assertEquals(0x99aabbcc, Pack.bigEndianToInt(enc, WORD_6));
        assertEquals(2, Pack.bigEndianToInt(enc, KEY_AND_MASK));
    }

    public void testLTreeAddressLayout()
    {
        LTreeAddress address = (LTreeAddress)new LTreeAddress.Builder()
            .withLTreeAddress(0x11223344)
            .withTreeHeight(0x55667788)
            .withTreeIndex(0x99aabbcc)
            .build();

        byte[] enc = address.toByteArray();

        assertEquals(0x01, Pack.bigEndianToInt(enc, TYPE));
        assertEquals(0x11223344, Pack.bigEndianToInt(enc, WORD_4));
        assertEquals(0x55667788, Pack.bigEndianToInt(enc, WORD_5));
        assertEquals(0x99aabbcc, Pack.bigEndianToInt(enc, WORD_6));
    }

    public void testHashTreeAddressLayout()
    {
        HashTreeAddress address = (HashTreeAddress)new HashTreeAddress.Builder()
            .withTreeHeight(0x55667788)
            .withTreeIndex(0x99aabbcc)
            .build();

        byte[] enc = address.toByteArray();

        assertEquals(0x02, Pack.bigEndianToInt(enc, TYPE));
        // word 4 is the reserved padding word of a hash-tree address and stays zero
        assertEquals(0, Pack.bigEndianToInt(enc, WORD_4));
        assertEquals(0x55667788, Pack.bigEndianToInt(enc, WORD_5));
        assertEquals(0x99aabbcc, Pack.bigEndianToInt(enc, WORD_6));
    }

    /**
     * The three address types differ only in their type word and the meaning of words 4 to 6, so a
     * type confusion would not show up as a length or a parse failure - only as a hash computed
     * over the wrong domain. Assert the three are distinct for the same word values.
     */
    public void testAddressTypesAreDistinct()
    {
        byte[] ots = ((OTSHashAddress)new OTSHashAddress.Builder().withOTSAddress(1).build()).toByteArray();
        byte[] lTree = ((LTreeAddress)new LTreeAddress.Builder().withLTreeAddress(1).build()).toByteArray();
        byte[] hashTree = ((HashTreeAddress)new HashTreeAddress.Builder().withTreeHeight(1).build()).toByteArray();

        assertFalse(org.bouncycastle.util.Arrays.areEqual(ots, lTree));
        assertFalse(org.bouncycastle.util.Arrays.areEqual(ots, hashTree));
        assertFalse(org.bouncycastle.util.Arrays.areEqual(lTree, hashTree));
    }
}
