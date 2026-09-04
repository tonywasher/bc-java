package org.bouncycastle.crypto.params;

import org.bouncycastle.crypto.signers.xmss.XMSSEngine;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

/**
 * The wire form an XMSS and an XMSS^MT private key share.
 * <p>
 * Neither family's private key is a standardised encoding - RFC 8391 sec. 4.1.3 and sec. 4.2.2
 * describe what a private key holds and leave how it is stored to the implementation, and NIST
 * SP 800-208 sec. 6 says only that the traversal state has to be stored with it - so this is BC's
 * own layout, and both families were written in it independently:
 * </p>
 * <pre>
 *     index || secretKeySeed || secretKeyPRF || publicSeed || root || BDS traversal state
 * </pre>
 * <p>
 * The four seed and root fields are n bytes each and the traversal state is variable length and
 * last, so only the head is fixed and only the head can be length checked. The two key classes
 * carried a line for line copy of all of that each, on both sides - the decoding constructor and
 * {@code toByteArray()} - so one layout was written out four times and had to be hand edited in
 * lockstep. This is the one copy, as {@link XMSSPublicKeyCodec} is for the public halves.
 * </p><p>
 * What actually differs between the families is one number: the width of the index field. Every
 * other difference between the four copies was incidental - the index read back as a signed int on
 * one side and as an unsigned long on the other, the length check spelled the same way twice - and
 * is gone. The width is named by {@link #XMSS_INDEX_SIZE} and {@link #mtIndexSize(int)}, which is
 * where a question about what the field can hold is asked.
 * </p><p>
 * Package private, like the public codec beside it: the classes it serves are the public surface.
 * The name starts XMSS so that the {@code crypto/params/XMSS*} excludes the jdk1.4 and jdk1.3 Ant
 * builds already carry keep covering it.
 * </p>
 */
class XMSSPrivateKeyCodec
{
    /**
     * The width of an XMSS index field, four bytes whatever the tree height.
     * <p>
     * It always suffices: {@link XMSSParameters#MAX_HEIGHT} is 30, so the largest index a key can
     * hold - 2^h, the position an exhausted key sits at, one past its last leaf - is 2^30, and
     * reads back the same whether the four bytes are taken as a signed int or an unsigned long.
     * </p>
     */
    static final int XMSS_INDEX_SIZE = 4;

    private final long index;
    private final byte[] secretKeySeed;
    private final byte[] secretKeyPRF;
    private final byte[] publicSeed;
    private final byte[] root;
    private final byte[] bdsState;

    private XMSSPrivateKeyCodec(long index, byte[] secretKeySeed, byte[] secretKeyPRF,
        byte[] publicSeed, byte[] root, byte[] bdsState)
    {
        this.index = index;
        this.secretKeySeed = secretKeySeed;
        this.secretKeyPRF = secretKeyPRF;
        this.publicSeed = publicSeed;
        this.root = root;
        this.bdsState = bdsState;
    }

    /**
     * The width of an XMSS^MT index field, the fewest whole bytes that hold a leaf index of a tree
     * of this total height.
     * <p>
     * Unlike the XMSS field this is not always wide enough for every index the key can hold: a
     * total height that is a multiple of eight leaves exactly h bits, and the exhausted position
     * 2^h needs h + 1 of them. Of the standard parameter sets that is the XMSSMT_*_40/* family,
     * whose exhausted index would need a sixth byte, and 2^40 signatures is not a number anyone
     * arrives at.
     * </p>
     *
     * @param totalHeight the height of the whole hypertree.
     */
    static int mtIndexSize(int totalHeight)
    {
        return (totalHeight + 7) / 8;
    }

    /**
     * Read a private key encoding, taking the index from a field of the given width.
     * <p>
     * Only the head is fixed - the serialized traversal state that follows it is variable length -
     * so what can be checked here is that the head is all there. It has to be checked somewhere:
     * the five reads below take their bytes at computed offsets, and nothing on the way in from
     * PrivateKeyFactory looks at the length at all.
     * </p>
     *
     * @param privateKey  the encoding.
     * @param indexSize   the width of the index field, in bytes.
     * @param totalHeight the height the index is bounded by.
     * @param n           the security parameter of the key's parameter set, in bytes.
     */
    static XMSSPrivateKeyCodec decode(byte[] privateKey, int indexSize, int totalHeight, int n)
    {
        if (privateKey.length < indexSize + 4 * n)
        {
            throw new IllegalArgumentException("private key has wrong size");
        }

        int position = 0;
        long index = Pack.bigEndianToLong_Low(privateKey, position, indexSize);
        if (!XMSSEngine.isStoredIndexValid(totalHeight, index))
        {
            throw new IllegalArgumentException("index out of bounds");
        }
        position += indexSize;
        byte[] secretKeySeed = Arrays.copyOfRange(privateKey, position, position + n);
        position += n;
        byte[] secretKeyPRF = Arrays.copyOfRange(privateKey, position, position + n);
        position += n;
        byte[] publicSeed = Arrays.copyOfRange(privateKey, position, position + n);
        position += n;
        byte[] root = Arrays.copyOfRange(privateKey, position, position + n);
        position += n;
        byte[] bdsState = Arrays.copyOfRange(privateKey, position, privateKey.length);

        return new XMSSPrivateKeyCodec(index, secretKeySeed, secretKeyPRF, publicSeed, root, bdsState);
    }

    /**
     * The encoding of a key holding these fields, with the index written in a field of the given
     * width.
     * <p>
     * The traversal state is encoded by the caller and passed in already serialized, so that it
     * can be written straight into the array that is returned: appending it afterwards meant
     * allocating the fixed part on its own and then copying both halves into a second array of the
     * full size.
     * </p>
     *
     * @param index     the position the key is at.
     * @param indexSize the width of the index field, in bytes.
     * @param bdsState  the encoded traversal state.
     */
    static byte[] encode(long index, int indexSize, byte[] secretKeySeed, byte[] secretKeyPRF,
        byte[] publicSeed, byte[] root, byte[] bdsState)
    {
        /* index || secretKeySeed || secretKeyPRF || publicSeed || root || bdsState */
        byte[] out = new byte[indexSize + secretKeySeed.length + secretKeyPRF.length
            + publicSeed.length + root.length + bdsState.length];
        int position = 0;

        /* copy index */
        Pack.longToBigEndian_Low(index, out, position, indexSize);
        position += indexSize;
        /* copy secretKeySeed */
        System.arraycopy(secretKeySeed, 0, out, position, secretKeySeed.length);
        position += secretKeySeed.length;
        /* copy secretKeyPRF */
        System.arraycopy(secretKeyPRF, 0, out, position, secretKeyPRF.length);
        position += secretKeyPRF.length;
        /* copy publicSeed */
        System.arraycopy(publicSeed, 0, out, position, publicSeed.length);
        position += publicSeed.length;
        /* copy root */
        System.arraycopy(root, 0, out, position, root.length);
        position += root.length;
        /* copy bdsState */
        System.arraycopy(bdsState, 0, out, position, bdsState.length);

        return out;
    }

    long getIndex()
    {
        return index;
    }

    byte[] getSecretKeySeed()
    {
        return secretKeySeed;
    }

    byte[] getSecretKeyPRF()
    {
        return secretKeyPRF;
    }

    byte[] getPublicSeed()
    {
        return publicSeed;
    }

    byte[] getRoot()
    {
        return root;
    }

    byte[] getBDSState()
    {
        return bdsState;
    }
}
