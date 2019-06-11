package org.bouncycastle.crypto.digests;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Memoable;
import org.bouncycastle.util.Pack;

/**
 * Blake2s digest.
 */
public class Blake2s
        extends Blake2 {
    /**
     * Number of Rounds.
     */
    private static final int ROUNDS = 10;

    /**
     * Block length.
     */
    private static final int BLOCK_LENGTH_BYTES = NUMWORDS * Integer.BYTES << 1;

    /**
     * Blake2b Initialization Vector.
     */
    private static final int[] IV =
            // Produced from the square root of primes 2, 3, 5, 7, 11, 13, 17, 19.
            // The same as SHA-256 IV.
            {
                    0x6a09e667, 0xbb67ae85, 0x3c6ef372,
                    0xa54ff53a, 0x510e527f, 0x9b05688c,
                    0x1f83d9ab, 0x5be0cd19
            };

    /**
     * The state.
     */
    private int[] theH = new int[NUMWORDS];

    /**
     * The workBuffer.
     */
    private int[] theV = new int[NUMWORDS << 1];

    /**
     * The messageBuffer.
     */
    private int[] theM = new int[NUMWORDS << 1];

    /**
     * Low Counter.
     */
    private int t0;

    /**
     * High Counter.
     */
    private int t1;

    /**
     * Constructor.
     * @param pLength the digest length in bits.
     */
    public Blake2s(final int pLength) {
        /* Initialise underlying class */
        super(ROUNDS, BLOCK_LENGTH_BYTES);

        /* Check digest length */
        if ((pLength % Byte.SIZE) != 0 || pLength < 0 || pLength > 256) {
            throw new IllegalArgumentException("Incorrect digest length");
        }
        setDigestLength(pLength / Byte.SIZE);
    }

    /**
     * Constructor.
     * @param pSource the source digest.
     */
    private Blake2s(final Blake2s pSource) {
        /* Initialise underlying class */
        super(pSource);

        /* Initialise from source */
        reset((Memoable) pSource);
    }

    @Override
    public String getAlgorithmName() {
        return "Blake2s-" + getDigestSize() * Byte.SIZE;
    }

    @Override
    public int getByteLength() {
        return BLOCK_LENGTH_BYTES;
    }

    @Override
    public void reset() {
        /* reset underlying class */
        super.reset();

        /* Reset counter */
        t0 = 0;
        t1 = 0;
    }

    @Override
    public void reset(final Memoable pSource) {
        /* Access source */
        final Blake2s mySource = (Blake2s) pSource;

        /* reset underlying class */
        super.reset(mySource);

        /* Reset counter */
        t0 = mySource.t0;
        t1 = mySource.t1;

        /* Copy state */
        System.arraycopy(mySource.theH, 0, theH, 0, theH.length);
    }

    @Override
    public Blake2s copy() {
        return new Blake2s(this);
    }

    @Override
    void adjustCounter(int pCount) {
        t0 += pCount;
        if (t0 == 0) {
            t1++;
        }
    }

    @Override
    void completeCounter(int pCount) {
        t0 += pCount;
        if (pCount > 0 && t0 == 0) {
            t1++;
        }
    }

    @Override
    void outputDigest(final byte[] pOut,
                      final int pOutOffset) {
        /* Loop to provide the output */
        final int myDigestLen = getDigestSize();
        for (int i = 0, j = 0; i < NUMWORDS && j < myDigestLen; i++, j += Integer.BYTES) {
            /* Convert the next word to bytes */
            final byte[] bytes = Pack.intToLittleEndian(theH[i]);

            if (j + Integer.BYTES < myDigestLen) {
                System.arraycopy(bytes, 0, pOut, pOutOffset + j, Integer.BYTES);
            } else {
                System.arraycopy(bytes, 0, pOut, pOutOffset + j, myDigestLen - j);
            }
        }
    }

    @Override
    protected void activateH() {
        /* Initialise from IV */
        System.arraycopy(IV, 0, theH, 0, IV.length);

        /* Initialise first word */
        theH[0] ^= getDigestSize() | (getKeyLen() << Byte.SIZE);
        theH[0] ^= (getFanOut() | (getMaxDepth() << Byte.SIZE)) << Short.SIZE;

        /* Initialise seomd word */
        theH[1] ^= getLeafLen();

        /* Initialise third word */
        theH[2] ^= getNodeOffset();

        /* Initialise fourth word */
        theH[3] ^= getXofLen();
        theH[3] ^= (getNodeDepth() | (getInnerLen() << Byte.SIZE)) << Short.SIZE;

        /* Build salt section */
        final byte[] mySalt = getSalt();
        if (mySalt != null) {
            theH[4] ^= Pack.littleEndianToInt(mySalt, 0);
            theH[5] ^= Pack.littleEndianToInt(mySalt, Integer.BYTES);
        }

        /* Build personalisation section */
        final byte[] myPersonal = getPersonal();
        if (myPersonal != null) {
            theH[6] ^= Pack.littleEndianToInt(myPersonal, 0);
            theH[7] ^= Pack.littleEndianToInt(myPersonal, Integer.BYTES);
        }

        /* Initialise any keyBlock */
        initKeyBlock();
    }

    @Override
    protected void initV() {
        /* Copy in H and IV */
        System.arraycopy(theH, 0, theV, 0, NUMWORDS);
        System.arraycopy(IV, 0, theV, NUMWORDS, NUMWORDS);

        /* Fold in counters */
        theV[12] ^= t0;
        theV[13] ^= t1;

        /* Fold in finalisation flags */
        if (isLastBlock()) {
            theV[14] ^= -1;
            if (isLastNode()) {
                theV[15] ^= -1;
            }
        }
    }

    @Override
    protected void initM(final byte[] pMessage,
                         final int pMsgPos) {
        /* Copy message bytes into word array */
        for (int i = 0; i < NUMWORDS << 1; i++) {
            theM[i] = Pack.littleEndianToInt(pMessage, pMsgPos + i * Integer.BYTES);
        }
    }

    @Override
    protected void adjustH() {
        /* Combine V into H */
        for (int i = 0; i < NUMWORDS; i++) {
            theH[i] ^= theV[i] ^ theV[i + NUMWORDS];
        }
    }

    @Override
    protected void mixG(final int msgIdx1,
                        final int msgIdx2,
                        final int posA,
                        final int posB,
                        final int posC,
                        final int posD) {
        /* Perform the Round */
        theV[posA] += theV[posB] + theM[msgIdx1];
        theV[posD] = rotr32(theV[posD] ^ theV[posA], 16);
        theV[posC] += theV[posD];
        theV[posB] = rotr32(theV[posB] ^ theV[posC], 12);
        theV[posA] += theV[posB] + theM[msgIdx2];
        theV[posD] = rotr32(theV[posD] ^ theV[posA], 8);
        theV[posC] += theV[posD];
        theV[posB] = rotr32(theV[posB] ^ theV[posC], 7);
    }

    /**
     * Rotate an int right.
     * @param x the value to rotate
     * @param rot the number of bits to rotate
     * @return the result
     */
    private static int rotr32(final int x,
                              final int rot) {
        return x >>> rot | (x << (Integer.SIZE - rot));
    }
}
