package org.bouncycastle.crypto.digests;

import org.bouncycastle.util.Memoable;
import org.bouncycastle.util.Pack;

/**
 * Blake2b digest.
 */
public class Blake2b
        extends Blake2 {
    /**
     * Number of Rounds.
     */
    private static final int ROUNDS = 12;

    /**
     * Block length.
     */
    private static final int BLOCK_LENGTH_BYTES = NUMWORDS * Long.BYTES << 1;

    /**
     * Blake2b Initialization Vector.
     */
    private static final long[] IV =
            // Produced from the square root of primes 2, 3, 5, 7, 11, 13, 17, 19.
            // The same as SHA-512 IV.
            {
                    0x6a09e667f3bcc908L, 0xbb67ae8584caa73bL, 0x3c6ef372fe94f82bL,
                    0xa54ff53a5f1d36f1L, 0x510e527fade682d1L, 0x9b05688c2b3e6c1fL,
                    0x1f83d9abfb41bd6bL, 0x5be0cd19137e2179L
            };

    /**
     * The state.
     */
    private long[] theH = new long[NUMWORDS];

    /**
     * The workBuffer.
     */
    private long[] theV = new long[NUMWORDS << 1];

    /**
     * The messageBuffer.
     */
    private long[] theM = new long[NUMWORDS << 1];

    /**
     * Low Counter.
     */
    private long t0;

    /**
     * High Counter.
     */
    private long t1;

    /**
     * Constructor.
     * @param pLength the digest length in bits.
     */
    public Blake2b(final int pLength) {
        /* Initialise underlying class */
        super(ROUNDS, BLOCK_LENGTH_BYTES);

        /* Check digest length */
        if ((pLength % Byte.SIZE) != 0 || pLength < 0 || pLength > 512) {
            throw new IllegalArgumentException("Incorrect digest length");
        }
        setDigestLength(pLength / Byte.SIZE);
    }

    /**
     * Constructor.
     * @param pSource the source digest.
     */
    private Blake2b(final Blake2b pSource) {
        /* Initialise underlying class */
        super(pSource);

        /* Initialise from source */
        reset((Memoable) pSource);
    }

    @Override
    public String getAlgorithmName() {
        return "Blake2b-" + getDigestSize() * Byte.SIZE;
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
        t0 = 0L;
        t1 = 0L;
    }

    @Override
    public void reset(final Memoable pSource) {
        /* Access source */
        final Blake2b mySource = (Blake2b) pSource;

        /* reset underlying class */
        super.reset(mySource);

        /* Reset counter */
        t0 = mySource.t0;
        t1 = mySource.t1;

        /* Copy state */
        System.arraycopy(mySource.theH, 0, theH, 0, theH.length);
    }

    @Override
    public Blake2b copy() {
        return new Blake2b(this);
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
        for (int i = 0, j = 0; i < NUMWORDS && j < myDigestLen; i++, j += Long.BYTES) {
            /* Convert the next word to bytes */
            final byte[] bytes = Pack.longToLittleEndian(theH[i]);

            if (j + Long.BYTES < myDigestLen) {
                System.arraycopy(bytes, 0, pOut, pOutOffset + j, Long.BYTES);
            } else {
                System.arraycopy(bytes, 0, pOut, pOutOffset + j, myDigestLen - j);
            }
        }
    }

    @Override
    void activateH() {
        /* Initialise from IV */
        System.arraycopy(IV, 0, theH, 0, IV.length);

        /* Initialise first word */
        theH[0] ^= getDigestSize() | (getKeyLen() << Byte.SIZE);
        theH[0] ^= (getFanOut() | (getMaxDepth() << Byte.SIZE)) << Short.SIZE;
        theH[0] ^= ((long) getLeafLen()) << Integer.SIZE;

        /* Initialise second word */
        theH[1] ^= getNodeOffset() | (((long) getXofLen()) << Integer.SIZE);

        /* Initialise third word */
        theH[2] ^= (getNodeDepth() | (getInnerLen() << Byte.SIZE));

        /* Build salt section */
        final byte[] mySalt = getSalt();
        if (mySalt != null) {
            theH[4] ^= Pack.littleEndianToLong(mySalt, 0);
            theH[5] ^= Pack.littleEndianToLong(mySalt, Long.BYTES);
        }

        /* Build personalisation section */
        final byte[] myPersonal = getPersonal();
        if (myPersonal != null) {
            theH[6] ^= Pack.littleEndianToLong(myPersonal, 0);
            theH[7] ^= Pack.littleEndianToLong(myPersonal, Long.BYTES);
        }

        /* Initialise any keyBlock */
        initKeyBlock();
    }

    @Override
    void initV() {
        /* Copy in H and IV */
        System.arraycopy(theH, 0, theV, 0, NUMWORDS);
        System.arraycopy(IV, 0, theV, NUMWORDS, NUMWORDS);

        /* Fold in counters */
        theV[12] ^= t0;
        theV[13] ^= t1;

        /* Fold in finalisation flags */
        if (isLastBlock()) {
            theV[14] ^= -1L;
            if (isLastNode()) {
                theV[15] ^= -1L;
            }
        }
    }

    @Override
    void initM(final byte[] pMessage,
               final int pMsgPos) {
        /* Copy message bytes into word array */
        for (int i = 0; i < NUMWORDS << 1; i++) {
            theM[i] = Pack.littleEndianToLong(pMessage, pMsgPos + i * Long.BYTES);
        }
    }

    @Override
    void adjustH() {
        /* Combine V into H */
        for (int i = 0; i < NUMWORDS; i++) {
            theH[i] ^= theV[i] ^ theV[i + NUMWORDS];
        }
    }

    @Override
    void mixG(final int msgIdx1,
              final int msgIdx2,
              final int posA,
              final int posB,
              final int posC,
              final int posD) {
        /* Perform the Round */
        theV[posA] += theV[posB] + theM[msgIdx1];
        theV[posD] = rotr64(theV[posD] ^ theV[posA], 32);
        theV[posC] += theV[posD];
        theV[posB] = rotr64(theV[posB] ^ theV[posC], 24);
        theV[posA] += theV[posB] + theM[msgIdx2];
        theV[posD] = rotr64(theV[posD] ^ theV[posA], 16);
        theV[posC] += theV[posD];
        theV[posB] = rotr64(theV[posB] ^ theV[posC], 63);
    }

    /**
     * Rotate a long right.
     * @param x the value to rotate
     * @param rot the number of bits to rotate
     * @return the result
     */
    private static long rotr64(final long x,
                               final int rot) {
        return x >>> rot | (x << (Long.SIZE - rot));
    }
}
