package org.bouncycastle.crypto.digests;

import java.util.Arrays;

import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.util.Memoable;

/**
 * CubeHash Digest.
 */
public class CubeHashDigest
        implements ExtendedDigest, Memoable {
    /**
     * The State length.
     */
    private static final int STATELEN = 32;

    /**
     * The Swap length.
     */
    private static final int SWAPLEN = STATELEN / 2;

    /**
     * The state.
     */
    private final int[] theState = new int[STATELEN];

    /**
     * The swap buffer.
     */
    private final int[] theSwap = new int[SWAPLEN];

    /**
     * The initial state.
     */
    private final int[] theInitState;

    /**
     * The block length.
     */
    private final int theBlockLen;

    /**
     * The hash length.
     */
    private final int theHashLen;

    /**
     * The number of final rounds.
     */
    private final int theNumRounds;

    /**
     * The number of final rounds.
     */
    private final int theNumFinalRounds;

    /**
     * The input buffer.
     */
    private final byte[] theInputBuffer;

    /**
     * The current byte index into input buffer.
     */
    private int theByteIndex;

    /**
     * Constructor.
     * @param pHashLen the hash lengyh
     */
    public CubeHashDigest(final int pHashLen) {
        this(pHashLen, 32, 16, 16, 32);
    }

    /**
     * Constructor.
     * @param pSource the source digest
     */
    private CubeHashDigest(final CubeHashDigest pSource) {
        /* Store configuration */
        theHashLen = pSource.theHashLen;
        theBlockLen = pSource.theBlockLen;
        theNumRounds = pSource.theNumRounds;
        theNumFinalRounds = pSource.theNumFinalRounds;

        /* Create the input buffer */
        theInputBuffer = new byte[theBlockLen];

        /* Copy the state */
        System.arraycopy(pSource.theState, 0, theState, 0, theState.length);
        System.arraycopy(pSource.theInputBuffer, 0, theInputBuffer, 0, theBlockLen);
        theByteIndex = pSource.theByteIndex;
        theInitState = Arrays.copyOf(pSource.theInitState, theState.length);
    }

    /**
     * Constructor.
     * @param pHashLen the hashLen in bits
     * @param pBlockLen the blockLen in bytes
     * @param pNumRounds the number of rounds per block
     * @param pInitRounds the number of initial rounds
     * @param pFinalRounds the number of final rounds;
     */
    private CubeHashDigest(final int pHashLen,
                           final int pBlockLen,
                           final int pNumRounds,
                           final int pInitRounds,
                           final int pFinalRounds) {
        /* Store configuration */
        theHashLen = pHashLen / Byte.SIZE;
        theBlockLen = pBlockLen;
        theNumRounds = pNumRounds;
        theNumFinalRounds = pFinalRounds;

        /* Create the input buffer */
        theInputBuffer = new byte[pBlockLen];

        /* Initialise the state */
        theState[0] = theHashLen;
        theState[1] = pBlockLen;
        theState[2] = pNumRounds;
        performRounds(pInitRounds);

        /* Save the initial state */
        theInitState = Arrays.copyOf(theState, theState.length);
    }

    @Override
    public String getAlgorithmName() {
        return "CubeHash-" + theHashLen * Byte.SIZE;
    }

    @Override
    public int getDigestSize() {
        return theHashLen;
    }

    @Override
    public int getByteLength() {
        return theHashLen;
    }

    @Override
    public void update(final byte pByte) {
        theInputBuffer[theByteIndex++] = pByte;
        if (theByteIndex == theBlockLen) {
            processBlock();
            theByteIndex = 0;
        }
    }

    @Override
    public void update(final byte[] pData, final int pOffset, final int pLength) {
        for (int i = 0; i < pLength; i++) {
            update(pData[pOffset + i]);
        }
    }

    @Override
    public int doFinal(final byte[] pHash, final int pOffset) {
        finaliseHash();
        outputHash(pHash, pOffset);
        return getDigestSize();
    }

    @Override
    public void reset() {
        System.arraycopy(theInitState, 0, theState, 0, theState.length);
        theByteIndex = 0;
    }

    @Override
    public CubeHashDigest copy() {
        return new CubeHashDigest(this);
    }

    @Override
    public void reset(final Memoable pState) {
        final CubeHashDigest d = (CubeHashDigest) pState;

        /* Copy the state */
        System.arraycopy(d.theState, 0, theState, 0, theState.length);
        System.arraycopy(d.theInputBuffer, 0, theInputBuffer, 0, theBlockLen);
        theByteIndex = d.theByteIndex;
    }

    /**
     * Decode a 32-bit value from a buffer (little-endian).
     *
     * @param buf the input buffer
     * @param off the input offset
     * @return the decoded value
     */
    private static int decode32le(final byte[] buf,
                                  final int off) {
        return (buf[off] & 0xFF)
                | ((buf[off + 1] & 0xFF) << 8)
                | ((buf[off + 2] & 0xFF) << 16)
                | ((buf[off + 3] & 0xFF) << 24);
    }

    /**
     * Encode a 32-bit value into a buffer (little-endian).
     *
     * @param val the value to encode
     * @param buf the output buffer
     * @param off the output offset
     */
    private static void encode32le(final int val,
                                   final byte[] buf,
                                   final int off) {
        buf[off] = (byte) val;
        buf[off + 1] = (byte) (val >> 8);
        buf[off + 2] = (byte) (val >> 16);
        buf[off + 3] = (byte) (val >> 24);
    }

    /**
     * Process a block.
     */
    private void processBlock() {
        /* Loop through the bytes in the block */
        for (int i = 0, j = 0; j < theBlockLen; i++, j += Integer.BYTES) {
            theState[i] ^= decode32le(theInputBuffer, j);
        }

        /* Perform the required rounds */
        performRounds(theNumRounds);
    }

    /**
     * Finalise the hash.
     */
    private void finaliseHash() {
        /* Set the marker */
        theInputBuffer[theByteIndex++] = (byte) 0x80;

        /* Fill remainder of buffer with zeroes */
        while (theByteIndex < theBlockLen) {
            theInputBuffer[theByteIndex++] = 0;
        }

        /* Process the block */
        processBlock();

        /* Adjust the final State word */
        theState[STATELEN - 1] ^= 1;

        /* Perform the required rounds */
        performRounds(theNumFinalRounds);
    }

    /**
     * Output the hash.
     * @param pOutput the output buffer
     * @param pOffSet the offset with the output buffer to write to
     */
    private void outputHash(final byte[] pOutput,
                            final int pOffSet) {
        /* Loop through the bytes in the block */
        for (int i = 0, j = 0; j < theHashLen; i++, j += Integer.BYTES) {
            encode32le(theState[i], pOutput, j + pOffSet);
        }

        /* Reset back to initial state */
        reset();
    }

    /**
     * Perform the required number of rounds.
     * @param pNumRounds the number of rounds
     */
    private void performRounds(final int pNumRounds) {
        /* Loop to perform the round */
        for (int i = 0; i < pNumRounds; i++) {
            performRound();
        }
    }

    /**
     * Perform the round.
     */
    private void performRound() {
        /* 1. Add x[0jklm] into x[1jklm] modulo 2^32, for each (j,k,l,m) */
        for (int i = 0; i < SWAPLEN; i++) {
            theState[i + SWAPLEN] += theState[i];
        }

        /* 2. Rotate x[0jklm] upwards by 7 bits, for each (j,k,l,m) */
        for (int i = 0; i < SWAPLEN; i++) {
            theSwap[i] = theState[i] << 7 | theState[i] >>> 25;
        }

        /* 3. Swap x[00klm] with x[01klm], for each (k,l,m) */
        for (int i = 0; i < SWAPLEN; i++) {
            theState[i] = theSwap[i ^ 8];
        }

        /* 4. Xor x[1jklm] into x[0jklm], for each (j,k,l,m) */
        for (int i = 0; i < SWAPLEN; i++) {
            theState[i] ^= theState[i + SWAPLEN];
        }

        /* 5. Swap x[1jk0m] with x[1jk1m], for each (j,k,m) */
        for (int i = 0; i < SWAPLEN; i++) {
            theSwap[i] = theState[i + SWAPLEN];
        }
        for (int i = 0; i < SWAPLEN; i++) {
            theState[i + SWAPLEN] = theSwap[i ^ 2];
        }

        /* 6. Add x[0jklm] into x[1jklm] modulo 2^32, for each (j,k,l,m) */
        for (int i = 0; i < SWAPLEN; i++) {
            theState[i + SWAPLEN] += theState[i];
        }

        /* 7. Rotate x[0jklm] upwards by 11 bits, for each (j,k,l,m) */
        for (int i = 0; i < SWAPLEN; i++) {
            theSwap[i] = theState[i] << 11 | theState[i] >>> 21;
        }

        /* 8. Swap x[0j0lm] with x[0j1lm], for each (j,l,m) */
        for (int i = 0; i < SWAPLEN; i++) {
            theState[i] = theSwap[i ^ 4];
        }

        /* 9. Xor x[1jklm] into x[0jklm], for each (j,k,l,m) */
        for (int i = 0; i < SWAPLEN; i++) {
            theState[i] ^= theState[i + SWAPLEN];
        }

        /* 10. Swap x[1jkl0] with x[1jkl1], for each (j,k,l) */
        for (int i = 0; i < SWAPLEN; i++) {
            theSwap[i] = theState[i + SWAPLEN];
        }
        for (int i = 0; i < SWAPLEN; i++) {
            theState[i + SWAPLEN] = theSwap[i ^ 1];
        }
    }
}
