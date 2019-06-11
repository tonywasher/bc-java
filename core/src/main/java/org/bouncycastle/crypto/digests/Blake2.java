package org.bouncycastle.crypto.digests;

import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Memoable;

/**
 * Blake2 Base class.
 */
public abstract class Blake2
        implements ExtendedDigest, Memoable {
    /**
     * Number of Words.
     */
    static final int NUMWORDS = 8;

    /**
     * Maximum Byte value.
     */
    private static final int MAXBYTE = 0xFF;

    /**
     * Message word permutations.
     */
    private static final byte[][] SIGMA = {
            {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
            {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
            {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
            {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
            {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
            {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
            {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
            {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
            {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
            {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
    };

    /**
     * The number of Rounds.
     */
    private final int theRounds;

    /**
     * The maximum xofLen.
     */
    private final long theMaxXofLen;

    /**
     * The buffer.
     */
    private final byte[] theBuffer;

    /**
     * Position of last inserted byte.
     */
    private int thePos;

    /**
     * The digestLength.
     */
    private short theDigestLen;

    /**
     * The key.
     */
    private byte[] theKey;

    /**
     * The salt.
     */
    private byte[] theSalt;

    /**
     * The personalisation.
     */
    private byte[] thePersonal;

    /**
     * The fanOut.
     */
    private short theFanOut;

    /**
     * The maxDepth.
     */
    private short theMaxDepth;

    /**
     * The leafLength.
     */
    private int theLeafLen;

    /**
     * The nodeOffSet.
     */
    private int theNodeOffset;

    /**
     * The nodeDepth.
     */
    private short theNodeDepth;

    /**
     * The xofLength.
     */
    private int theXofLen;

    /**
     * The innerLength.
     */
    private short theInnerLen;

    /**
     * Is this the final block?
     */
    private boolean isLastBlock;

    /**
     * Is this the last node at this depth?
     */
    private boolean isLastNode;

    /**
     * Is the digest active?
     */
    private boolean isActive;

    /**
     * Constructor.
     * @param pRounds the number of rounds.
     * @param pBlockLen the blockLength
     */
    Blake2(final int pRounds,
           final int pBlockLen) {
        /* Store parameters */
        theRounds = pRounds;
        theBuffer = new byte[pBlockLen];
        theFanOut = 1;
        theMaxDepth = 1;

        /* Determine maxXofLen */
        theMaxXofLen = this instanceof Blake2b ? 0xFFFFFFFEL : 0xFFFEL;
    }

    /**
     * Constructor.
     * @param pSource the source
     */
    Blake2(final Blake2 pSource) {
        /* Store parameters */
        theRounds = pSource.theRounds;
        theBuffer = new byte[pSource.theBuffer.length];

        /* Determine maxXofLen */
        theMaxXofLen = pSource.theMaxXofLen;
    }

    /**
     * Set the digestLength.
     * @param pLength the digestLength.
     */
    void setDigestLength(final int pLength) {
        checkActive();
        if (pLength < 0 || pLength > theBuffer.length << 2) {
            throw new IllegalArgumentException("DigestLength out of range");
        }
        theDigestLen = (short) pLength;
    }

    @Override
    public int getDigestSize() {
        return theDigestLen;
    }

    /**
     * Set the key.
     * @param pKey the key.
     */
    public void setKey(final byte[] pKey) {
        checkActive();
        if (pKey == null || pKey.length == 0) {
            clearKey();
            theKey = null;
        } else {
            if (pKey.length > theBuffer.length >> 1) {
                throw new IllegalArgumentException("Key too long");
            }
            clearKey();
            theKey = Arrays.copyOf(pKey, pKey.length);
        }
    }
    /**
     * Clear the key.
     */
    private void clearKey() {
        if (theKey != null) {
            Arrays.fill(theKey, (byte) 0);
        }
    }

    /**
     * Obtain the keyfLength.
     * @return the keyLength
     */
    int getKeyLen() {
        return theKey == null ? 0 : theKey.length;
    }

    /**
     * Set the salt.
     * @param pSalt the salt.
     */
    public void setSalt(final byte[] pSalt) {
        checkActive();
        if (pSalt == null || pSalt.length == 0) {
            theSalt = null;
        } else {
            if (pSalt.length != theBuffer.length >> 3) {
                throw new IllegalArgumentException("Salt incorrect length");
            }
            theSalt = Arrays.copyOf(pSalt, pSalt.length);
        }
    }

    /**
     * Obtain the salt.
     * @return the salt
     */
    byte[] getSalt() {
        return theSalt;
    }

    /**
     * Set the personalisation.
     * @param pPersonal the personalisation.
     */
    public void setPersonalisation(final byte[] pPersonal) {
        checkActive();
        if (pPersonal == null || pPersonal.length == 0) {
            thePersonal = null;
        } else {
            if (pPersonal.length != theBuffer.length >> 3) {
                throw new IllegalArgumentException("Personalisation incorrect length");
            }
            thePersonal = Arrays.copyOf(pPersonal, pPersonal.length);
        }
    }

    /**
     * Obtain the personalisation.
     * @return the personalisation
     */
    byte[] getPersonal() {
        return thePersonal;
    }

    /**
     * Set the xofLen.
     * @param pXofLen the xofLength.
     */
    void setXofLen(final long pXofLen) {
        checkActive();
        if (pXofLen < -1 || pXofLen == 0 || pXofLen > theMaxXofLen) {
            throw new IllegalArgumentException("XofLength out of range");
        }
        theXofLen = (int) pXofLen;
    }

    /**
     * Obtain the xofLength.
     * @return the xofLength
     */
    int getXofLen() {
        return theXofLen;
    }

    /**
     * Set the treeConfig.
     * @param pFanOut the fanout.
     * @param pMaxDepth the maxDepth.
     * @param pLeafLen the leafLength.
     */
    public void setTreeConfig(final int pFanOut,
                              final int pMaxDepth,
                              final int pLeafLen) {
        checkActive();
        if (pFanOut < 0 || pFanOut > MAXBYTE) {
            throw new IllegalArgumentException("FanOut out of range");
        }
        theFanOut = (short) pFanOut;
        if (pMaxDepth < -1 || pMaxDepth > MAXBYTE - 1) {
            throw new IllegalArgumentException("MaxDepth out of range");
        }
        theMaxDepth = (short) pMaxDepth;
        if (pLeafLen < 0) {
            throw new IllegalArgumentException("LeafLength out of range");
        }
        theLeafLen = pLeafLen;
    }

    /**
     * Obtain the fanout.
     * @return the fanout
     */
    short getFanOut() {
        return theFanOut;
    }

    /**
     * Obtain the maxDepth.
     * @return the maxDepth
     */
    short getMaxDepth() {
        return theMaxDepth;
    }

    /**
     * Obtain the leafLength.
     * @return the leafLength
     */
    int getLeafLen() {
        return theLeafLen;
    }

    /**
     * Set the nodePosition.
     * @param pOffset the offset.
     * @param pDepth the depth.
     */
    public void setNodePosition(final int pOffset,
                                final short pDepth) {
        checkActive();
        if (pOffset < 0) {
            throw new IllegalArgumentException("NodeOffset out of range");
        }
        theNodeOffset = pOffset;
        if (pDepth < 0 || pDepth > MAXBYTE) {
            throw new IllegalArgumentException("NodeDepth out of range");
        }
        theNodeDepth = (byte) pDepth;
    }

    /**
     * Obtain the nodeOffset.
     * @return the nodeOffset
     */
    int getNodeOffset() {
        return theNodeOffset;
    }

    /**
     * Obtain the nodeDepth.
     * @return the nodeDepth
     */
    short getNodeDepth() {
        return theNodeDepth;
    }

    /**
     * is this the last node?
     * @return true/false
     */
    boolean isLastBlock() {
        return isLastBlock;
    }

    /**
     * Set the lastNode indicator.
     * @param pLast is this the last node at this depth?
     */
    public void setLastNode(final boolean pLast) {
        isLastNode = pLast;
    }
    /**
     * is this the last node?
     * @return true/false
     */
    boolean isLastNode() {
        return isLastNode;
    }

    /**
     * Set the innerLength.
     * @param pInnerLen the innerLength.
     */
    void setInnerLength(final int pInnerLen) {
        checkActive();
        if (pInnerLen < 0 || pInnerLen > MAXBYTE) {
            throw new IllegalArgumentException("InnerLength out of range");
        }
        theInnerLen = (short) pInnerLen;
    }

    /**
     * Obtain the innerLength.
     * @return the innerLength
     */
    short getInnerLen() {
        return theInnerLen;
    }

    /**
     * checkActive.
     */
    private void checkActive() {
        if (isActive) {
            throw new IllegalStateException("Cannot configure digest after update");
        }
    }

    @Override
    public void update(final byte b) {
        /* Make sure that we are activated */
        activateH();

        /* If the buffer is full */
        final int blockLen = theBuffer.length;
        final int remainingLength = blockLen - thePos;
        if (remainingLength == 0) {
            /* Process the buffer */
            adjustCounter(blockLen);
            compressF(theBuffer, 0);

            /* Reset the buffer */
            Arrays.fill(theBuffer, (byte) 0);
            thePos = 0;
        }

        /* Store the byte */
        theBuffer[thePos] = b;
        thePos++;
    }

    @Override
    public void update(final byte[] pMessage,
                       final int pOffset,
                       final int pLen) {
        /* Ignore null operation */
        if (pMessage == null || pLen == 0) {
            return;
        }

        /* Make sure that we are activated */
        activate();

        /* Process any bytes currently in the buffer */
        final int blockLen = theBuffer.length;
        int remainingLen = 0; // left bytes of buffer
        if (thePos != 0) {
            /* Calculate space remaining in the buffer */
            remainingLen = blockLen - thePos;

            /* If there is sufficient space in the buffer */
            if (remainingLen >= pLen) {
                /* Copy date ointo byffer and return */
                System.arraycopy(pMessage, pOffset, theBuffer, thePos, pLen);
                thePos += pLen;
                return;
            }

            /* Fill the buffer */
            System.arraycopy(pMessage, pOffset, theBuffer, thePos, remainingLen);

            /* Adjust bytes count */
            adjustCounter(blockLen);

            /* Process the buffer */
            compressF(theBuffer, 0);

            /* Reset the buffer */
            thePos = 0;
            Arrays.fill(theBuffer, (byte) 0);
        }

        /* process all blocks except the last one */
        int messagePos;
        final int blockWiseLastPos = pOffset + pLen - blockLen;
        for (messagePos = pOffset + remainingLen; messagePos < blockWiseLastPos; messagePos += blockLen) {
            /* Adjust bytes count */
            adjustCounter(blockLen);

            /* Process the buffer */
            compressF(pMessage, messagePos);
        }

        /* Fill the buffer with the remaining bytes of the message */
        final int len = pLen - messagePos;
        System.arraycopy(pMessage, messagePos, theBuffer, 0, pOffset + len);
        thePos += pOffset + len;
    }

    @Override
    public int doFinal(final byte[] pOut,
                       final int pOutOffset) {
        /* Make sure that we are activated */
        activate();

        /* Adjust flags and counter */
        isLastBlock = true;
        completeCounter(thePos);

        /* Process the buffer */
        compressF(theBuffer, 0);
        Arrays.fill(theBuffer, (byte) 0);

        /* Output the digest */
        outputDigest(pOut, pOutOffset);

        /* Reset the state */
        reset();

        /* Return the digest length */
        return theDigestLen;
    }

    @Override
    public void reset() {
        /* Reset flags */
        isActive = false;
        isLastBlock = false;
        isLastNode = false;

        /* Reset the data Buffer */
        thePos = 0;
        Arrays.fill(theBuffer, (byte) 0);
    }

    /**
     * Copy state from source.
     * @param pSource the source
     */
    void reset(final Blake2 pSource) {
        /* Copy config */
        theDigestLen = pSource.theDigestLen;
        theInnerLen = pSource.theInnerLen;
        theLeafLen = pSource.theLeafLen;
        theXofLen = pSource.theXofLen;
        theFanOut = pSource.theFanOut;
        theMaxDepth = pSource.theMaxDepth;
        theNodeDepth = pSource.theNodeDepth;
        theNodeOffset = pSource.theNodeOffset;

        /* Copy flags */
        isActive = pSource.isActive;
        isLastNode = pSource.isLastNode;

        /* Clone arrays */
        theKey = Arrays.clone(pSource.theKey);
        theSalt = Arrays.clone(pSource.theSalt);
        thePersonal = Arrays.clone(pSource.thePersonal);

        /* Copy buffer */
        System.arraycopy(pSource.theBuffer, 0, theBuffer, 0, theBuffer.length);
        thePos = pSource.thePos;
    }

    /**
     * Adjust Counter.
     * @param pCount bytes processed
     */
    abstract void adjustCounter(int pCount);

    /**
     * Complete Counter.
     * @param pCount bytes processed
     */
    abstract void completeCounter(int pCount);

    /**
     * Output the digest.
     * @param pOut the output buffer
     * @param pOutOffset the offset in the output buffer
     */
    abstract void outputDigest(byte[] pOut,
                               int pOutOffset);
    /**
     * Activate.
     */
    private void activate() {
        /* If we are not active */
        if (!isActive) {
            /* Initialise H */
            activateH();

            /* Initialise any keyBlock */
            initKeyBlock();

            /* Set active flag */
            isActive = true;
        }
    }

    /**
     * Init the keyBlock.
     */
    void initKeyBlock() {
        /* If we have a key */
        if (theKey != null) {
            /* Initialise the first data block */
            System.arraycopy(theKey, 0, theBuffer, 0, theKey.length);
            thePos = theBuffer.length;
        }
    }

    /**
     * ActivateH.
     */
    abstract void activateH();

    /**
     * Obtain the Sigma for the round.
     * @param pRound the round
     * @return the Sigma
     */
    private static byte[] getSigmaForRound(final int pRound) {
        return SIGMA[pRound % SIGMA.length];
    }

    /**
     * Compress a message.
     * @param pMessage the message buffer
     * @param pMsgPos the position within the message buffer
     */
    private void compressF(final byte[] pMessage,
                           final int pMsgPos) {
        /* Initialise the buffers */
        initV();
        initM(pMessage, pMsgPos);

        /* Loop through the rounds */
        for (int round = 0; round < theRounds; round++) {
            /* Obtain the relevant SIGMA */
            final byte[] sigma = getSigmaForRound(round);

            /* Apply to columns of V */
            mixG(sigma[0], sigma[1], 0, 4, 8, 12);
            mixG(sigma[2], sigma[3], 1, 5, 9, 13);
            mixG(sigma[4], sigma[5], 2, 6, 10, 14);
            mixG(sigma[6], sigma[7], 3, 7, 11, 15);

            /* Apply to diagonals of V */
            mixG(sigma[8], sigma[9], 0, 5, 10, 15);
            mixG(sigma[10], sigma[11], 1, 6, 11, 12);
            mixG(sigma[12], sigma[13], 2, 7, 8, 13);
            mixG(sigma[14], sigma[15], 3, 4, 9, 14);
        }

        /* Adjust H */
        adjustH();
    }

    /**
     * Initialise V.
     */
    abstract void initV();

    /**
     * Initialise M.
     * @param pMessage the message buffer
     * @param pMsgPos the position in the message buffer
     */
    abstract void initM(byte[] pMessage,
                        int pMsgPos);

    /**
     * Mix function.
     * @param msgIdx1 the first msgIndex
     * @param msgIdx2 the second msgIndex
     * @param posA position A
     * @param posB position B
     * @param posC position C
     * @param posD position D
     */
    abstract void mixG(int msgIdx1,
                       int msgIdx2,
                       int posA,
                       int posB,
                       int posC,
                       int posD);

    /**
     * Adjust H.
     */
    abstract void adjustH();
}
