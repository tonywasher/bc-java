package org.bouncycastle.crypto.digests;

import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.Xof;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Memoable;

public class Blake2X
        implements ExtendedDigest, Memoable, Xof {
    /**
     * The underlying Blake instance.
     */
    private final Blake2 theUnderlying;

    /**
     * The combining Blake instance.
     */
    private final Blake2 theComposite;

    /**
     * The XofLen.
     */
    private long theXofLen;

    /**
     * The Root hash.
     */
    private byte[] theRoot;

    /**
     * The XofRemaining.
     */
    private long theXofRemaining;

    /**
     * The current hash.
     */
    private byte[] theCurrent;

    /**
     * The data index within the current hash.
     */
    private int theHashIndex;

    /**
     * The Xof NodeIndex.
     */
    private int theNodeIndex;

    /**
     * Constructor.
     * @param p2b use Blake2b?
     */
    public Blake2X(final boolean p2b) {
        /* Create the two digests */
        theUnderlying = p2b ? new Blake2b(512) : new Blake2s(256);
        theComposite = (Blake2) theUnderlying.copy();

        /* Configure the composite */
        theComposite.setTreeConfig(0, 0, theUnderlying.getDigestSize());
        theComposite.setInnerLength(theUnderlying.getDigestSize());
        theComposite.setXofLen(-1);
        theXofLen = -1;
    }

    /**
     * Constructor.
     * @param pSource the source digest.
     */
    private Blake2X(final Blake2X pSource) {
        /* Create hashes */
        theUnderlying = pSource.theUnderlying instanceof Blake2b ? new Blake2b(512) : new Blake2s(256);
        theComposite = (Blake2) theUnderlying.copy();

        /* Initialise from source */
        reset(pSource);
    }

    /**
     * Set the key.
     * @param pKey the key.
     */
    public void setKey(final byte[] pKey) {
        theUnderlying.setKey(pKey);
    }

    /**
     * Set the salt.
     * @param pSalt the salt.
     */
    public void setSalt(final byte[] pSalt) {
        theUnderlying.setSalt(pSalt);
        theComposite.setSalt(pSalt);
    }

    /**
     * Set the personalisation.
     * @param pPersonal the personalisation.
     */
    public void setPersonalisation(final byte[] pPersonal) {
        theUnderlying.setPersonalisation(pPersonal);
        theComposite.setSalt(pPersonal);
    }

    /**
     * Set the XofLength.
     * @param pXofLen the XofLen.
     */
    public void setXofLen(final long pXofLen) {
        theUnderlying.setXofLen(pXofLen);
        theComposite.setXofLen(pXofLen);
        theXofLen = pXofLen;
    }

    @Override
    public String getAlgorithmName() {
        final String myBase = theUnderlying instanceof Blake2b ? "Blake2Xb" : "Blake2Xs";
        return myBase + (theXofLen == -1L ? "" : theXofLen);
    }

    @Override
    public int getDigestSize() {
        return (int) theXofLen;
    }

    @Override
    public int getByteLength() {
        return theUnderlying.getByteLength();
    }

    @Override
    public void update(final byte b) {
        theUnderlying.update(b);
    }

    @Override
    public void update(final byte[] pMessage,
                       final int pOffset,
                       final int pLen) {
        theUnderlying.update(pMessage, pOffset, pLen);
    }

    @Override
    public int doFinal(final byte[] pOut,
                       final int pOutOffset) {
        return doFinal(pOut, pOutOffset, pOut.length);
    }

    @Override
    public int doFinal(final byte[] pOut,
                       final int pOutOffset,
                       final int pOutLen) {
        /* Build the required output */
        final int length = doOutput(pOut, pOutOffset, pOutLen);

        /* reset the underlying digest and return the length */
        reset();
        return length;
    }

    @Override
    public int doOutput(final byte[] pOut,
                        final int pOutOffset,
                        final int pOutLen) {
        /* If we have not created the root hash yet */
        if (theRoot == null) {
            /* Calculate the underlying hash */
            theRoot = new byte[theUnderlying.getDigestSize()];
            theUnderlying.doFinal(theRoot, 0);
            theNodeIndex = 0;

            /* Calculate the number of bytes available */
            theXofRemaining = theXofLen == -1
                              ? (1L << Integer.SIZE) * theUnderlying.getDigestSize()
                              : theXofLen;

            /* Allocate a new current hash buffer */
            theCurrent = new byte[theUnderlying.getDigestSize()];
            theHashIndex = theCurrent.length;
        }

        /* Reject if there is insufficient Xof remaining */
        if (pOutLen < 0 || pOutLen > theXofRemaining) {
            throw new IllegalArgumentException("Insufficient bytes remaining");
        }

        /* If we have some remaining data in the current hash */
        int dataLeft = pOutLen;
        int outPos = pOutOffset;
        if (theHashIndex < theCurrent.length) {
            /* Copy data from current hash */
            final int dataToCopy = Math.min(dataLeft, theCurrent.length - theHashIndex);
            System.arraycopy(theCurrent, theHashIndex, pOut, outPos, dataToCopy);

            /* Adjust counters */
            theXofRemaining -= dataToCopy;
            theHashIndex += dataToCopy;
            outPos += dataToCopy;
            dataLeft -= dataToCopy;
        }

        /* Loop until we have completed the request */
        while (dataLeft > 0) {
            /* Calculate the next hash */
            obtainNextHash();

            /* Copy data from current hash */
            final int dataToCopy = Math.min(dataLeft, theCurrent.length);
            System.arraycopy(theCurrent, theHashIndex, pOut, outPos, dataToCopy);

            /* Adjust counters */
            theXofRemaining -= dataToCopy;
            theHashIndex += dataToCopy;
            outPos += dataToCopy;
            dataLeft -= dataToCopy;
        }

        /* Return the number of bytes transferred */
        return pOutLen;
    }

    @Override
    public void reset() {
        theUnderlying.reset();
        theRoot = null;
        theCurrent = null;
    }

    @Override
    public void reset(final Memoable pSource) {
        /* Access source */
        final Blake2X mySource = (Blake2X) pSource;

        /* Reset digests */
        theUnderlying.reset(mySource.theUnderlying);
        theComposite.reset(mySource.theComposite);

        /* Clone hashes */
        theRoot = Arrays.clone(mySource.theRoot);
        theCurrent = Arrays.clone(mySource.theCurrent);

        /* Copy state */
        theXofLen = mySource.theXofLen;
        theXofRemaining = mySource.theXofRemaining;
        theHashIndex = mySource.theHashIndex;
        theNodeIndex = mySource.theNodeIndex;
    }

    @Override
    public Blake2X copy() {
        return new Blake2X(this);
    }

    /**
     * Obtain the next hash.
     */
    private void obtainNextHash() {
        /* Set the digestLength */
        int digestLen = theUnderlying.getDigestSize();
        if (theXofRemaining < digestLen) {
            digestLen = (int) theXofRemaining;
        }
        theComposite.setDigestLength(digestLen);

        /* Calculate the hash */
        theComposite.setNodePosition(theNodeIndex++, (short) 0);
        theComposite.update(theRoot, 0, theRoot.length);
        theComposite.doFinal(theCurrent, 0);
        theHashIndex = 0;
    }
}
