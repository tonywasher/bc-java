package org.bouncycastle.crypto.signers.xmss;

/**
 * WOTS+ signature.
 */
final class WOTSPlusSignature
{
    private final byte[][] signature;

    public WOTSPlusSignature(WOTSPlusParameters params, byte[][] signature)
    {
        this.signature = params.checkedClone(signature, "signature");
    }

    public byte[][] toByteArray()
    {
        return XMSSUtil.cloneArray(signature);
    }

    /**
     * The i'th of this signature's blocks, by reference, for public-key recovery to chain from.
     * chain() only reads its starting value and returns an array of its own however many steps it
     * takes, so no block escapes this object. What this saves is the deep copy
     * {@link #toByteArray()} makes, len + 1 arrays per verification and that again per layer of a
     * hypertree. The caller must not write to what it gets back.
     */
    byte[] getBlock(int i)
    {
        return signature[i];
    }

    /**
     * Write the len n-byte blocks of this signature into {@code out} at {@code position}. The
     * signature encoders only read them, so writing them straight into the buffer they are filling
     * - rather than through the deep copy {@link #toByteArray()} makes - saves a clone of the whole
     * block array per reduced signature encoded, and lets nothing escape either.
     */
    void encodeTo(byte[] out, int position)
    {
        for (int i = 0; i != signature.length; i++)
        {
            System.arraycopy(signature[i], 0, out, position, signature[i].length);
            position += signature[i].length;
        }
    }
}
