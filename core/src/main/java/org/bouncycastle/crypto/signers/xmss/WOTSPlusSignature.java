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
