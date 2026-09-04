package org.bouncycastle.crypto.signers.xmss;

/**
 * WOTS+ signature.
 */
final class WOTSPlusSignature
{
    private final byte[][] signature;

    /**
     * This signature's len n-byte blocks, taken over rather than copied in.
     * <p>
     * All three of the callers that build one - {@link WOTSPlus#sign} and the two branches of
     * XMSSReducedSignature's constructor, and this class being package-private and final is what
     * makes that a list rather than a guess - allocate the array and every block in it and hand it
     * straight here, so nothing outside holds either. Two of the three are plainly their own: the
     * decoding branch fills the blocks with copyOfRange of the encoding being read, so the
     * caller's own array does not reach in, and the branch that was given no signature allocates
     * an empty len-by-n. Signing fills them with what chain() returns, and that those are chain()'s
     * own arrays is the part to check rather than assume - it chains one step per base-w digit of
     * the message, so it does reach the zero-step case, where chain() copies its starting value
     * out rather than handing it back. That starting value is one buffer reused across the len
     * chains, so without the copy every block for a zero digit would be the same array, holding
     * whatever the last chain left there.
     * <p>
     * Nothing escapes that did not before: {@link #toByteArray()} still copies on the way out, and
     * {@link #getBlock(int)} and {@link #encodeTo(byte[], int)} say for themselves that their
     * callers only read. What goes is a copy of a len-by-n array no one else could reach.
     *
     * @param signature the len n-byte blocks of the signature, which this instance takes over.
     */
    public WOTSPlusSignature(WOTSPlusParameters params, byte[][] signature)
    {
        this.signature = params.validateShape(signature, "signature");
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
