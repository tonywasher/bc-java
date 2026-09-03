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
}
