package org.bouncycastle.crypto.signers.xmss;

/**
 * WOTS+ public key.
 */
final class WOTSPlusPublicKeyParameters
{

    private final byte[][] publicKey;

    public WOTSPlusPublicKeyParameters(WOTSPlusParameters params, byte[][] publicKey)
    {
        super();
        this.publicKey = params.checkedClone(publicKey, "publicKey");
    }

    public byte[][] toByteArray()
    {
        return XMSSUtil.cloneArray(publicKey);
    }
}
