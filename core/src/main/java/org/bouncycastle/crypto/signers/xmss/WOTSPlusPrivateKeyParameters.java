package org.bouncycastle.crypto.signers.xmss;

/**
 * WOTS+ private key.
 */
final class WOTSPlusPrivateKeyParameters
{
    private final byte[][] privateKey;

    public WOTSPlusPrivateKeyParameters(WOTSPlusParameters params, byte[][] privateKey)
    {
        this.privateKey = params.checkedClone(privateKey, "privateKey");
    }

    public byte[][] toByteArray()
    {
        return XMSSUtil.cloneArray(privateKey);
    }
}
