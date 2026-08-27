package org.bouncycastle.crypto.signers.xmss;

import java.io.Serializable;

/**
 * Binary tree node.
 */
public final class XMSSNode
    implements Serializable
{
    private static final long serialVersionUID = 1L;

    private final int height;
    private final byte[] value;

    public XMSSNode(int height, byte[] value)
    {
        super();
        this.height = height;
        this.value = value;
    }

    public int getHeight()
    {
        return height;
    }

    public byte[] getValue()
    {
        return XMSSUtil.cloneArray(value);
    }
}
