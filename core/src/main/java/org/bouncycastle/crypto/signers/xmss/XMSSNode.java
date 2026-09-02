package org.bouncycastle.crypto.signers.xmss;

import java.io.Serializable;

/**
 * Binary tree node.
 */
final class XMSSNode
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

    /**
     * This node's own value, one height further up the tree. Every caller computes this from a
     * node it is about to discard, so reusing the value directly - rather than round-tripping it
     * through the defensive copy {@link #getValue()} - avoids a clone nothing needs.
     */
    XMSSNode incrementHeight()
    {
        return new XMSSNode(height + 1, value);
    }
}
