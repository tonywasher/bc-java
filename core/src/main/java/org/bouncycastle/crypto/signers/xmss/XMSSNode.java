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
     * Write this node's value into {@code out} at {@code position}. The signature encoders only
     * read it, so writing it straight into the buffer they are filling - rather than through the
     * defensive copy {@link #getValue()} makes - saves a clone per node of every authentication
     * path encoded, and lets nothing escape either.
     */
    void encodeTo(byte[] out, int position)
    {
        System.arraycopy(value, 0, out, position, value.length);
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
