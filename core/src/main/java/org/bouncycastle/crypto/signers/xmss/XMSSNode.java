package org.bouncycastle.crypto.signers.xmss;

import java.io.Serializable;

import org.bouncycastle.util.Bytes;

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
     * XOR the first {@code length} bytes of this node's value with {@code bitmask} into
     * {@code out} at {@code position}. randomizeHash() masks a pair of nodes into one 2n-byte
     * buffer this way and only reads them to do it, so masking straight from the value - rather
     * than through the defensive copy {@link #getValue()} makes - saves two clones per interior
     * node of every tree walked, and lets nothing escape either.
     * <p>
     * The length is the caller's n rather than this value's own, so a node that is somehow not n
     * bytes still fails here the way it did when randomizeHash passed n to Bytes.xor itself,
     * instead of quietly masking fewer bytes and leaving the rest of the buffer as it found it.
     */
    void maskTo(int length, byte[] bitmask, byte[] out, int position)
    {
        Bytes.xor(length, value, bitmask, out, position);
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
