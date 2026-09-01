package org.bouncycastle.crypto.params;

public class XMSSMTKeyParameters
    extends AsymmetricKeyParameter
{
    private final String treeDigest;

    public XMSSMTKeyParameters(boolean isPrivateKey, String treeDigest)
    {
        super(isPrivateKey);
        this.treeDigest = treeDigest;
    }

    public String getTreeDigest()
    {
        return treeDigest;
    }

    /**
     * Return {@code value} once it is confirmed to be {@code size} bytes long, or a freshly
     * allocated all-zero array of that size if {@code value} is null.
     */
    protected static byte[] validateOrAllocate(byte[] value, int size, String name)
    {
        if (value != null)
        {
            if (value.length != size)
            {
                throw new IllegalArgumentException("size of " + name + " needs to be equal size of digest");
            }
            return value;
        }

        return new byte[size];
    }
}
