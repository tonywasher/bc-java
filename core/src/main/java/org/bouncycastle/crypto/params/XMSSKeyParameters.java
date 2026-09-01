package org.bouncycastle.crypto.params;

public class XMSSKeyParameters
    extends AsymmetricKeyParameter
{
    public static final String SHA_256 = "SHA-256";
    public static final String SHA_512 = "SHA-512";
    public static final String SHAKE128 = "SHAKE128";
    public static final String SHAKE256 = "SHAKE256";
    public static final String SHAKE256_LEN = "SHAKE256-LEN";

    private final String treeDigest;

    public XMSSKeyParameters(boolean isPrivateKey, String treeDigest)
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
