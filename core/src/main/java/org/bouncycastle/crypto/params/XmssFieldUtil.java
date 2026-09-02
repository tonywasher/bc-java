package org.bouncycastle.crypto.params;

/**
 * Shared by the four XMSS and XMSS^MT key parameter classes, public and private, which accept the
 * same n-byte fields on the same terms and so must say the same thing about one that is the wrong
 * size - the message is asserted on verbatim, and a copy of the check per class is a chance per
 * class to change only that one. The two public key classes had already drifted to a different
 * wording before they were brought here.
 */
class XmssFieldUtil
{
    private XmssFieldUtil()
    {
    }

    /**
     * Return {@code value} once it is confirmed to be {@code size} bytes long, or a freshly
     * allocated all-zero array of that size if {@code value} is null.
     */
    static byte[] validateOrAllocate(byte[] value, int size, String name)
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
