package org.bouncycastle.crypto.params;

/**
 * Shared by the XMSS and XMSS^MT key parameter classes, which accept the same n-byte fields on the
 * same terms and so must say the same thing about one that is the wrong size - the message is
 * asserted on verbatim, and two copies of the check are two chances to change only one of them.
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
