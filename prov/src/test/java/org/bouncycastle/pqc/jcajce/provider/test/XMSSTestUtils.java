package org.bouncycastle.pqc.jcajce.provider.test;

import org.bouncycastle.util.Strings;

/**
 * What XMSSTest and XMSSMTTest both need. The two are twins - every case in one has a counterpart
 * in the other differing only in which parameter set and which key type it names - so a helper
 * with no XMSS-versus-XMSS^MT typing in it belongs here rather than once in each.
 */
class XMSSTestUtils
{
    private XMSSTestUtils()
    {
    }

    /**
     * Whether a PKCS#8 encoding carries the Java-serialized BDS state the pre-promotion keys wrote,
     * which names its class in the clear. A fixture that has lost this is no longer the legacy
     * encoding the test means to read.
     */
    static boolean hasLegacyBdsMarker(byte[] encoding)
    {
        byte[] marker = Strings.toByteArray("org.bouncycastle.pqc.crypto.xmss.BDS");

        for (int i = 0; i <= encoding.length - marker.length; i++)
        {
            int j = 0;
            while (j != marker.length && encoding[i + j] == marker[j])
            {
                j++;
            }
            if (j == marker.length)
            {
                return true;
            }
        }

        return false;
    }
}
