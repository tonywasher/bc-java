package org.bouncycastle.pqc.jcajce.provider.test;

import java.security.PrivateKey;

import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.util.Strings;

/**
 * What XMSSTest and XMSSMTTest both need. The two are twins - every case in one has a counterpart
 * in the other differing only in which parameter set and which key type it names - so a helper
 * with no XMSS-versus-XMSS^MT typing in it belongs here rather than once in each.
 */
class XMSSTestUtils
{
    /**
     * A PKCS#8 attribute set to carry through an encode, a signature and a shard, so a key that
     * arrived with attributes can be told from one that had them dropped along the way.
     */
    static final ASN1Set ATTRIBUTES = new DERSet(new Attribute(
        PKCSObjectIdentifiers.pkcs_9_at_friendlyName, new DERSet(new DERBMPString("a stateful key"))));

    private XMSSTestUtils()
    {
    }

    /**
     * The same PKCS#8 encoding with {@link #ATTRIBUTES} on it. The algorithm identifier and the
     * private key octets are the ones that arrived; only the attributes field is written.
     */
    static byte[] withAttributes(byte[] pkcs8)
        throws Exception
    {
        PrivateKeyInfo info = PrivateKeyInfo.getInstance(pkcs8);

        return new PrivateKeyInfo(info.getPrivateKeyAlgorithm(), info.parsePrivateKey(), ATTRIBUTES)
            .getEncoded();
    }

    /**
     * The attributes a PKCS#8 encoding carries, or null when it carries none.
     */
    static ASN1Set attributesOf(byte[] pkcs8)
    {
        return PrivateKeyInfo.getInstance(pkcs8).getAttributes();
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

    /**
     * A daemon thread that asks one.equals(two) two thousand times and, if every answer was true,
     * records that in agreed[slot]. Started against a second thread comparing the same pair the
     * other way round, it is the deadlock probe: nested monitors stop both threads within a few
     * rounds and neither ever reaches the write.
     */
    static Thread comparing(final PrivateKey one, final PrivateKey two, final boolean[] agreed,
        final int slot)
    {
        Thread thread = new Thread(new Runnable()
        {
            public void run()
            {
                for (int i = 0; i != 2000; i++)
                {
                    if (!one.equals(two))
                    {
                        return;
                    }
                }

                agreed[slot] = true;
            }
        });

        thread.setDaemon(true);

        return thread;
    }
}
