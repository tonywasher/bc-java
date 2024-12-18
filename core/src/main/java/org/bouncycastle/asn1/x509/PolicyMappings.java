package org.bouncycastle.asn1.x509;

import java.util.Enumeration;
import java.util.Hashtable;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

/**
 * PolicyMappings V3 extension, described in RFC3280.
 * <pre>
 *    PolicyMappings ::= SEQUENCE SIZE (1..MAX) OF SEQUENCE {
 *      issuerDomainPolicy      CertPolicyId,
 *      subjectDomainPolicy     CertPolicyId }
 * </pre>
 *
 * @see <a href="https://www.faqs.org/rfc/rfc3280.txt">RFC 3280, section 4.2.1.6</a>
 */
public class PolicyMappings
    extends ASN1Object
{
    ASN1Sequence seq = null;

    public static PolicyMappings getInstance(Object obj)
    {
        if (obj instanceof PolicyMappings)
        {
            return (PolicyMappings)obj;
        }
        if (obj != null)
        {
            return new PolicyMappings(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    /**
     * Creates a new <code>PolicyMappings</code> instance.
     *
     * @param seq an <code>ASN1Sequence</code> constructed as specified
     *            in RFC 3280
     */
    private PolicyMappings(ASN1Sequence seq)
    {
        this.seq = seq;
    }

    /**
     * Creates a new <code>PolicyMappings</code> instance.
     *
     * @param mappings a <code>HashMap</code> value that maps
     *                 <code>String</code> oids
     *                 to other <code>String</code> oids.
     * @deprecated use CertPolicyId constructors.
     */
    public PolicyMappings(Hashtable mappings)
    {
        ASN1EncodableVector dev = new ASN1EncodableVector(mappings.size());

        Enumeration it = mappings.keys();
        while (it.hasMoreElements())
        {
            String idp = (String)it.nextElement();
            String sdp = (String)mappings.get(idp);

            dev.add(new DERSequence(new ASN1ObjectIdentifier(idp), new ASN1ObjectIdentifier(sdp)));
        }

        seq = new DERSequence(dev);
    }

    public PolicyMappings(CertPolicyId issuerDomainPolicy, CertPolicyId subjectDomainPolicy)
    {
        seq = new DERSequence(new DERSequence(issuerDomainPolicy, subjectDomainPolicy));
    }

    public PolicyMappings(CertPolicyId[] issuerDomainPolicy, CertPolicyId[] subjectDomainPolicy)
    {
        ASN1EncodableVector dev = new ASN1EncodableVector(issuerDomainPolicy.length);

        for (int i = 0; i != issuerDomainPolicy.length; i++)
        {
            dev.add(new DERSequence(issuerDomainPolicy[i], subjectDomainPolicy[i]));
        }

        seq = new DERSequence(dev);
    }

    public ASN1Primitive toASN1Primitive()
    {
        return seq;
    }
}
