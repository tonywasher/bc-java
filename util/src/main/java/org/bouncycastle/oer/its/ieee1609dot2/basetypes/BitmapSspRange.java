package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

import java.util.Iterator;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.oer.its.ItsUtils;

/**
 * <pre>
 *     BitmapSspRange ::= SEQUENCE {
 *         sspValue OCTET STRING (SIZE(1..32)),
 *         sspBitmask OCTET STRING (SIZE(1..32))
 *     }
 * </pre>
 */
public class BitmapSspRange
    extends ASN1Object
{
    private final ASN1OctetString sspValue;
    private final ASN1OctetString sspBitmask;

    public BitmapSspRange(ASN1OctetString sspValue, ASN1OctetString sspBitmask)
    {
        this.sspValue = sspValue;
        this.sspBitmask = sspBitmask;
    }

    private BitmapSspRange(ASN1Sequence seq)
    {
        if (seq.size() != 2)
        {
            throw new IllegalArgumentException("expected sequence size of 2");
        }
        Iterator<ASN1Encodable> it = seq.iterator();
        sspValue = ASN1OctetString.getInstance(it.next());
        sspBitmask = ASN1OctetString.getInstance(it.next());
    }

    public static BitmapSspRange getInstance(Object o)
    {
        if (o instanceof BitmapSspRange)
        {
            return (BitmapSspRange)o;
        }
        else if (o != null)
        {
            return new BitmapSspRange(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public ASN1OctetString getSspValue()
    {
        return sspValue;
    }

    public ASN1OctetString getSspBitmask()
    {
        return sspBitmask;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return ItsUtils.toSequence(sspValue, sspBitmask);
    }
}