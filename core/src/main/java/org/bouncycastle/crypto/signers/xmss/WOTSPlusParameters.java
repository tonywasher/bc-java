package org.bouncycastle.crypto.signers.xmss;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/**
 * WOTS+ Parameters.
 */
final class WOTSPlusParameters
{
    /**
     * OID.
     */
    private final XMSSOid oid;

    /**
     * The message digest size.
     */
    private final int digestSize;
    /**
     * The number of n-byte string elements in a WOTS+ secret key, public key,
     * and signature.
     */
    private final int len;
    /**
     * len1.
     */
    private final int len1;
    /**
     * len2.
     */
    private final int len2;
    private final ASN1ObjectIdentifier treeDigest;

    /**
     * The Winternitz parameter, fixed at 16 by RFC 8391 sec. 5. It is a constant rather than a
     * field with a getter because no parameter set varies it: len1, len2 and the OID lookup below
     * are derived from it here, and WOTSPlus reads it directly for the chain lengths and the
     * base-w conversion.
     */
    static final int WINTERNITZ_PARAMETER = 16;

    /**
     * Constructor...
     *
     * @param treeDigest The digest used for WOTS+.
     */
    public WOTSPlusParameters(ASN1ObjectIdentifier treeDigest)
    {
        this(treeDigest, DigestUtil.getDigest(treeDigest).getDigestSize());
    }

    /**
     * Constructor with explicit digest size (security parameter n).
     *
     * @param treeDigest The digest used for WOTS+.
     * @param digestSize The security parameter n in bytes.
     */
    public WOTSPlusParameters(ASN1ObjectIdentifier treeDigest, int digestSize)
    {
        if (treeDigest == null)
        {
            throw new NullPointerException("treeDigest == null");
        }
        this.treeDigest = treeDigest;
        this.digestSize = digestSize;
        len1 = (int)Math.ceil((double)(8 * digestSize) / XMSSUtil.log2(WINTERNITZ_PARAMETER));
        len2 = (int)Math.floor(XMSSUtil.log2(len1 * (WINTERNITZ_PARAMETER - 1)) / XMSSUtil.log2(WINTERNITZ_PARAMETER)) + 1;
        len = len1 + len2;
        String algName = DigestUtil.getDigestName(treeDigest);
        oid = WOTSPlusOid.lookup(algName, digestSize, WINTERNITZ_PARAMETER, len);
        if (oid == null)
        {
            throw new IllegalArgumentException("cannot find OID for digest algorithm: " + algName);
        }
    }

    /**
     * Getter OID.
     *
     * @return WOTS+ OID.
     */
    public XMSSOid getOid()
    {
        return oid;
    }
    
    /**
     * Getter digestSize.
     *
     * @return digestSize.
     */
    public int getTreeDigestSize()
    {
        return digestSize;
    }

    /**
     * Getter len.
     *
     * @return len.
     */
    public int getLen()
    {
        return len;
    }

    /**
     * Getter len1.
     *
     * @return len1.
     */
    public int getLen1()
    {
        return len1;
    }

    /**
     * Getter len2.
     *
     * @return len2.
     */
    public int getLen2()
    {
        return len2;
    }

    public ASN1ObjectIdentifier getTreeDigest()
    {
        return treeDigest;
    }
}
