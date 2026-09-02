package org.bouncycastle.pqc.jcajce.provider.xmss;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.signers.xmss.XMSSEngine;
import org.bouncycastle.pqc.jcajce.spec.XMSSParameterSpec;

class DigestUtil
{
    /**
     * The tree-digest OID for a lightweight tree-digest name, including the SHAKE256-LEN of the
     * SP 800-208 SHAKE256/256 and SHAKE256/192 sets.
     * <p>
     * The names are the ones the lightweight key parameters report, so the table belongs to the
     * implementation that produces them rather than being kept a second time here: a copy of it
     * here was a copy that could be one parameter set behind. The digest-instance table beside
     * it, a third copy of the same five entries, had no caller at all.
     * </p>
     */
    static ASN1ObjectIdentifier getDigestOID(String digest)
    {
        return XMSSEngine.getDigestOID(digest);
    }

    public static byte[] getDigestResult(Digest digest)
    {
        byte[] hash = new byte[digest.getDigestSize()];

        digest.doFinal(hash, 0);

        return hash;
    }

    public static String getXMSSDigestName(ASN1ObjectIdentifier treeDigest)
    {
        if (treeDigest.equals(NISTObjectIdentifiers.id_sha256))
        {
            return XMSSParameterSpec.SHA256;
        }
        if (treeDigest.equals(NISTObjectIdentifiers.id_sha512))
        {
            return XMSSParameterSpec.SHA512;
        }
        if (treeDigest.equals(NISTObjectIdentifiers.id_shake128))
        {
            return XMSSParameterSpec.SHAKE128;
        }
        if (treeDigest.equals(NISTObjectIdentifiers.id_shake256))
        {
            return XMSSParameterSpec.SHAKE256;
        }

        throw new IllegalArgumentException("unrecognized digest OID: " + treeDigest);
    }

    /**
     * Tree-digest name including the security parameter, so the SP 800-208 sets are
     * distinguished from their RFC 8391 siblings sharing the same digest OID:
     * SHA-256/192 (n=24) shares id-sha256 with SHA-256/256 (n=32), and both SHAKE256/256
     * (n=32) and SHAKE256/192 (n=24) use id-shake256-len.
     *
     * @param treeDigest the tree-digest OID.
     * @param n          the security parameter (digest output size in bytes).
     */
    public static String getXMSSDigestName(ASN1ObjectIdentifier treeDigest, int n)
    {
        if (treeDigest.equals(NISTObjectIdentifiers.id_sha256))
        {
            return (n == 24) ? XMSSParameterSpec.SHA256_192 : XMSSParameterSpec.SHA256;
        }
        if (treeDigest.equals(NISTObjectIdentifiers.id_shake256_len))
        {
            return (n == 24) ? XMSSParameterSpec.SHAKE256_192 : XMSSParameterSpec.SHAKE256_256;
        }

        return getXMSSDigestName(treeDigest);
    }

    static class DoubleDigest
        implements Digest
    {
        private SHAKEDigest digest;

        DoubleDigest(SHAKEDigest digest)
        {
             this.digest = digest;
        }

        @Override
        public String getAlgorithmName()
        {
            return digest.getAlgorithmName() + "/" + (digest.getDigestSize() * 2 * 8);
        }

        @Override
        public int getDigestSize()
        {
            return digest.getDigestSize() * 2;
        }

        @Override
        public void update(byte in)
        {
             digest.update(in);
        }

        @Override
        public void update(byte[] in, int inOff, int len)
        {
            digest.update(in, inOff, len);
        }

        @Override
        public int doFinal(byte[] out, int outOff)
        {
            return digest.doFinal(out, outOff, this.getDigestSize());
        }

        @Override
        public void reset()
        {
            digest.reset();
        }
    }
}
