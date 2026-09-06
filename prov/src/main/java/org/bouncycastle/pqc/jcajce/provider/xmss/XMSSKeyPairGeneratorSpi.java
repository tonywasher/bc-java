package org.bouncycastle.pqc.jcajce.provider.xmss;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.generators.XMSSKeyPairGenerator;
import org.bouncycastle.crypto.params.XMSSKeyGenerationParameters;
import org.bouncycastle.crypto.params.XMSSParameters;
import org.bouncycastle.crypto.params.XMSSPrivateKeyParameters;
import org.bouncycastle.crypto.params.XMSSPublicKeyParameters;
import org.bouncycastle.pqc.jcajce.spec.XMSSParameterSpec;

public class XMSSKeyPairGeneratorSpi
    extends java.security.KeyPairGenerator
{
    private XMSSKeyGenerationParameters param;
    private ASN1ObjectIdentifier treeDigest;
    private XMSSKeyPairGenerator engine = new XMSSKeyPairGenerator();

    private SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
    private boolean initialised = false;

    public XMSSKeyPairGeneratorSpi()
    {
        super("XMSS");
    }

    public void initialize(
        int strength,
        SecureRandom random)
    {
        // what the JCA specifies here; it extends IllegalArgumentException, so catches still match
        throw new InvalidParameterException("use AlgorithmParameterSpec");
    }

    public void initialize(
        AlgorithmParameterSpec params,
        SecureRandom random)
        throws InvalidAlgorithmParameterException
    {
        if (!(params instanceof XMSSParameterSpec))
        {
            throw new InvalidAlgorithmParameterException("parameter object not a XMSSParameterSpec");
        }

        XMSSParameterSpec xmssParams = (XMSSParameterSpec)params;

        // the name to OID and n table is DigestUtil's, shared with XMSSMTKeyPairGeneratorSpi,
        // which had a copy of these seven branches differing only in the parameter set class built
        // below
        DigestUtil.TreeDigest digest = DigestUtil.getTreeDigest(xmssParams.getTreeDigest());

        treeDigest = digest.getOID();
        param = new XMSSKeyGenerationParameters(
            new XMSSParameters(xmssParams.getHeight(), digest.getOID(), digest.getN()), random);

        engine.init(param);
        initialised = true;
    }

    public KeyPair generateKeyPair()
    {
        if (!initialised)
        {
            // the tree digest has to be set here as well, otherwise the key returned carries none
            // and its equals()/hashCode()/getTreeDigest() fail on it.
            treeDigest = NISTObjectIdentifiers.id_sha512;
            param = new XMSSKeyGenerationParameters(new XMSSParameters(10, new SHA512Digest()), random);

            engine.init(param);
            initialised = true;
        }

        AsymmetricCipherKeyPair pair = engine.generateKeyPair();
        XMSSPublicKeyParameters pub = (XMSSPublicKeyParameters)pair.getPublic();
        XMSSPrivateKeyParameters priv = (XMSSPrivateKeyParameters)pair.getPrivate();

        return new KeyPair(new BCXMSSPublicKey(treeDigest, pub), new BCXMSSPrivateKey(treeDigest, priv));
    }
}
