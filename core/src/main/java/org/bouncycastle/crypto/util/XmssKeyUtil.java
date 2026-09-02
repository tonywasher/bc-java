package org.bouncycastle.crypto.util;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.iana.IANAObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.XMSSKeyParameters;
import org.bouncycastle.crypto.params.XMSSMTParameters;
import org.bouncycastle.crypto.params.XMSSMTPrivateKeyParameters;
import org.bouncycastle.crypto.params.XMSSMTPublicKeyParameters;
import org.bouncycastle.crypto.params.XMSSParameters;
import org.bouncycastle.crypto.params.XMSSPrivateKeyParameters;
import org.bouncycastle.crypto.params.XMSSPublicKeyParameters;
import org.bouncycastle.crypto.signers.xmss.BDS;
import org.bouncycastle.crypto.signers.xmss.BDSStateMap;
import org.bouncycastle.crypto.signers.xmss.XMSSEngine;
import org.bouncycastle.internal.asn1.isara.IsaraObjectIdentifiers;
import org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
import org.bouncycastle.pqc.asn1.XMSSKeyParams;
import org.bouncycastle.pqc.asn1.XMSSMTKeyParams;
import org.bouncycastle.pqc.asn1.XMSSMTPrivateKey;
import org.bouncycastle.pqc.asn1.XMSSMTPublicKey;
import org.bouncycastle.pqc.asn1.XMSSPrivateKey;
import org.bouncycastle.pqc.asn1.XMSSPublicKey;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Exceptions;
import org.bouncycastle.util.Pack;

/**
 * The XMSS / XMSS^MT (RFC 8391, SP 800-208) half of the key factories in this package, held apart
 * from them so that the distributions which exclude XMSS - the jdk1.4 and jdk1.3 Ant builds - can
 * replace this one class rather than fork four factories. Every method answers null for a key or a
 * key info that is not XMSS / XMSS^MT, which is what lets the callers fall through to their own
 * unrecognised-algorithm handling; the jdk1.4 twin answers null unconditionally.
 * <p>
 * <b>Keep the jdk1.4 twin (core/src/main/jdk1.4) in step with this class:</b> a method added
 * here and not there breaks the jdk1.4 and jdk1.3 Ant builds.
 */
class XmssKeyUtil
{
    private XmssKeyUtil()
    {
    }

    /**
     * The SubjectPublicKeyInfo for an XMSS or XMSS^MT public key, or null if the key is neither.
     */
    static SubjectPublicKeyInfo createSubjectPublicKeyInfo(AsymmetricKeyParameter publicKey)
        throws IOException
    {
        if (publicKey instanceof XMSSPublicKeyParameters)
        {
            XMSSPublicKeyParameters keyParams = (XMSSPublicKeyParameters)publicKey;

            byte[] publicSeed = keyParams.getPublicSeed();
            byte[] root = keyParams.getRoot();
            byte[] keyEnc = keyParams.getEncoded();
            if (keyEnc.length > publicSeed.length + root.length)
            {
                // RFC 9802: raw RFC 8391 public key, no parameters, no ASN.1 wrapping.
                AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(IANAObjectIdentifiers.id_alg_xmss_hashsig);

                return new SubjectPublicKeyInfo(algorithmIdentifier, keyEnc);
            }

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCObjectIdentifiers.xmss,
                new XMSSKeyParams(keyParams.getParameters().getHeight(), lookupTreeAlgID(keyParams.getTreeDigest())));

            return new SubjectPublicKeyInfo(algorithmIdentifier, new XMSSPublicKey(publicSeed, root));
        }
        if (publicKey instanceof XMSSMTPublicKeyParameters)
        {
            XMSSMTPublicKeyParameters keyParams = (XMSSMTPublicKeyParameters)publicKey;

            byte[] publicSeed = keyParams.getPublicSeed();
            byte[] root = keyParams.getRoot();
            byte[] keyEnc = keyParams.getEncoded();
            if (keyEnc.length > publicSeed.length + root.length)
            {
                // RFC 9802: raw RFC 8391 public key, no parameters, no ASN.1 wrapping.
                AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(IANAObjectIdentifiers.id_alg_xmssmt_hashsig);

                return new SubjectPublicKeyInfo(algorithmIdentifier, keyEnc);
            }

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCObjectIdentifiers.xmss_mt,
                new XMSSMTKeyParams(keyParams.getParameters().getHeight(), keyParams.getParameters().getLayers(),
                    lookupTreeAlgID(keyParams.getTreeDigest())));

            return new SubjectPublicKeyInfo(algorithmIdentifier, new XMSSMTPublicKey(publicSeed, root));
        }

        return null;
    }

    /**
     * The PrivateKeyInfo for an XMSS or XMSS^MT private key, or null if the key is neither.
     */
    static PrivateKeyInfo createPrivateKeyInfo(AsymmetricKeyParameter privateKey, ASN1Set attributes)
        throws IOException
    {
        if (privateKey instanceof XMSSPrivateKeyParameters)
        {
            XMSSPrivateKeyParameters keyParams = (XMSSPrivateKeyParameters)privateKey;
            XMSSParameters params = keyParams.getParameters();

            if (params.getParameterSetOID() != 0)
            {
                // Encode any standard (RFC 8391 / SP 800-208) parameter set in the RFC 9802 form
                // (id-alg-xmss-hashsig), matching the SubjectPublicKeyInfo the public half produces,
                // so the private and public keys of a keypair share one algorithm OID. The 4-octet
                // parameter-set OID is carried ahead of the raw key so createPrivateKey() can recover
                // the full parameter set (including n) - the legacy XMSSKeyParams (height + tree-digest
                // OID only) cannot represent the SP 800-208 sets. A non-standard tree height has no
                // parameter-set OID (0) and falls through to the legacy PQCObjectIdentifiers.xmss form.
                byte[] keyEnc = Arrays.concatenate(Pack.intToBigEndian(params.getParameterSetOID()), keyParams.getEncoded());
                AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(IANAObjectIdentifiers.id_alg_xmss_hashsig);

                return new PrivateKeyInfo(algorithmIdentifier, new DEROctetString(keyEnc), attributes);
            }

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCObjectIdentifiers.xmss,
                new XMSSKeyParams(params.getHeight(), lookupTreeAlgID(keyParams.getTreeDigest())));

            return new PrivateKeyInfo(algorithmIdentifier, xmssCreateKeyStructure(keyParams), attributes);
        }
        if (privateKey instanceof XMSSMTPrivateKeyParameters)
        {
            XMSSMTPrivateKeyParameters keyParams = (XMSSMTPrivateKeyParameters)privateKey;
            XMSSMTParameters params = keyParams.getParameters();

            if (params.getParameterSetOID() != 0)
            {
                // See the XMSS branch above: any standard parameter set is encoded in the RFC 9802
                // form (id-alg-xmssmt-hashsig) with the 4-octet parameter-set OID ahead of the raw
                // key; a non-standard tree height falls through to PQCObjectIdentifiers.xmss_mt.
                byte[] keyEnc = Arrays.concatenate(Pack.intToBigEndian(params.getParameterSetOID()), keyParams.getEncoded());
                AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(IANAObjectIdentifiers.id_alg_xmssmt_hashsig);

                return new PrivateKeyInfo(algorithmIdentifier, new DEROctetString(keyEnc), attributes);
            }

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCObjectIdentifiers.xmss_mt,
                new XMSSMTKeyParams(params.getHeight(), params.getLayers(), lookupTreeAlgID(keyParams.getTreeDigest())));

            return new PrivateKeyInfo(algorithmIdentifier, xmssmtCreateKeyStructure(keyParams), attributes);
        }

        return null;
    }

    /**
     * The public key parameters for an XMSS or XMSS^MT SubjectPublicKeyInfo, or null when this
     * distribution has no XMSS support. Only called for the six XMSS / XMSS^MT algorithm OIDs, so
     * this never answers null in the base tree.
     */
    static AsymmetricKeyParameter createPublicKey(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        ASN1ObjectIdentifier algOID = keyInfo.getAlgorithm().getAlgorithm();

        if (algOID.equals(PQCObjectIdentifiers.xmss_mt)
            || algOID.equals(IsaraObjectIdentifiers.id_alg_xmssmt)
            || algOID.equals(IANAObjectIdentifiers.id_alg_xmssmt_hashsig))
        {
            XMSSMTKeyParams keyParams = XMSSMTKeyParams.getInstance(keyInfo.getAlgorithm().getParameters());

            if (keyParams != null)
            {
                ASN1ObjectIdentifier treeDigest = keyParams.getTreeDigest().getAlgorithm();

                XMSSPublicKey xmssMtPublicKey = XMSSPublicKey.getInstance(keyInfo.parsePublicKey());

                return new XMSSMTPublicKeyParameters
                    .Builder(new XMSSMTParameters(keyParams.getHeight(), keyParams.getLayers(), getDigest(treeDigest)))
                    .withPublicSeed(xmssMtPublicKey.getPublicSeed())
                    .withRoot(xmssMtPublicKey.getRoot()).build();
            }

            // RFC 9802 carries the raw RFC 8391 key; the legacy draft form wrapped it in an OCTET STRING.
            byte[] keyEnc = rawPublicKey(keyInfo);

            if (keyEnc.length < 4)
            {
                throw new IOException("XMSS^MT public key data too short");
            }

            XMSSMTParameters parameters = XMSSMTParameters.lookupByOID(Pack.bigEndianToInt(keyEnc, 0));
            if (parameters == null)
            {
                throw new IOException("unknown XMSS^MT public key OID: " + Pack.bigEndianToInt(keyEnc, 0));
            }

            try
            {
                return new XMSSMTPublicKeyParameters
                    .Builder(parameters)
                    .withPublicKey(keyEnc).build();
            }
            catch (IllegalArgumentException e)
            {
                throw new IOException("malformed XMSS^MT public key: " + e.getMessage());
            }
        }

        if (algOID.equals(PQCObjectIdentifiers.xmss)
            || algOID.equals(IsaraObjectIdentifiers.id_alg_xmss)
            || algOID.equals(IANAObjectIdentifiers.id_alg_xmss_hashsig))
        {
            XMSSKeyParams keyParams = XMSSKeyParams.getInstance(keyInfo.getAlgorithm().getParameters());

            if (keyParams != null)
            {
                ASN1ObjectIdentifier treeDigest = keyParams.getTreeDigest().getAlgorithm();
                XMSSPublicKey xmssPublicKey = XMSSPublicKey.getInstance(keyInfo.parsePublicKey());

                return new XMSSPublicKeyParameters
                    .Builder(new XMSSParameters(keyParams.getHeight(), getDigest(treeDigest)))
                    .withPublicSeed(xmssPublicKey.getPublicSeed())
                    .withRoot(xmssPublicKey.getRoot()).build();
            }

            // RFC 9802 carries the raw RFC 8391 key; the legacy draft form wrapped it in an OCTET STRING.
            byte[] keyEnc = rawPublicKey(keyInfo);

            if (keyEnc.length < 4)
            {
                throw new IOException("XMSS public key data too short");
            }

            XMSSParameters parameters = XMSSParameters.lookupByOID(Pack.bigEndianToInt(keyEnc, 0));
            if (parameters == null)
            {
                throw new IOException("unknown XMSS public key OID: " + Pack.bigEndianToInt(keyEnc, 0));
            }

            try
            {
                return new XMSSPublicKeyParameters
                    .Builder(parameters)
                    .withPublicKey(keyEnc).build();
            }
            catch (IllegalArgumentException e)
            {
                throw new IOException("malformed XMSS public key: " + e.getMessage());
            }
        }

        return null;
    }

    /**
     * The private key parameters for an XMSS or XMSS^MT PrivateKeyInfo, or null when this
     * distribution has no XMSS support.
     */
    static AsymmetricKeyParameter createPrivateKey(PrivateKeyInfo keyInfo)
        throws IOException
    {
        ASN1ObjectIdentifier algOID = keyInfo.getPrivateKeyAlgorithm().getAlgorithm();

        if (algOID.equals(PQCObjectIdentifiers.xmss))
        {
            XMSSKeyParams keyParams = XMSSKeyParams.getInstance(keyInfo.getPrivateKeyAlgorithm().getParameters());
            ASN1ObjectIdentifier treeDigest = keyParams.getTreeDigest().getAlgorithm();

            XMSSPrivateKey xmssPrivateKey = XMSSPrivateKey.getInstance(keyInfo.parsePrivateKey());

            try
            {
                XMSSPrivateKeyParameters.Builder keyBuilder = new XMSSPrivateKeyParameters
                    .Builder(new XMSSParameters(keyParams.getHeight(), getDigest(treeDigest)))
                    .withIndex(xmssPrivateKey.getIndex())
                    .withSecretKeySeed(xmssPrivateKey.getSecretKeySeed())
                    .withSecretKeyPRF(xmssPrivateKey.getSecretKeyPRF())
                    .withPublicSeed(xmssPrivateKey.getPublicSeed())
                    .withRoot(xmssPrivateKey.getRoot());

                if (xmssPrivateKey.getVersion() != 0)
                {
                    keyBuilder.withMaxIndex(xmssPrivateKey.getMaxIndex());
                }

                if (xmssPrivateKey.getBdsState() != null)
                {
                    BDS bds = XMSSEngine.getBDSFromEncoding(xmssPrivateKey.getBdsState(), xmssPrivateKey.getPublicSeed());
                    keyBuilder.withBDSState(bds.withWOTSDigest(treeDigest));
                }

                return keyBuilder.build();
            }
            catch (ClassNotFoundException e)
            {
                throw Exceptions.ioException("ClassNotFoundException processing BDS state: " + e.getMessage(), e);
            }
        }
        if (algOID.equals(PQCObjectIdentifiers.xmss_mt))
        {
            XMSSMTKeyParams keyParams = XMSSMTKeyParams.getInstance(keyInfo.getPrivateKeyAlgorithm().getParameters());
            ASN1ObjectIdentifier treeDigest = keyParams.getTreeDigest().getAlgorithm();

            try
            {
                XMSSMTPrivateKey xmssMtPrivateKey = XMSSMTPrivateKey.getInstance(keyInfo.parsePrivateKey());

                XMSSMTPrivateKeyParameters.Builder keyBuilder = new XMSSMTPrivateKeyParameters
                    .Builder(new XMSSMTParameters(keyParams.getHeight(), keyParams.getLayers(), getDigest(treeDigest)))
                    .withIndex(xmssMtPrivateKey.getIndex())
                    .withSecretKeySeed(xmssMtPrivateKey.getSecretKeySeed())
                    .withSecretKeyPRF(xmssMtPrivateKey.getSecretKeyPRF())
                    .withPublicSeed(xmssMtPrivateKey.getPublicSeed())
                    .withRoot(xmssMtPrivateKey.getRoot());

                if (xmssMtPrivateKey.getVersion() != 0)
                {
                    keyBuilder.withMaxIndex(xmssMtPrivateKey.getMaxIndex());
                }

                if (xmssMtPrivateKey.getBdsState() != null)
                {
                    BDSStateMap bdsState = XMSSEngine.getBDSStateMapFromEncoding(xmssMtPrivateKey.getBdsState(), xmssMtPrivateKey.getPublicSeed());
                    keyBuilder.withBDSState(bdsState.withWOTSDigest(treeDigest));
                }

                return keyBuilder.build();
            }
            catch (ClassNotFoundException e)
            {
                throw Exceptions.ioException("ClassNotFoundException processing BDS state: " + e.getMessage(), e);
            }
        }
        if (algOID.equals(IANAObjectIdentifiers.id_alg_xmss_hashsig))
        {
            // RFC 9802 form used for the SP 800-208 sets: the private key octets are the 4-octet
            // parameter-set OID followed by the raw XMSSPrivateKeyParameters encoding, recovered
            // via lookupByOID so the full parameter set (including n) is restored.
            byte[] keyEnc = ASN1OctetString.getInstance(keyInfo.parsePrivateKey()).getOctets();
            if (keyEnc.length < 4)
            {
                throw new IOException("XMSS private key data too short");
            }
            int paramSet = Pack.bigEndianToInt(keyEnc, 0);
            XMSSParameters xmssParams = XMSSParameters.lookupByOID(paramSet);
            if (xmssParams == null)
            {
                throw new IOException("unknown XMSS private key OID: " + paramSet);
            }
            try
            {
                return new XMSSPrivateKeyParameters.Builder(xmssParams)
                    .withPrivateKey(Arrays.copyOfRange(keyEnc, 4, keyEnc.length)).build();
            }
            catch (IllegalArgumentException e)
            {
                throw new IOException("malformed XMSS private key: " + e.getMessage());
            }
        }
        if (algOID.equals(IANAObjectIdentifiers.id_alg_xmssmt_hashsig))
        {
            byte[] keyEnc = ASN1OctetString.getInstance(keyInfo.parsePrivateKey()).getOctets();
            if (keyEnc.length < 4)
            {
                throw new IOException("XMSSMT private key data too short");
            }
            int paramSet = Pack.bigEndianToInt(keyEnc, 0);
            XMSSMTParameters xmssmtParams = XMSSMTParameters.lookupByOID(paramSet);
            if (xmssmtParams == null)
            {
                throw new IOException("unknown XMSSMT private key OID: " + paramSet);
            }
            try
            {
                return new XMSSMTPrivateKeyParameters.Builder(xmssmtParams)
                    .withPrivateKey(Arrays.copyOfRange(keyEnc, 4, keyEnc.length)).build();
            }
            catch (IllegalArgumentException e)
            {
                throw new IOException("malformed XMSSMT private key: " + e.getMessage());
            }
        }

        return null;
    }

    private static byte[] rawPublicKey(SubjectPublicKeyInfo keyInfo)
    {
        byte[] keyEnc = keyInfo.getPublicKeyData().getOctets();
        ASN1OctetString data = Utils.parseOctetData(keyEnc);

        return (data != null) ? data.getOctets() : keyEnc;
    }

    /**
     * The tree digest for a tree-digest OID. Held here rather than taken from Utils because the
     * SP 800-208 SHAKE256/192 and SHAKE256/256 sets name id-shake256-len, which no other algorithm
     * in this package uses.
     */
    private static Digest getDigest(ASN1ObjectIdentifier oid)
    {
        if (oid.equals(NISTObjectIdentifiers.id_sha256))
        {
            return new SHA256Digest();
        }
        if (oid.equals(NISTObjectIdentifiers.id_sha512))
        {
            return new SHA512Digest();
        }
        if (oid.equals(NISTObjectIdentifiers.id_shake128))
        {
            return new SHAKEDigest(128);
        }
        if (oid.equals(NISTObjectIdentifiers.id_shake256) || oid.equals(NISTObjectIdentifiers.id_shake256_len))
        {
            return new SHAKEDigest(256);
        }

        throw new IllegalArgumentException("unrecognized digest OID: " + oid);
    }

    private static AlgorithmIdentifier lookupTreeAlgID(String treeDigest)
    {
        if (treeDigest.equals(XMSSKeyParameters.SHA_256))
        {
            return new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);
        }
        if (treeDigest.equals(XMSSKeyParameters.SHA_512))
        {
            return new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha512);
        }
        if (treeDigest.equals(XMSSKeyParameters.SHAKE128))
        {
            return new AlgorithmIdentifier(NISTObjectIdentifiers.id_shake128);
        }
        if (treeDigest.equals(XMSSKeyParameters.SHAKE256))
        {
            return new AlgorithmIdentifier(NISTObjectIdentifiers.id_shake256);
        }

        throw new IllegalArgumentException("unknown tree digest: " + treeDigest);
    }

    private static XMSSPrivateKey xmssCreateKeyStructure(XMSSPrivateKeyParameters keyParams)
        throws IOException
    {
        byte[] keyData = keyParams.getEncoded();

        int n = keyParams.getParameters().getTreeDigestSize();
        int totalHeight = keyParams.getParameters().getHeight();
        int indexSize = 4;
        int secretKeySize = n;
        int secretKeyPRFSize = n;
        int publicSeedSize = n;
        int rootSize = n;

        int position = 0;
        int index = (int)XMSSEngine.bytesToXBigEndian(keyData, position, indexSize);
        if (!XMSSEngine.isStoredIndexValid(totalHeight, index))
        {
            throw new IllegalArgumentException("index out of bounds");
        }
        position += indexSize;
        byte[] secretKeySeed = XMSSEngine.extractBytesAtOffset(keyData, position, secretKeySize);
        position += secretKeySize;
        byte[] secretKeyPRF = XMSSEngine.extractBytesAtOffset(keyData, position, secretKeyPRFSize);
        position += secretKeyPRFSize;
        byte[] publicSeed = XMSSEngine.extractBytesAtOffset(keyData, position, publicSeedSize);
        position += publicSeedSize;
        byte[] root = XMSSEngine.extractBytesAtOffset(keyData, position, rootSize);
        position += rootSize;
        /* import BDS state */
        byte[] bdsStateBinary = XMSSEngine.extractBytesAtOffset(keyData, position, keyData.length - position);
        BDS bds;
        try
        {
            bds = XMSSEngine.getBDSFromEncoding(bdsStateBinary, publicSeed);
        }
        catch (ClassNotFoundException e)
        {
            throw Exceptions.ioException("cannot parse BDS: " + e.getMessage(), e);
        }

        if ((bds.getMaxIndex() != (1 << totalHeight) - 1))
        {
            return new XMSSPrivateKey(index, secretKeySeed, secretKeyPRF, publicSeed, root, bdsStateBinary, bds.getMaxIndex());
        }

        return new XMSSPrivateKey(index, secretKeySeed, secretKeyPRF, publicSeed, root, bdsStateBinary);
    }

    private static XMSSMTPrivateKey xmssmtCreateKeyStructure(XMSSMTPrivateKeyParameters keyParams)
        throws IOException
    {
        byte[] keyData = keyParams.getEncoded();

        int n = keyParams.getParameters().getTreeDigestSize();
        int totalHeight = keyParams.getParameters().getHeight();
        int indexSize = (totalHeight + 7) / 8;
        int secretKeySize = n;
        int secretKeyPRFSize = n;
        int publicSeedSize = n;
        int rootSize = n;

        int position = 0;
        // read as a long: indexSize is up to eight bytes for a tree taller than 32, and the index
        // is a long the whole way through - XMSSMTPrivateKey carries one and isStoredIndexValid
        // takes one. Narrowing to int here truncated silently and did so *before* the bounds check,
        // so an out-of-range index was not rejected but wrapped into an in-range one, and the key
        // was then exported and re-imported at a position it had already signed from.
        long index = XMSSEngine.bytesToXBigEndian(keyData, position, indexSize);
        if (!XMSSEngine.isStoredIndexValid(totalHeight, index))
        {
            throw new IllegalArgumentException("index out of bounds");
        }
        position += indexSize;
        byte[] secretKeySeed = XMSSEngine.extractBytesAtOffset(keyData, position, secretKeySize);
        position += secretKeySize;
        byte[] secretKeyPRF = XMSSEngine.extractBytesAtOffset(keyData, position, secretKeyPRFSize);
        position += secretKeyPRFSize;
        byte[] publicSeed = XMSSEngine.extractBytesAtOffset(keyData, position, publicSeedSize);
        position += publicSeedSize;
        byte[] root = XMSSEngine.extractBytesAtOffset(keyData, position, rootSize);
        position += rootSize;
        /* import BDS state */
        byte[] bdsStateBinary = XMSSEngine.extractBytesAtOffset(keyData, position, keyData.length - position);
        BDSStateMap bds;
        try
        {
            bds = XMSSEngine.getBDSStateMapFromEncoding(bdsStateBinary, publicSeed);
        }
        catch (ClassNotFoundException e)
        {
            throw Exceptions.ioException("cannot parse BDSStateMap: " + e.getMessage(), e);
        }

        if ((bds.getMaxIndex() != (1L << totalHeight) - 1))
        {
            return new XMSSMTPrivateKey(index, secretKeySeed, secretKeyPRF, publicSeed, root, bdsStateBinary, bds.getMaxIndex());
        }

        return new XMSSMTPrivateKey(index, secretKeySeed, secretKeyPRF, publicSeed, root, bdsStateBinary);
    }
}
