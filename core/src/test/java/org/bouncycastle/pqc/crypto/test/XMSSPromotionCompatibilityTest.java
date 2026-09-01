package org.bouncycastle.pqc.crypto.test;

import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.test.FixedSecureRandom;

/**
 * The XMSS / XMSS^MT implementation under org.bouncycastle.crypto is a copy of the deprecated
 * org.bouncycastle.pqc.crypto.xmss one, so the two must agree byte for byte on every encoding and
 * each must verify what the other signed. This test pins that down over the parameter-set matrix,
 * and is the guard against the copy drifting from the original while both ship.
 */
public class XMSSPromotionCompatibilityTest
    extends TestCase
{
    private static final byte[] MESSAGE = Strings.toByteArray("the quick brown fox jumped over the lazy dog");

    /**
     * The same seed drives both implementations, so a matching pair of keys must come out with
     * identical X.509 / PKCS#8 encodings, and each side must verify the other's signature. The
     * tree height is kept small: it does not change any encoding rule, only how long the tree
     * takes to build.
     */
    public void testXMSSKeysAndSignaturesMatchAcrossImplementations()
        throws Exception
    {
        for (int i = 0; i != 4; i++)
        {
            checkXMSS("h4/" + i, newXmssParams(4, i), oldXmssParams(4, i), seedFor(i));
        }

        // The matrix stops at the four RFC 8391 tree digests with their natural n. A tree height
        // outside the standard sets has no parameter-set OID, so its key is written in the legacy
        // PQCObjectIdentifiers.xmss form, whose XMSSKeyParams carries the height and the tree
        // digest OID but not n - neither implementation can express an SP 800-208 n that way, and
        // both have always failed on it. Those sets are all standard heights and are covered by
        // testStandardParameterSetEncodingMatches below, which exercises the RFC 9802 branch.
    }

    /**
     * A standard RFC 8391 parameter set, which is encoded in the RFC 9802 form (id-alg-xmss-hashsig
     * with the 4-octet parameter-set OID ahead of the raw key) rather than the legacy
     * XMSSKeyParams one - a different branch of both key factories. The smallest standard XMSS^MT
     * set is 20/2, too slow to build here; the provider tests cover that side.
     */
    public void testStandardParameterSetEncodingMatches()
        throws Exception
    {
        checkXMSS("XMSS-SHA2_10_256",
            new org.bouncycastle.crypto.params.XMSSParameters(10, new SHA256Digest()),
            new org.bouncycastle.pqc.crypto.xmss.XMSSParameters(10, new SHA256Digest()),
            seedFor(10));

        // XMSS_SHAKE256_10_192, an SP 800-208 set: SHAKE256 truncated to n = 24, named by
        // id-shake256-len rather than by one of the four RFC 8391 tree digests
        checkXMSS("XMSS-SHAKE256_10_192",
            new org.bouncycastle.crypto.params.XMSSParameters(10, NISTObjectIdentifiers.id_shake256_len, 24),
            new org.bouncycastle.pqc.crypto.xmss.XMSSParameters(10, NISTObjectIdentifiers.id_shake256_len, 24),
            seedFor(11));
    }

    public void testXMSSMTKeysAndSignaturesMatchAcrossImplementations()
        throws Exception
    {
        for (int i = 0; i != 4; i++)
        {
            checkXMSSMT("h4d2/" + i, newXmssMtParams(4, 2, i), oldXmssMtParams(4, 2, i), seedFor(20 + i));
        }
    }

    /**
     * The promoted signers implement org.bouncycastle.crypto.Signer rather than the pqc
     * StateAwareMessageSigner, so a message streamed in through update() must sign and verify, and
     * the buffer must be consumed by each operation rather than carried into the next. That the
     * streamed signature is byte-identical to the deprecated signer's one-shot output is asserted
     * by checkXMSS / checkXMSSMT below.
     */
    public void testStreamingRoundTrip()
        throws Exception
    {
        org.bouncycastle.crypto.params.XMSSParameters params =
            new org.bouncycastle.crypto.params.XMSSParameters(4, new SHA256Digest());

        org.bouncycastle.crypto.generators.XMSSKeyPairGenerator gen =
            new org.bouncycastle.crypto.generators.XMSSKeyPairGenerator();
        gen.init(new org.bouncycastle.crypto.params.XMSSKeyGenerationParameters(params, fixedRandom(seedFor(7))));
        AsymmetricCipherKeyPair kp = gen.generateKeyPair();

        org.bouncycastle.crypto.signers.XMSSSigner signer = new org.bouncycastle.crypto.signers.XMSSSigner();
        signer.init(true, kp.getPrivate());
        signer.update(MESSAGE, 0, MESSAGE.length);
        byte[] streamed = signer.generateSignature();

        org.bouncycastle.crypto.signers.XMSSSigner verifier = new org.bouncycastle.crypto.signers.XMSSSigner();
        verifier.init(false, kp.getPublic());
        verifier.update(MESSAGE, 0, MESSAGE.length);
        assertTrue("streamed signature did not verify through the streaming path",
            verifier.verifySignature(streamed));

        // verifySignature() consumed the buffer, so feeding the same message again verifies the
        // message alone and not the message twice
        verifier.init(false, kp.getPublic());
        verifier.update(MESSAGE, 0, MESSAGE.length);
        assertTrue("second streamed verification failed", verifier.verifySignature(streamed));
    }

    private void checkXMSS(String label,
                           org.bouncycastle.crypto.params.XMSSParameters newParams,
                           org.bouncycastle.pqc.crypto.xmss.XMSSParameters oldParams,
                           byte[] seed)
        throws Exception
    {
        org.bouncycastle.crypto.generators.XMSSKeyPairGenerator newGen =
            new org.bouncycastle.crypto.generators.XMSSKeyPairGenerator();
        newGen.init(new org.bouncycastle.crypto.params.XMSSKeyGenerationParameters(newParams, fixedRandom(seed)));
        AsymmetricCipherKeyPair newKp = newGen.generateKeyPair();

        org.bouncycastle.pqc.crypto.xmss.XMSSKeyPairGenerator oldGen =
            new org.bouncycastle.pqc.crypto.xmss.XMSSKeyPairGenerator();
        oldGen.init(new org.bouncycastle.pqc.crypto.xmss.XMSSKeyGenerationParameters(oldParams, fixedRandom(seed)));
        AsymmetricCipherKeyPair oldKp = oldGen.generateKeyPair();

        compareEncodings(label, newKp, oldKp);

        org.bouncycastle.crypto.signers.XMSSSigner newSigner = new org.bouncycastle.crypto.signers.XMSSSigner();
        newSigner.init(true, newKp.getPrivate());
        newSigner.update(MESSAGE, 0, MESSAGE.length);
        byte[] newSig = newSigner.generateSignature();

        org.bouncycastle.pqc.crypto.xmss.XMSSSigner oldSigner = new org.bouncycastle.pqc.crypto.xmss.XMSSSigner();
        oldSigner.init(true, oldKp.getPrivate());
        byte[] oldSig = oldSigner.generateSignature(MESSAGE);

        assertTrue(label + ": signatures differ", Arrays.areEqual(newSig, oldSig));

        org.bouncycastle.crypto.signers.XMSSSigner newVerifier = new org.bouncycastle.crypto.signers.XMSSSigner();
        newVerifier.init(false, newKp.getPublic());
        newVerifier.update(MESSAGE, 0, MESSAGE.length);
        assertTrue(label + ": promoted verifier rejected the deprecated signature",
            newVerifier.verifySignature(oldSig));

        org.bouncycastle.pqc.crypto.xmss.XMSSSigner oldVerifier = new org.bouncycastle.pqc.crypto.xmss.XMSSSigner();
        oldVerifier.init(false, oldKp.getPublic());
        assertTrue(label + ": deprecated verifier rejected the promoted signature",
            oldVerifier.verifySignature(MESSAGE, newSig));
    }

    private void checkXMSSMT(String label,
                             org.bouncycastle.crypto.params.XMSSMTParameters newParams,
                             org.bouncycastle.pqc.crypto.xmss.XMSSMTParameters oldParams,
                             byte[] seed)
        throws Exception
    {
        org.bouncycastle.crypto.generators.XMSSMTKeyPairGenerator newGen =
            new org.bouncycastle.crypto.generators.XMSSMTKeyPairGenerator();
        newGen.init(new org.bouncycastle.crypto.params.XMSSMTKeyGenerationParameters(newParams, fixedRandom(seed)));
        AsymmetricCipherKeyPair newKp = newGen.generateKeyPair();

        org.bouncycastle.pqc.crypto.xmss.XMSSMTKeyPairGenerator oldGen =
            new org.bouncycastle.pqc.crypto.xmss.XMSSMTKeyPairGenerator();
        oldGen.init(new org.bouncycastle.pqc.crypto.xmss.XMSSMTKeyGenerationParameters(oldParams, fixedRandom(seed)));
        AsymmetricCipherKeyPair oldKp = oldGen.generateKeyPair();

        compareEncodings(label, newKp, oldKp);

        org.bouncycastle.crypto.signers.XMSSMTSigner newSigner = new org.bouncycastle.crypto.signers.XMSSMTSigner();
        newSigner.init(true, newKp.getPrivate());
        newSigner.update(MESSAGE, 0, MESSAGE.length);
        byte[] newSig = newSigner.generateSignature();

        org.bouncycastle.pqc.crypto.xmss.XMSSMTSigner oldSigner = new org.bouncycastle.pqc.crypto.xmss.XMSSMTSigner();
        oldSigner.init(true, oldKp.getPrivate());
        byte[] oldSig = oldSigner.generateSignature(MESSAGE);

        assertTrue(label + ": signatures differ", Arrays.areEqual(newSig, oldSig));

        org.bouncycastle.crypto.signers.XMSSMTSigner newVerifier = new org.bouncycastle.crypto.signers.XMSSMTSigner();
        newVerifier.init(false, newKp.getPublic());
        newVerifier.update(MESSAGE, 0, MESSAGE.length);
        assertTrue(label + ": promoted verifier rejected the deprecated signature",
            newVerifier.verifySignature(oldSig));

        org.bouncycastle.pqc.crypto.xmss.XMSSMTSigner oldVerifier = new org.bouncycastle.pqc.crypto.xmss.XMSSMTSigner();
        oldVerifier.init(false, oldKp.getPublic());
        assertTrue(label + ": deprecated verifier rejected the promoted signature",
            oldVerifier.verifySignature(MESSAGE, newSig));
    }

    private void compareEncodings(String label, AsymmetricCipherKeyPair newKp, AsymmetricCipherKeyPair oldKp)
        throws Exception
    {
        byte[] newPub = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(newKp.getPublic()).getEncoded();
        byte[] oldPub = org.bouncycastle.pqc.crypto.util.SubjectPublicKeyInfoFactory
            .createSubjectPublicKeyInfo(oldKp.getPublic()).getEncoded();
        assertTrue(label + ": public key encodings differ", Arrays.areEqual(newPub, oldPub));

        byte[] newPriv = PrivateKeyInfoFactory.createPrivateKeyInfo(newKp.getPrivate()).getEncoded();
        byte[] oldPriv = org.bouncycastle.pqc.crypto.util.PrivateKeyInfoFactory
            .createPrivateKeyInfo(oldKp.getPrivate()).getEncoded();
        assertTrue(label + ": private key encodings differ", Arrays.areEqual(newPriv, oldPriv));

        // each side's key factory must accept the other side's encoding
        assertNotNull(label + ": promoted factory rejected the deprecated public key",
            PublicKeyFactory.createKey(oldPub));
        assertNotNull(label + ": promoted factory rejected the deprecated private key",
            PrivateKeyFactory.createKey(oldPriv));
        assertNotNull(label + ": deprecated factory rejected the promoted public key",
            org.bouncycastle.pqc.crypto.util.PublicKeyFactory.createKey(newPub));
        assertNotNull(label + ": deprecated factory rejected the promoted private key",
            org.bouncycastle.pqc.crypto.util.PrivateKeyFactory.createKey(newPriv));
    }

    private static org.bouncycastle.crypto.params.XMSSParameters newXmssParams(int height, int digest)
    {
        return new org.bouncycastle.crypto.params.XMSSParameters(height, digest(digest));
    }

    private static org.bouncycastle.pqc.crypto.xmss.XMSSParameters oldXmssParams(int height, int digest)
    {
        return new org.bouncycastle.pqc.crypto.xmss.XMSSParameters(height, digest(digest));
    }

    private static org.bouncycastle.crypto.params.XMSSMTParameters newXmssMtParams(int height, int layers, int digest)
    {
        return new org.bouncycastle.crypto.params.XMSSMTParameters(height, layers, digest(digest));
    }

    private static org.bouncycastle.pqc.crypto.xmss.XMSSMTParameters oldXmssMtParams(int height, int layers, int digest)
    {
        return new org.bouncycastle.pqc.crypto.xmss.XMSSMTParameters(height, layers, digest(digest));
    }

    private static Digest digest(int n)
    {
        switch (n)
        {
        case 0:
            return new SHA256Digest();
        case 1:
            return new SHAKEDigest(128);
        case 2:
            return new SHA512Digest();
        default:
            return new SHAKEDigest(256);
        }
    }

    private static byte[] seedFor(int n)
    {
        byte[] seed = new byte[64];
        for (int i = 0; i != seed.length; i++)
        {
            seed[i] = (byte)(n * 31 + i);
        }
        return seed;
    }

    private static SecureRandom fixedRandom(byte[] seed)
    {
        // key generation reads three tree-digest-sized blocks (3 * 64 at the largest parameter set)
        byte[] material = new byte[6 * seed.length];
        for (int i = 0; i != 6; i++)
        {
            System.arraycopy(seed, 0, material, i * seed.length, seed.length);
        }

        return new FixedSecureRandom(new FixedSecureRandom.Source[]{ new FixedSecureRandom.Data(material) });
    }
}
