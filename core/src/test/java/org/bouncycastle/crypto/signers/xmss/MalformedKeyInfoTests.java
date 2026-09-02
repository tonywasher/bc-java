package org.bouncycastle.crypto.signers.xmss;

import java.io.IOException;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.iana.IANAObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
import org.bouncycastle.pqc.asn1.XMSSKeyParams;
import org.bouncycastle.pqc.asn1.XMSSMTKeyParams;
import org.bouncycastle.pqc.asn1.XMSSPrivateKey;
import org.bouncycastle.pqc.asn1.XMSSPublicKey;

/**
 * The key factories are declared {@code throws IOException}, and a key that will not decode is what
 * that is for. Their XMSS half read the ASN.1 in stages, and only the last stage - building the
 * parameter set - was inside the try: an algorithm identifier carrying the wrong parameters, or
 * none at all, was decoded before it, so it came back out as an unchecked exception through a
 * method whose signature says a bad key is reported. A caller that wrapped the call in
 * {@code catch (IOException)}, which is the whole contract, did not catch it.
 * <p>
 * The cause is kept as well: the factory's own message says which key it was, and getCause() says
 * what was wrong with it.
 * </p>
 */
public class MalformedKeyInfoTests
    extends TestCase
{
    private static final AlgorithmIdentifier TREE_DIGEST =
        new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);

    private static XMSSPrivateKey privateKeyBody()
    {
        return new XMSSPrivateKey(0, new byte[32], new byte[32], new byte[32], new byte[32], null);
    }

    /**
     * An XMSS OID with no algorithm parameters at all. Reading the tree digest off the absent
     * XMSSKeyParams was a NullPointerException; the XMSS^MT twin was the same.
     */
    public void testPrivateKeyWithNoParameters()
        throws Exception
    {
        try
        {
            PrivateKeyFactory.createKey(new PrivateKeyInfo(
                new AlgorithmIdentifier(PQCObjectIdentifiers.xmss), privateKeyBody()));
            fail("XMSS private key with absent parameters accepted");
        }
        catch (IOException e)
        {
            assertEquals("no parameters found in XMSS private key", e.getMessage());
        }

        try
        {
            PrivateKeyFactory.createKey(new PrivateKeyInfo(
                new AlgorithmIdentifier(PQCObjectIdentifiers.xmss_mt), privateKeyBody()));
            fail("XMSS^MT private key with absent parameters accepted");
        }
        catch (IOException e)
        {
            assertEquals("no parameters found in XMSS^MT private key", e.getMessage());
        }
    }

    /**
     * An XMSS OID whose parameters are present but are not an XMSSKeyParams: the getInstance that
     * rejects them ran ahead of the try.
     */
    public void testKeyWithParametersOfTheWrongShape()
        throws Exception
    {
        AlgorithmIdentifier xmss = new AlgorithmIdentifier(PQCObjectIdentifiers.xmss, new ASN1Integer(1));
        AlgorithmIdentifier xmssMt = new AlgorithmIdentifier(PQCObjectIdentifiers.xmss_mt, new ASN1Integer(1));

        try
        {
            PublicKeyFactory.createKey(new SubjectPublicKeyInfo(xmss,
                new XMSSPublicKey(new byte[32], new byte[32])));
            fail("XMSS public key with non-XMSSKeyParams parameters accepted");
        }
        catch (IOException e)
        {
            assertTrue(e.getMessage(), e.getMessage().startsWith("malformed XMSS public key: "));
            assertNotNull("the cause of a malformed key is kept", e.getCause());
        }

        try
        {
            PublicKeyFactory.createKey(new SubjectPublicKeyInfo(xmssMt,
                new XMSSPublicKey(new byte[32], new byte[32])));
            fail("XMSS^MT public key with non-XMSSMTKeyParams parameters accepted");
        }
        catch (IOException e)
        {
            assertTrue(e.getMessage(), e.getMessage().startsWith("malformed XMSS^MT public key: "));
            assertNotNull(e.getCause());
        }

        try
        {
            PrivateKeyFactory.createKey(new PrivateKeyInfo(xmss, privateKeyBody()));
            fail("XMSS private key with non-XMSSKeyParams parameters accepted");
        }
        catch (IOException e)
        {
            assertTrue(e.getMessage(), e.getMessage().startsWith("malformed XMSS private key: "));
            assertNotNull(e.getCause());
        }

        try
        {
            PrivateKeyFactory.createKey(new PrivateKeyInfo(xmssMt, privateKeyBody()));
            fail("XMSS^MT private key with non-XMSSMTKeyParams parameters accepted");
        }
        catch (IOException e)
        {
            assertTrue(e.getMessage(), e.getMessage().startsWith("malformed XMSS^MT private key: "));
            assertNotNull(e.getCause());
        }
    }

    /**
     * Well-formed parameters, but a key body that is not the structure they call for - the second
     * getInstance, which also ran ahead of the try.
     */
    public void testKeyWithBodyOfTheWrongShape()
        throws Exception
    {
        AlgorithmIdentifier xmss = new AlgorithmIdentifier(PQCObjectIdentifiers.xmss,
            new XMSSKeyParams(4, TREE_DIGEST));
        AlgorithmIdentifier xmssMt = new AlgorithmIdentifier(PQCObjectIdentifiers.xmss_mt,
            new XMSSMTKeyParams(4, 2, TREE_DIGEST));

        try
        {
            PublicKeyFactory.createKey(new SubjectPublicKeyInfo(xmss, new ASN1Integer(1)));
            fail("XMSS public key with a non-XMSSPublicKey body accepted");
        }
        catch (IOException e)
        {
            assertTrue(e.getMessage(), e.getMessage().startsWith("malformed XMSS public key: "));
            assertNotNull(e.getCause());
        }

        try
        {
            PublicKeyFactory.createKey(new SubjectPublicKeyInfo(xmssMt, new ASN1Integer(1)));
            fail("XMSS^MT public key with a non-XMSSPublicKey body accepted");
        }
        catch (IOException e)
        {
            assertTrue(e.getMessage(), e.getMessage().startsWith("malformed XMSS^MT public key: "));
            assertNotNull(e.getCause());
        }

        try
        {
            PrivateKeyFactory.createKey(new PrivateKeyInfo(xmss, new ASN1Integer(1)));
            fail("XMSS private key with a non-XMSSPrivateKey body accepted");
        }
        catch (IOException e)
        {
            assertTrue(e.getMessage(), e.getMessage().startsWith("malformed XMSS private key: "));
            assertNotNull(e.getCause());
        }

        try
        {
            PrivateKeyFactory.createKey(new PrivateKeyInfo(xmssMt, new ASN1Integer(1)));
            fail("XMSS^MT private key with a non-XMSSMTPrivateKey body accepted");
        }
        catch (IOException e)
        {
            assertTrue(e.getMessage(), e.getMessage().startsWith("malformed XMSS^MT private key: "));
            assertNotNull(e.getCause());
        }
    }

    /**
     * The RFC 9802 form, whose octets are a parameter-set OID and a raw key: the OCTET STRING is
     * pulled out ahead of the try there too.
     */
    public void testRfc9802KeyWithBodyOfTheWrongShape()
        throws Exception
    {
        AlgorithmIdentifier xmss = new AlgorithmIdentifier(IANAObjectIdentifiers.id_alg_xmss_hashsig);
        AlgorithmIdentifier xmssMt = new AlgorithmIdentifier(IANAObjectIdentifiers.id_alg_xmssmt_hashsig);

        try
        {
            PrivateKeyFactory.createKey(new PrivateKeyInfo(xmss, new ASN1Integer(1)));
            fail("RFC 9802 XMSS private key with a non-OCTET STRING body accepted");
        }
        catch (IOException e)
        {
            assertTrue(e.getMessage(), e.getMessage().startsWith("malformed XMSS private key: "));
            assertNotNull(e.getCause());
        }

        try
        {
            PrivateKeyFactory.createKey(new PrivateKeyInfo(xmssMt, new ASN1Integer(1)));
            fail("RFC 9802 XMSS^MT private key with a non-OCTET STRING body accepted");
        }
        catch (IOException e)
        {
            assertTrue(e.getMessage(), e.getMessage().startsWith("malformed XMSS^MT private key: "));
            assertNotNull(e.getCause());
        }

        // and the length and OID checks below them, which report without a cause to keep
        try
        {
            PrivateKeyFactory.createKey(new PrivateKeyInfo(xmssMt, new DEROctetString(new byte[3])));
            fail("RFC 9802 XMSS^MT private key shorter than its parameter-set OID accepted");
        }
        catch (IOException e)
        {
            assertEquals("XMSS^MT private key data too short", e.getMessage());
        }

        try
        {
            PrivateKeyFactory.createKey(new PrivateKeyInfo(xmssMt,
                new DEROctetString(new byte[]{0x7f, (byte)0xff, (byte)0xff, (byte)0xff, 0x00})));
            fail("RFC 9802 XMSS^MT private key with an unregistered parameter set accepted");
        }
        catch (IOException e)
        {
            assertTrue(e.getMessage(), e.getMessage().startsWith("unknown XMSS^MT private key OID: "));
        }
    }
}
