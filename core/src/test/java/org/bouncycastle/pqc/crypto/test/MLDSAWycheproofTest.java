package org.bouncycastle.pqc.crypto.test;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import junit.framework.TestCase;
import org.bouncycastle.crypto.params.MLDSAParameters;
import org.bouncycastle.crypto.params.MLDSAPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithContext;
import org.bouncycastle.crypto.signers.MLDSASigner;
import org.bouncycastle.test.TestResourceFinder;
import org.bouncycastle.util.encoders.Hex;

/**
 * ML-DSA signature verification against the Project Wycheproof vectors in
 * crypto/wycheproof/mldsa_&lt;n&gt;_verify_test.json.
 * <p>
 * These complement the ACVP and NIST KAT batteries driven from {@link MLDSATest}: where those
 * confirm the specified paths, the majority of these cases are invalid by construction - signatures
 * violating the infinity norm bound, malformed hint encodings, wrong-length keys and signatures,
 * zero public keys and out-of-range contexts - and the point of them is that verification says no.
 * <p>
 * A verifier is allowed to reject at any stage, so a case the file marks invalid passes here
 * whether the key is refused when it is constructed, the signer refuses it at init, or verification
 * returns false. A case marked valid has to construct, initialise and verify cleanly.
 */
public class MLDSAWycheproofTest
    extends TestCase
{
    private static final String VECTOR_HOME = "crypto/wycheproof";

    public void testMLDSA44Verify()
        throws Exception
    {
        doVerifyTest("mldsa_44_verify_test.json", MLDSAParameters.ml_dsa_44, 180, 77, 103);
    }

    public void testMLDSA65Verify()
        throws Exception
    {
        doVerifyTest("mldsa_65_verify_test.json", MLDSAParameters.ml_dsa_65, 210, 79, 131);
    }

    public void testMLDSA87Verify()
        throws Exception
    {
        doVerifyTest("mldsa_87_verify_test.json", MLDSAParameters.ml_dsa_87, 241, 71, 170);
    }

    /**
     * The expected counts are asserted so that a vector file swapped underneath the suite - upstream
     * revises these - shows up as a count mismatch rather than as silently reduced coverage.
     */
    private void doVerifyTest(String fileName, MLDSAParameters parameters, int expectedTests, int expectedValid, int expectedInvalid)
        throws Exception
    {
        InputStream src = TestResourceFinder.findTestResource(VECTOR_HOME, fileName);
        Map root;
        try
        {
            root = JsonParser.parseObject(src);
        }
        finally
        {
            src.close();
        }

        assertEquals(fileName + ": algorithm", parameters.getName().toUpperCase(), (String)root.get("algorithm"));

        List failures = new ArrayList();
        Map flagCounts = new TreeMap();
        int valid = 0;
        int invalid = 0;

        List groups = (List)root.get("testGroups");
        for (Iterator git = groups.iterator(); git.hasNext(); )
        {
            Map group = (Map)git.next();

            byte[] publicKey = Hex.decode((String)group.get("publicKey"));

            // a wrong-length or otherwise unusable key is refused here, which is a rejection of
            // every case in the group rather than an error in the run.
            MLDSAPublicKeyParameters pubParams = null;
            String keyFailure = null;
            try
            {
                pubParams = new MLDSAPublicKeyParameters(parameters, publicKey);
            }
            catch (Exception e)
            {
                keyFailure = describe(e);
            }

            List tests = (List)group.get("tests");
            for (Iterator tit = tests.iterator(); tit.hasNext(); )
            {
                Map test = (Map)tit.next();

                int tcId = ((Integer)test.get("tcId")).intValue();
                boolean expectedValidCase = "valid".equals(test.get("result"));

                if (expectedValidCase)
                {
                    valid++;
                }
                else
                {
                    invalid++;
                }

                countFlags(flagCounts, (List)test.get("flags"));

                String rejection;
                if (keyFailure != null)
                {
                    rejection = "public key rejected: " + keyFailure;
                }
                else
                {
                    rejection = verify(pubParams, test);
                }

                if (expectedValidCase == (rejection == null))
                {
                    continue;
                }

                failures.add("tcId " + tcId + " (" + test.get("comment") + ", flags " + test.get("flags") + "): expected "
                    + test.get("result") + ", got " + (rejection == null ? "accepted" : "rejected - " + rejection));
            }
        }

        assertEquals(fileName + ": total cases", expectedTests, valid + invalid);
        assertEquals(fileName + ": valid cases", expectedValid, valid);
        assertEquals(fileName + ": invalid cases", expectedInvalid, invalid);

        if (!failures.isEmpty())
        {
            StringBuffer message = new StringBuffer(fileName + ": " + failures.size() + " of " + (valid + invalid)
                + " cases disagreed with the vectors (flags present: " + flagCounts + ")");
            for (Iterator it = failures.iterator(); it.hasNext(); )
            {
                message.append("\n    ").append(it.next());
            }
            fail(message.toString());
        }
    }

    /**
     * @return null when the signature verified, otherwise why it did not.
     */
    private String verify(MLDSAPublicKeyParameters pubParams, Map test)
    {
        byte[] msg = Hex.decode((String)test.get("msg"));
        byte[] sig = Hex.decode((String)test.get("sig"));
        String ctx = (String)test.get("ctx");

        MLDSASigner signer = new MLDSASigner();

        try
        {
            if (ctx != null)
            {
                signer.init(false, new ParametersWithContext(pubParams, Hex.decode(ctx)));
            }
            else
            {
                signer.init(false, pubParams);
            }
        }
        catch (Exception e)
        {
            return "init: " + describe(e);
        }

        try
        {
            signer.update(msg, 0, msg.length);

            return signer.verifySignature(sig) ? null : "verification returned false";
        }
        catch (Exception e)
        {
            return "verify: " + describe(e);
        }
    }

    private static void countFlags(Map flagCounts, List flags)
    {
        if (flags == null)
        {
            return;
        }

        for (Iterator it = flags.iterator(); it.hasNext(); )
        {
            String flag = (String)it.next();
            Integer count = (Integer)flagCounts.get(flag);

            flagCounts.put(flag, count == null ? new Integer(1) : new Integer(count.intValue() + 1));
        }
    }

    private static String describe(Exception e)
    {
        return e.getClass().getName() + (e.getMessage() == null ? "" : ": " + e.getMessage());
    }
}
