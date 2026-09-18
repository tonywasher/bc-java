package org.bouncycastle.crypto.signers.lms;

import junit.framework.TestCase;
import org.bouncycastle.crypto.params.LMOtsParameters;
import org.bouncycastle.crypto.params.LMSParameters;
import org.bouncycastle.crypto.params.LMSPrivateKeyParameters;
import org.bouncycastle.crypto.params.LMSigParameters;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

/**
 * Tests of the LM-OTS one-time signature layer (RFC 8554 sec. 4), which is package-private.
 */
public class LMOtsTests
    extends TestCase
{
    public void testCoefFunc()
        throws Exception
    {
        byte[] S = Hex.decodeStrict("1234");
        TestCase.assertEquals(0, LM_OTS.coef(S, 7, 1));
        TestCase.assertEquals(1, LM_OTS.coef(S, 0, 4));
    }

    public void testPrivateKeyRound()
        throws Exception
    {
        LMOtsParameters parameter = LMOtsParameters.sha256_n32_w4;

        byte[] seed = Hex.decode("558b8966c48ae9cb898b423c83443aae014a72f1b1ab5cc85cf1d892903b5439");
        byte[] I = Hex.decode("d08fabd4a2091ff0a8cb4ed834e74534");

        LMOtsPrivateKey privateKey = new LMOtsPrivateKey(parameter, I, 0, seed);
        LMOtsPublicKey publicKey = privateKey.generatePublicKey();

        byte[] ms = new byte[32];
        for (int t = 0; t < ms.length; t++)
        {
            ms[t] = (byte)t;
        }

        LMSContext ctx = privateKey.getSignatureContext(null, null);

        ctx.update(ms, 0, ms.length);

        byte[] Q = new byte[parameter.getN() + 2];
        ctx.outputQ(Q, 0);

        LMOtsSignature sig = LM_OTS.lm_ots_generate_signature(privateKey, Q, ctx.getC());
        assertTrue(LM_OTS.lm_ots_validate_signature(publicKey, sig, ms, false));

        // Recreate signature
        {
            byte[] recreatedSignature = sig.getEncoded();
            assertTrue(LM_OTS.lm_ots_validate_signature(publicKey, LMOtsSignature.getInstance(recreatedSignature), ms, false));
        }

        // Recreate public key.
        {
            byte[] recreatedPubKey = Arrays.clone(publicKey.getEncoded());
            assertTrue(LM_OTS.lm_ots_validate_signature(LMOtsPublicKey.getInstance(recreatedPubKey), sig, ms, false));
        }

        // Vandalise signature
        {
            byte[] vandalisedSignature = sig.getEncoded();
            vandalisedSignature[256] ^= 1; // Single bit error
            assertFalse(LM_OTS.lm_ots_validate_signature(publicKey, LMOtsSignature.getInstance(vandalisedSignature), ms, false));
        }

        // Vandalise public key.
        {
            byte[] vandalisedPubKey = Arrays.clone(publicKey.getEncoded());
            vandalisedPubKey[50] ^= 1;
            assertFalse(LM_OTS.lm_ots_validate_signature(LMOtsPublicKey.getInstance(vandalisedPubKey), sig, ms, false));
        }


        //
        // check incorrect alg type is detected.
        //
        try
        {
            byte[] vandalisedPubKey = Arrays.clone(publicKey.getEncoded());
            vandalisedPubKey[3] += 1;
            LM_OTS.lm_ots_validate_signature(LMOtsPublicKey.getInstance(vandalisedPubKey), sig, ms, false);
            assertTrue("Must fail as public key type not match signature type.", false);
        }
        catch (LMSException ex)
        {
            assertTrue(ex.getMessage().contains("public key and signature ots types do not match"));
        }


    }

    public void testContextSingleUse()
        throws Exception
    {
        LMOtsParameters parameter = LMOtsParameters.sha256_n32_w4;

        byte[] seed = Hex.decode("558b8966c48ae9cb898b423c83443aae014a72f1b1ab5cc85cf1d892903b5439");
        byte[] I = Hex.decode("d08fabd4a2091ff0a8cb4ed834e74534");

        LMOtsPrivateKey privateKey = new LMOtsPrivateKey(parameter, I, 0, seed);
        LMOtsPublicKey publicKey = privateKey.generatePublicKey();

        byte[] ms = new byte[32];
        for (int t = 0; t < ms.length; t++)
        {
            ms[t] = (byte)t;
        }

        LMSContext ctx = privateKey.getSignatureContext(null, null);

        ctx.update(ms, 0, ms.length);

        byte[] Q = new byte[parameter.getN() + 2];
        ctx.outputQ(Q, 0);

        LMOtsSignature sig = LM_OTS.lm_ots_generate_signature(privateKey, Q, ctx.getC());
        assertTrue(LM_OTS.lm_ots_validate_signature(publicKey, sig, ms, false));

        try
        {
            ctx.update((byte)1);
            fail("Digest reuse after signature taken.");
        }
        catch (NullPointerException npe)
        {
            assertTrue(true);
        }

    }

    /**
     * The sixteen LM-OTS parameter sets against the tables of RFC 8554 sec. 4.1 (p and ls per n and w) and the
     * signature length that follows from them, then the lengths against real signatures. The n=24 sigLen values
     * were wrong in the hand-written table this replaced.
     */
    public void testOtsParameterTables()
        throws Exception
    {
        LMOtsParameters[] all =
        {
            LMOtsParameters.sha256_n32_w1, LMOtsParameters.sha256_n32_w2,
            LMOtsParameters.sha256_n32_w4, LMOtsParameters.sha256_n32_w8,
            LMOtsParameters.sha256_n24_w1, LMOtsParameters.sha256_n24_w2,
            LMOtsParameters.sha256_n24_w4, LMOtsParameters.sha256_n24_w8,
            LMOtsParameters.shake256_n32_w1, LMOtsParameters.shake256_n32_w2,
            LMOtsParameters.shake256_n32_w4, LMOtsParameters.shake256_n32_w8,
            LMOtsParameters.shake256_n24_w1, LMOtsParameters.shake256_n24_w2,
            LMOtsParameters.shake256_n24_w4, LMOtsParameters.shake256_n24_w8,
        };
        int[] ws = { 1, 2, 4, 8 };
        int[] p32 = { 265, 133, 67, 34 }, ls32 = { 7, 6, 4, 0 };
        int[] p24 = { 200, 101, 51, 26 }, ls24 = { 8, 6, 4, 0 };

        for (int i = 0; i < all.length; ++i)
        {
            LMOtsParameters ots = all[i];
            int col = i % 4;
            int n = (i / 4) % 2 == 0 ? 32 : 24;
            int p = n == 32 ? p32[col] : p24[col];
            int ls = n == 32 ? ls32[col] : ls24[col];
            String label = "LM-OTS type " + (i + 1);

            assertEquals(label, i + 1, ots.getType());
            assertEquals(label, n, ots.getN());
            assertEquals(label, ws[col], ots.getW());
            assertEquals(label, p, ots.getP());
            assertEquals(label, ls, ots.getLs());
            assertEquals(label, 4 + n + p * n, ots.getSigLen());
            assertSame(label, ots, LMOtsParameters.getParametersForType(i + 1));
        }

        // and against real signatures, one set per hash length and function
        LMSParameters[] samples =
        {
            LMSParameters.create(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w4),
            LMSParameters.create(LMSigParameters.lms_sha256_n24_h5, LMOtsParameters.sha256_n24_w4),
            LMSParameters.create(LMSigParameters.lms_shake256_n24_h5, LMOtsParameters.shake256_n24_w1),
        };
        byte[] seed = Hex.decode("558b8966c48ae9cb898b423c83443aae014a72f1b1ab5cc85cf1d892903b5439");
        byte[] I = Hex.decode("d08fabd4a2091ff0a8cb4ed834e74534");
        byte[] msg = Hex.decode("48656c6c6f");

        for (int i = 0; i < samples.length; ++i)
        {
            LMSigParameters sigParams = samples[i].getLMSigParam();
            LMOtsParameters otsParams = samples[i].getLMOTSParam();

            LMSPrivateKeyParameters key = new LMSPrivateKeyParameters(sigParams, otsParams, 0, I,
                1 << sigParams.getH(), seed);
            LMSContext ctx = key.generateLMSContext();
            ctx.update(msg, 0, msg.length);
            LMSSignature sig = LMSEngine.generateSign(ctx);

            assertEquals("LM-OTS type " + otsParams.getType(), otsParams.getSigLen(),
                sig.getOtsSignature().getEncoded().length);

            // the LMS signature adds u32str(q), u32str(type) and the h path nodes (RFC 8554 sec. 5.4)
            assertEquals("LMS type " + sigParams.getType(), 4 + otsParams.getSigLen() + 4 + sigParams.getH() * sigParams.getM(),
                sig.getEncoded().length);
        }
    }
}
