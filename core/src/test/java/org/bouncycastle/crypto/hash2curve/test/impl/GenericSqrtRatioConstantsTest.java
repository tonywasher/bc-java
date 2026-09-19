package org.bouncycastle.crypto.hash2curve.test.impl;

import java.lang.reflect.Field;
import java.math.BigInteger;
import java.util.Random;

import junit.framework.TestCase;

import org.bouncycastle.crypto.hash2curve.impl.GenericSqrtRatioCalculator;
import org.bouncycastle.crypto.hash2curve.impl.SqrtRatio;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.custom.sec.SecP256R1Curve;
import org.bouncycastle.math.ec.custom.sec.SecP384R1Curve;
import org.bouncycastle.math.ec.custom.sec.SecP521R1Curve;

public class GenericSqrtRatioConstantsTest
    extends TestCase
{
    public void testConstantsMatchDirectPowersForSmallFields()
        throws Exception
    {
        // Includes c3 == 0 (3, 5, 17, 257) and several two-adic valuations of q - 1.
        int[] primes = { 3, 5, 7, 13, 17, 29, 97, 257 };
        for (int i = 0; i < primes.length; ++i)
        {
            int p = primes[i];
            ECCurve curve = smallCurve(BigInteger.valueOf(p));
            for (int z = -2 * p; z <= 2 * p; ++z)
            {
                checkConstants(curve, BigInteger.valueOf(z));
            }
        }
    }

    public void testConstantsMatchDirectPowersForLargeFields()
        throws Exception
    {
        ECCurve[] curves = {
            new SecP256R1Curve(), new SecP384R1Curve(), new SecP521R1Curve(),
            smallCurve(BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19))),
            smallCurve(BigInteger.ONE.shiftLeft(448).subtract(BigInteger.ONE.shiftLeft(224)).subtract(BigInteger.ONE))
        };
        Random random = new Random(9380L);
        for (int i = 0; i < curves.length; ++i)
        {
            BigInteger q = curves[i].getField().getCharacteristic();
            BigInteger[] edges = {
                BigInteger.ZERO, BigInteger.ONE, BigInteger.ONE.negate(),
                BigInteger.valueOf(-10), q.subtract(BigInteger.ONE), q,
                q.add(BigInteger.ONE), q.shiftLeft(1).add(BigInteger.valueOf(3))
            };
            for (int j = 0; j < edges.length; ++j)
            {
                checkConstants(curves[i], edges[j]);
            }
            for (int j = 0; j < 16; ++j)
            {
                BigInteger z = new BigInteger(2 * q.bitLength(), random);
                checkConstants(curves[i], (j & 1) == 0 ? z : z.negate());
            }
        }
    }

    public void testRepeatedRatiosOverSmallFields()
    {
        int[] primes = { 3, 5, 7, 13, 17, 29 };
        for (int i = 0; i < primes.length; ++i)
        {
            BigInteger q = BigInteger.valueOf(primes[i]);
            BigInteger half = q.subtract(BigInteger.ONE).shiftRight(1);
            BigInteger z = BigInteger.valueOf(2);
            while (z.modPow(half, q).equals(BigInteger.ONE))
            {
                z = z.add(BigInteger.ONE);
            }
            GenericSqrtRatioCalculator calculator = new GenericSqrtRatioCalculator(smallCurve(q), z);
            for (int u = 1; u < primes[i]; ++u)
            {
                for (int v = 1; v < primes[i]; ++v)
                {
                    BigInteger numerator = BigInteger.valueOf(u);
                    BigInteger denominator = BigInteger.valueOf(v);
                    boolean square = numerator.multiply(denominator.modInverse(q)).mod(q)
                        .modPow(half, q).equals(BigInteger.ONE);
                    SqrtRatio result = calculator.sqrtRatio(numerator, denominator);
                    assertEquals("quadratic-residue flag", square, result.isQR());
                    BigInteger expected = square ? numerator : numerator.multiply(z).mod(q);
                    assertEquals("square-root equation", expected,
                        result.getRatio().multiply(result.getRatio()).multiply(denominator).mod(q));
                }
            }
        }
    }

    private static ECCurve smallCurve(BigInteger q)
    {
        // Fixed, known primes only. No point arithmetic is needed for these constant tests.
        return new ECCurve.Fp(q, BigInteger.ONE, BigInteger.ONE, null, null, true);
    }

    private static void checkConstants(ECCurve curve, BigInteger z)
        throws Exception
    {
        BigInteger q = curve.getField().getCharacteristic();
        BigInteger oddPart = q.subtract(BigInteger.ONE);
        oddPart = oddPart.shiftRight(oddPart.getLowestSetBit());
        GenericSqrtRatioCalculator calculator = new GenericSqrtRatioCalculator(curve, z);
        // Compare the actual stored constants, not a separate implementation of the rewrite.
        assertEquals("c6 for q=" + q + ", z=" + z,
            z.modPow(oddPart, q), constant(calculator, "c6"));
        assertEquals("c7 for q=" + q + ", z=" + z,
            z.modPow(oddPart.add(BigInteger.ONE).shiftRight(1), q), constant(calculator, "c7"));
    }

    private static BigInteger constant(GenericSqrtRatioCalculator calculator, String name)
        throws Exception
    {
        Field field = GenericSqrtRatioCalculator.class.getDeclaredField(name);
        field.setAccessible(true);
        return (BigInteger)field.get(calculator);
    }
}
