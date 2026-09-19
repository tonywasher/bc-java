package org.bouncycastle.crypto.params;

import java.security.SecureRandom;

import org.bouncycastle.crypto.KeyGenerationParameters;

public class HSSKeyGenerationParameters
    extends KeyGenerationParameters
{
    private static LMSParameters[] validateParameters(LMSParameters[] lmsParameters)
    {
        if (lmsParameters == null)
        {
            throw new NullPointerException("lmsParameters cannot be null");
        }
        if (lmsParameters.length < 1 || lmsParameters.length > 8)  // RFC 8554, Section 6.
        {
            throw new IllegalArgumentException("lmsParameters length should be between 1 and 8 inclusive");
        }

        // copy before checking the elements, so what was validated is what is kept
        LMSParameters[] copy = (LMSParameters[])lmsParameters.clone();

        for (int i = 0; i < copy.length; ++i)
        {
            if (copy[i] == null)
            {
                throw new NullPointerException("HSS level " + i + " has no parameters");
            }

            // TODO Consider the SP 800-208 sec. 4 restrictions: one hash function within each level (LMS tree and
            // LM-OTS keys) and across the hierarchy. bc-csharp enforces both here; it is unclear what BC was aiming
            // for, since the RFC 8554 parameter sets allow mixing.
        }

        return copy;
    }

    private final LMSParameters[] lmsParameters;

    /**
     * Base constructor - parameters and a source of randomness.
     *
     * @param lmsParameters array of LMS parameters, one per level in the hierarchy (up to 8 levels).
     * @param random   the random byte source.
     */
    public HSSKeyGenerationParameters(
        LMSParameters[] lmsParameters,
        SecureRandom random)
    {
        this(random, validateParameters(lmsParameters));
    }

    private HSSKeyGenerationParameters(SecureRandom random, LMSParameters[] lmsParameters)
    {
        super(random, LMSParameters.calculateStrength(lmsParameters[0]));
        this.lmsParameters = lmsParameters;
    }

    public int getDepth()
    {
        return lmsParameters.length;
    }

    /**
     * The parameters of one level of the hierarchy, 0 being the root; {@link #getDepth()} gives the range.
     *
     * @throws ArrayIndexOutOfBoundsException if index is outside 0 .. getDepth() - 1.
     */
    public LMSParameters getLmsParameters(int index)
    {
        return lmsParameters[index];
    }

    public LMSParameters[] getLmsParameters()
    {
        return (LMSParameters[])lmsParameters.clone();
    }
}
