package org.bouncycastle.crypto.params;

/**
 * An LMS parameter set: the LMS tree parameters paired with the LM-OTS parameters of its one-time keys.
 * Obtain instances via {@link #create(LMSigParameters, LMOtsParameters)}.
 */
public class LMSParameters
{
    /**
     * Pair LMS tree parameters with the LM-OTS parameters of its one-time keys.
     *
     * @param lmSigParam the LMS tree parameters.
     * @param lmOTSParam the LM-OTS one-time signature parameters.
     * @return the parameter set.
     * @throws NullPointerException if either argument is null.
     */
    public static LMSParameters create(LMSigParameters lmSigParam, LMOtsParameters lmOTSParam)
    {
        return new LMSParameters(lmSigParam, lmOTSParam);
    }

    private final LMSigParameters lmSigParam;
    private final LMOtsParameters lmOTSParam;

    /**
     * @deprecated Use {@link #create(LMSigParameters, LMOtsParameters)}; this class is not intended to be subclassed
     * and this constructor will be made private.
     */
    @Deprecated
    public LMSParameters(LMSigParameters lmSigParam, LMOtsParameters lmOTSParam)
    {
        if (lmSigParam == null)
        {
            throw new NullPointerException("lmSigParam cannot be null");
        }
        if (lmOTSParam == null)
        {
            throw new NullPointerException("lmOTSParam cannot be null");
        }

        this.lmSigParam = lmSigParam;
        this.lmOTSParam = lmOTSParam;
    }

    public boolean equals(Object obj)
    {
        if (this == obj)
        {
            return true;
        }
        if (!(obj instanceof LMSParameters))
        {
            return false;
        }

        LMSParameters that = (LMSParameters)obj;
        return lmSigParam.equals(that.lmSigParam) && lmOTSParam.equals(that.lmOTSParam);
    }

    public int hashCode()
    {
        return lmSigParam.hashCode() * 31 + lmOTSParam.hashCode();
    }

    public LMSigParameters getLMSigParam()
    {
        return lmSigParam;
    }

    public LMOtsParameters getLMOTSParam()
    {
        return lmOTSParam;
    }

    /**
     * The strength a key generator reports for this parameter set: the total number of
     * message bytes' worth of one-time keys the tree carries (2^h keys of m bytes).
     */
    static int calculateStrength(LMSParameters lmsParameters)
    {
        if (lmsParameters == null)
        {
            throw new NullPointerException("lmsParameters cannot be null");
        }

        LMSigParameters sigParameters = lmsParameters.getLMSigParam();
        return (1 << sigParameters.getH()) * sigParameters.getM();
    }
}
