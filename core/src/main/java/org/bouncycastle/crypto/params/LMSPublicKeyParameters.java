package org.bouncycastle.crypto.params;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.crypto.signers.LMSContextBasedVerifier;
import org.bouncycastle.crypto.signers.lms.LMSContext;
import org.bouncycastle.crypto.signers.lms.LMSEngine;
import org.bouncycastle.crypto.signers.lms.LMSSignature;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Exceptions;
import org.bouncycastle.util.io.Streams;

public class LMSPublicKeyParameters
    extends LMSKeyParameters
    implements LMSContextBasedVerifier
{
    private final LMSParameters lmsParameters;
    private final byte[] I;
    private final byte[] T1;

    public LMSPublicKeyParameters(LMSigParameters parameterSet, LMOtsParameters lmOtsType, byte[] T1, byte[] I)
    {
        this(LMSParameters.create(parameterSet, lmOtsType), Arrays.clone(T1), Arrays.clone(I));
    }

    /**
     * Takes ownership of T1 and I: the caller must not modify them afterwards.
     */
    LMSPublicKeyParameters(LMSParameters lmsParameters, byte[] T1, byte[] I)
    {
        super(false);

        this.lmsParameters = lmsParameters;
        this.T1 = T1;
        this.I = I;
    }

    public static LMSPublicKeyParameters getInstance(Object src)
        throws IOException
    {
        if (src instanceof LMSPublicKeyParameters)
        {
            return (LMSPublicKeyParameters)src;
        }
        else if (src instanceof DataInputStream)
        {
            int pubType = ((DataInputStream)src).readInt();
            LMSigParameters sigParameters = LMSigParameters.getParametersForType(pubType);
            if (sigParameters == null)
            {
                throw new IOException("unknown LMS type code: " + pubType);
            }

            int otsType = ((DataInputStream)src).readInt();
            LMOtsParameters ostTypeCode = LMOtsParameters.getParametersForType(otsType);
            if (ostTypeCode == null)
            {
                throw new IOException("unknown LM-OTS type code: " + otsType);
            }

            byte[] I = new byte[16];
            ((DataInputStream)src).readFully(I);

            byte[] T1 = new byte[sigParameters.getM()];
            ((DataInputStream)src).readFully(T1);
            return new LMSPublicKeyParameters(LMSParameters.create(sigParameters, ostTypeCode), T1, I);
        }
        else if (src instanceof byte[])
        {

            InputStream in = null;
            try // 1.5 / 1.6 compatibility
            {
                in = new DataInputStream(new ByteArrayInputStream((byte[])src));
                LMSPublicKeyParameters pKey = getInstance(in);
                // RFC 8554, Section 5.3: the public key is exactly 24 + m bytes long.
                if (in.available() != 0)
                {
                    throw new IOException("unexpected data found after LMS public key");
                }
                return pKey;
            }
            finally
            {
                if (in != null)
                {
                    in.close();
                }
            }
        }
        else if (src instanceof InputStream)
        {
            return getInstance(Streams.readAll((InputStream)src));
        }

        throw new IllegalArgumentException("cannot parse " + src);
    }

    public byte[] getEncoded()
        throws IOException
    {
        return this.toByteArray();
    }

    public LMSigParameters getSigParameters()
    {
        return lmsParameters.getLMSigParam();
    }

    public LMOtsParameters getOtsParameters()
    {
        return lmsParameters.getLMOTSParam();
    }

    public LMSParameters getLMSParameters()
    {
        return lmsParameters;
    }

    public byte[] getT1()
    {
        return Arrays.clone(T1);
    }

    public byte[] getI()
    {
        return Arrays.clone(I);
    }

    byte[] refI()
    {
        return I;
    }

    @Override
    public boolean equals(Object o)
    {
        if (this == o)
        {
            return true;
        }
        if (o == null || getClass() != o.getClass())
        {
            return false;
        }

        LMSPublicKeyParameters publicKey = (LMSPublicKeyParameters)o;

        if (!lmsParameters.equals(publicKey.lmsParameters))
        {
            return false;
        }
        if (!Arrays.areEqual(I, publicKey.I))
        {
            return false;
        }
        return Arrays.areEqual(T1, publicKey.T1);
    }

    @Override
    public int hashCode()
    {
        int result = lmsParameters.hashCode();
        result = 31 * result + Arrays.hashCode(I);
        result = 31 * result + Arrays.hashCode(T1);
        return result;
    }

    /**
     * The RFC 8554 sec. 5.3 encoding: u32str(type) || u32str(otstype) || I || T[1].
     */
    byte[] toByteArray()
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        u32str(getSigParameters().getType(), bOut);
        u32str(getOtsParameters().getType(), bOut);
        bytes(I, bOut);
        bytes(T1, bOut);

        return bOut.toByteArray();
    }

    /**
     * The context a message is absorbed into before verifying an encoded LMS signature against this
     * key. Consumed by {@link #verify(LMSContext)}.
     *
     * @throws IllegalStateException if the signature does not decode.
     */
    public LMSContext generateLMSContext(byte[] signature)
    {
        try
        {
            return LMSEngine.generateVerifyContext(this, LMSSignature.getInstance(signature));
        }
        catch (IOException e)
        {
            throw Exceptions.illegalStateException("cannot parse signature", e);
        }
    }

    public boolean verify(LMSContext context)
    {
        return LMSEngine.verifySignature(this, context);
    }
}
