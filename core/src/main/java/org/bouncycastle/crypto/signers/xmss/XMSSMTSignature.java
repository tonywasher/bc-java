package org.bouncycastle.crypto.signers.xmss;

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.crypto.params.XMSSMTParameters;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Encodable;
import org.bouncycastle.util.Pack;

/**
 * XMSS^MT Signature.
 */
final class XMSSMTSignature
    implements Encodable
{

    private final XMSSMTParameters params;
    private final long index;
    private final byte[] random;
    private final List<XMSSReducedSignature> reducedSignatures;

    private XMSSMTSignature(Builder builder)
    {
        params = builder.params;
        int n = params.getTreeDigestSize();
        byte[] signature = builder.signature;
        if (signature != null)
        {
            /* import */
            int len = params.getLen();
            int indexSize = (int)Math.ceil(params.getHeight() / 8.0);
            int reducedSignatureSizeSingle = ((params.getHeight() / params.getLayers()) + len) * n;
            int reducedSignaturesSizeTotal = reducedSignatureSizeSingle * params.getLayers();
            int totalSize = indexSize + n + reducedSignaturesSizeTotal;
            if (signature.length != totalSize)
            {
                throw new IllegalArgumentException("signature has wrong size");
            }
            int position = 0;
            index = XMSSUtil.bytesToXBigEndian(signature, position, indexSize);

            if (!XMSSUtil.isIndexValid(params.getHeight(), index))
            {
                throw new IllegalArgumentException("index out of bounds");
            }
            position += indexSize;
            random = Arrays.copyOfRange(signature, position, position + n);
            position += n;
            reducedSignatures = new ArrayList<XMSSReducedSignature>();
            while (position < signature.length)
            {
                XMSSReducedSignature xmssSig = new XMSSReducedSignature.Builder(params.getXMSSParameters())
                    .withReducedSignature(Arrays.copyOfRange(signature, position, position + reducedSignatureSizeSingle))
                    .build();
                reducedSignatures.add(xmssSig);
                position += reducedSignatureSizeSingle;
            }
        }
        else
        {
            /* set */
            index = builder.index;
            random = XMSSUtil.validateOrAllocate(builder.random, n, "random");
            reducedSignatures = new ArrayList<XMSSReducedSignature>();
        }
    }

    public byte[] getEncoded()
    {
        return toByteArray();
    }

    public static class Builder
    {

        /* mandatory */
        private final XMSSMTParameters params;
        /* optional */
        private long index = 0L;
        private byte[] random = null;

        private byte[] signature = null;

        public Builder(XMSSMTParameters params)
        {
            this.params = params;
        }

        public Builder withIndex(long val)
        {
            index = val;
            return this;
        }

        public Builder withRandom(byte[] val)
        {
            random = XMSSUtil.cloneArray(val);
            return this;
        }

        public Builder withSignature(byte[] val)
        {
            signature = Arrays.clone(val);
            return this;
        }

        public XMSSMTSignature build()
        {
            return new XMSSMTSignature(this);
        }
    }

    public byte[] toByteArray()
    {
        /* index || random || reduced signatures */
        int n = params.getTreeDigestSize();
        int len = params.getLen();
        int indexSize = (int)Math.ceil(params.getHeight() / 8.0);
        int reducedSignatureSizeSingle = ((params.getHeight() / params.getLayers()) + len) * n;
        int reducedSignaturesSizeTotal = reducedSignatureSizeSingle * params.getLayers();
        int totalSize = indexSize + n + reducedSignaturesSizeTotal;
        byte[] out = new byte[totalSize];
        int position = 0;
        /* copy index - indexSize is 1..8 for every height the parameters admit (2..62) */
        Pack.longToBigEndian_Low(index, out, position, indexSize);
        position += indexSize;
        /* copy random */
        System.arraycopy(random, 0, out, position, random.length);
        position += n;
        /* copy reduced signatures */
        for (XMSSReducedSignature reducedSignature : reducedSignatures)
        {
            reducedSignature.encodeTo(out, position);
            position += reducedSignatureSizeSingle;
        }
        return out;
    }

    public long getIndex()
    {
        return index;
    }

    public byte[] getRandom()
    {
        return XMSSUtil.cloneArray(random);
    }

    public List<XMSSReducedSignature> getReducedSignatures()
    {
        return reducedSignatures;
    }
}
