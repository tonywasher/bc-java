package org.bouncycastle.crypto.signers.xmss;

import org.bouncycastle.crypto.params.XMSSParameters;
import org.bouncycastle.util.Arrays;

import java.util.ArrayList;
import java.util.List;

/**
 * Reduced XMSS Signature.
 */
class XMSSReducedSignature
{
    private final XMSSParameters params;
    private final WOTSPlusSignature wotsPlusSignature;
    private final List<XMSSNode> authPath;

    public XMSSReducedSignature(Builder builder)
    {
        params = builder.params;
        int n = params.getTreeDigestSize();
        int len = params.getLen();
        int height = params.getHeight();
        byte[] reducedSignature = builder.reducedSignature;
        if (reducedSignature != null)
        {
            /* import */
            int signatureSize = len * n;
            int authPathSize = height * n;
            int totalSize = signatureSize + authPathSize;
            if (reducedSignature.length != totalSize)
            {
                throw new IllegalArgumentException("signature has wrong size");
            }
            int position = 0;
            byte[][] wotsPlusSignature = new byte[len][];
            for (int i = 0; i < wotsPlusSignature.length; i++)
            {
                wotsPlusSignature[i] = Arrays.copyOfRange(reducedSignature, position, position + n);
                position += n;
            }
            this.wotsPlusSignature = new WOTSPlusSignature(XMSSEngine.newWOTSPlusParameters(params), wotsPlusSignature);

            List<XMSSNode> nodeList = new ArrayList<XMSSNode>();
            for (int i = 0; i < height; i++)
            {
                nodeList.add(new XMSSNode(i, Arrays.copyOfRange(reducedSignature, position, position + n)));
                position += n;
            }
            authPath = nodeList;
        }
        else
        {
            /* set */
            WOTSPlusSignature tmpSignature = builder.wotsPlusSignature;
            if (tmpSignature != null)
            {
                wotsPlusSignature = tmpSignature;
            }
            else
            {
                wotsPlusSignature = new WOTSPlusSignature(XMSSEngine.newWOTSPlusParameters(params), new byte[len][n]);
            }
            List<XMSSNode> tmpAuthPath = builder.authPath;
            if (tmpAuthPath != null)
            {
                if (tmpAuthPath.size() != height)
                {
                    throw new IllegalArgumentException("size of authPath needs to be equal to height of tree");
                }
                authPath = tmpAuthPath;
            }
            else
            {
                authPath = new ArrayList<XMSSNode>();
            }
        }
    }

    static class Builder
    {
        /* mandatory */
        private final XMSSParameters params;
        /* optional */
        private WOTSPlusSignature wotsPlusSignature = null;
        private List<XMSSNode> authPath = null;
        private byte[] reducedSignature = null;

        public Builder(XMSSParameters params)
        {
            this.params = params;
        }

        public Builder withWOTSPlusSignature(WOTSPlusSignature val)
        {
            wotsPlusSignature = val;
            return this;
        }

        public Builder withAuthPath(List<XMSSNode> val)
        {
            authPath = val;
            return this;
        }

        public Builder withReducedSignature(byte[] val)
        {
            reducedSignature = XMSSUtil.cloneArray(val);
            return this;
        }

        public XMSSReducedSignature build()
        {
            return new XMSSReducedSignature(this);
        }
    }

    public byte[] toByteArray()
    {
        /* signature || authentication path */
        int n = params.getTreeDigestSize();
        int signatureSize = params.getLen() * n;
        int authPathSize = params.getHeight() * n;
        byte[] out = new byte[signatureSize + authPathSize];
        encodeTo(out, 0);
        return out;
    }

    /**
     * Write signature || authentication path into {@code out} at {@code position}.
     * <p>
     * The encodings that carry one of these are filling a buffer of their own - XMSSSignature puts
     * index || random in front of it, XMSSMTSignature lays one down per layer - so writing into the
     * caller's buffer is what keeps a per-signature array out of the encoding: XMSSMTSignature had
     * been building one per layer and copying it in, and both had been taking the defensive copies
     * of the WOTS+ blocks and of every authentication path node on the way past.
     * </p>
     */
    void encodeTo(byte[] out, int position)
    {
        int n = params.getTreeDigestSize();
        /* copy signature */
        wotsPlusSignature.encodeTo(out, position);
        position += params.getLen() * n;
        /* copy authentication path */
        for (int i = 0; i < authPath.size(); i++)
        {
            authPath.get(i).encodeTo(out, position);
            position += n;
        }
    }

    public XMSSParameters getParams()
    {
        return params;
    }

    public WOTSPlusSignature getWOTSPlusSignature()
    {
        return wotsPlusSignature;
    }

    public List<XMSSNode> getAuthPath()
    {
        return authPath;
    }
}
