package org.bouncycastle.crypto.signers.xmss;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.Iterator;
import java.util.Map;
import java.util.TreeMap;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.crypto.params.XMSSMTParameters;
import org.bouncycastle.crypto.params.XMSSParameters;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Pack;

public class BDSStateMap
    implements Serializable
{
    private static final long serialVersionUID = -3464451825208522308L;
    
    private final Map<Integer, BDS> bdsState = new TreeMap<Integer, BDS>();

    private transient long maxIndex;

    public BDSStateMap(long maxIndex)
    {
        this.maxIndex = maxIndex;
    }

    public BDSStateMap(BDSStateMap stateMap, long maxIndex)
    {
        for (Iterator it = stateMap.bdsState.keySet().iterator(); it.hasNext();)
        {
            Integer key = (Integer)it.next();

            bdsState.put(key, new BDS(stateMap.bdsState.get(key)));
        }
        this.maxIndex = maxIndex;
    }

    public BDSStateMap(XMSSMTParameters params, long globalIndex, byte[] publicSeed, byte[] secretKeySeed)
    {
        this.maxIndex = (1L << params.getHeight()) - 1;
        for (long index = 0; index < globalIndex; index++)
        {
            updateState(params, index, publicSeed, secretKeySeed);
        }
    }

    public long getMaxIndex()
    {
        return maxIndex;
    }

    /**
     * The traversal state for the leaf after {@code globalIndex}, as a new state map: the one this
     * is called on is left where it is. This is the multi-tree counterpart of
     * {@link BDS#getNextState(byte[], byte[], OTSHashAddress)}, and advancing by replacement rather
     * than in place is what lets the owning key move its index and its state as one - see
     * {@link XMSSEngine#rollState}.
     */
    BDSStateMap getNextState(XMSSMTParameters params, long globalIndex, byte[] publicSeed, byte[] secretKeySeed)
    {
        BDSStateMap next = new BDSStateMap(this, maxIndex);

        next.updateState(params, globalIndex, publicSeed, secretKeySeed);

        return next;
    }

    /**
     * Advance this state map in place. Package-private, and for a map that is not yet anyone's: the
     * constructor building a state up to an index, and the copy {@link #getNextState} has just
     * taken. The state a key holds is advanced by being replaced, never through here.
     */
    void updateState(XMSSMTParameters params, long globalIndex, byte[] publicSeed, byte[] secretKeySeed)
    {
        XMSSParameters xmssParams = params.getXMSSParameters();
        int xmssHeight = xmssParams.getHeight();

        //
        // set up state for next signature
        //
        long indexTree = XMSSUtil.getTreeIndex(globalIndex, xmssHeight);
        int indexLeaf = XMSSUtil.getLeafIndex(globalIndex, xmssHeight);

        OTSHashAddress otsHashAddress = (OTSHashAddress)new OTSHashAddress.Builder().withTreeAddress(indexTree)
            .withOTSAddress(indexLeaf).build();

        /* prepare authentication path for next leaf */
        if (indexLeaf < ((1 << xmssHeight) - 1))
        {
            if (this.get(0) == null || indexLeaf == 0)
            {
                this.put(0, new BDS(xmssParams, publicSeed, secretKeySeed, otsHashAddress));
            }

            this.update(0, publicSeed, secretKeySeed, otsHashAddress);
        }

        /* loop over remaining layers */
        for (int layer = 1; layer < params.getLayers(); layer++)
        {
                /* get root of layer - 1 */
            indexLeaf = XMSSUtil.getLeafIndex(indexTree, xmssHeight);
            indexTree = XMSSUtil.getTreeIndex(indexTree, xmssHeight);
                /* adjust addresses */
            otsHashAddress = (OTSHashAddress)new OTSHashAddress.Builder().withLayerAddress(layer)
                .withTreeAddress(indexTree).withOTSAddress(indexLeaf).build();

                /* prepare authentication path for next leaf */
            if (bdsState.get(layer) == null || XMSSUtil.isNewBDSInitNeeded(globalIndex, xmssHeight, layer))
            {
                bdsState.put(layer, new BDS(xmssParams, publicSeed, secretKeySeed, otsHashAddress));
            }

            if (indexLeaf < ((1 << xmssHeight) - 1)
                && XMSSUtil.isNewAuthenticationPathNeeded(globalIndex, xmssHeight, layer))
            {
                this.update(layer, publicSeed, secretKeySeed, otsHashAddress);
            }
        }
    }

    boolean isEmpty()
    {
        return bdsState.isEmpty();
    }

    Map<Integer, BDS> getStateMap()
    {
        return bdsState;
    }

    public void validate(XMSSMTParameters params)
    {
        long maxIndexLimit = (1L << params.getHeight()) - 1;
        if (maxIndex < 0 || maxIndex > maxIndexLimit || bdsState.size() > params.getLayers())
        {
            throw new IllegalStateException("BDS state map does not match XMSSMT parameters");
        }

        XMSSParameters xmssParams = params.getXMSSParameters();
        for (Iterator<Integer> it = bdsState.keySet().iterator(); it.hasNext();)
        {
            Integer layer = it.next();
            if (layer.intValue() < 0 || layer.intValue() >= params.getLayers())
            {
                throw new IllegalStateException("BDS state map has invalid layer");
            }
            BDS state = bdsState.get(layer);
            if (state == null)
            {
                throw new IllegalStateException("BDS state map has null state");
            }
            state.validate(xmssParams);
        }
    }

    /**
     * Confirm the top layer's root is the one the enclosing private key declares - the top tree's
     * root is the public root. A layer with no state yet is built lazily at signing time and so is
     * not compared (github #2414).
     *
     * @param params       the parameters of the enclosing key.
     * @param expectedRoot the root the private key declares.
     */
    public void validateRoot(XMSSMTParameters params, byte[] expectedRoot)
    {
        BDS top = bdsState.get(Integers.valueOf(params.getLayers() - 1));

        if (top != null)
        {
            top.validateRoot(expectedRoot);
        }
    }

    /**
     * Validate as validate(XMSSMTParameters) and additionally tie each layer's traversal state to
     * the enclosing private key's index. RFC 8391 sec. 1.1 requires each one-time key to be used
     * once, and the global index and the per-layer BDS states are two records of the same position,
     * so a stored key whose index has been rolled back while its state stayed advanced - a partial
     * write, a restore from backup, a buggy storage layer - is detectable and must be refused: it
     * would otherwise sign a second message under a one-time key already used, and the signature
     * would verify. The XMSS side has done this since its own state was tied to its index; this is
     * the multi-tree counterpart.
     *
     * @param params      the parameters of the enclosing key.
     * @param globalIndex the index the enclosing key declares.
     */
    public void validate(XMSSMTParameters params, long globalIndex)
    {
        validate(params);

        int xmssHeight = params.getXMSSParameters().getHeight();
        int lastLeaf = (1 << xmssHeight) - 1;
        long treeIndex = globalIndex;

        for (int layer = 0; layer < params.getLayers(); layer++)
        {
            // the same walk down the layers the signer and updateState perform
            int expectedLeaf = XMSSUtil.getLeafIndex(treeIndex, xmssHeight);
            treeIndex = XMSSUtil.getTreeIndex(treeIndex, xmssHeight);

            BDS state = bdsState.get(Integers.valueOf(layer));
            if (state == null)
            {
                // a layer's state is built lazily, on the first signature that needs it
                continue;
            }

            //
            // At a leaf index of 0 the layer has just moved into a new subtree and its state has not
            // been advanced into it: updateState skips the advance on the last leaf of a subtree and
            // the signer rebuilds the state when it next signs there, so the carried-over final
            // index of the previous subtree is legitimate at that one position. Every other position
            // must agree exactly. Enumerating every index of the h=4/d=2, h=6/d=2, h=6/d=3, h=9/d=3
            // and h=8/d=4 parameter sets produces no other divergence.
            //
            int actual = state.getIndex();
            boolean ok = (expectedLeaf == 0)
                ? (actual == 0 || actual == lastLeaf)
                : (actual == expectedLeaf);

            if (!ok)
            {
                throw new IllegalStateException(
                    "BDS state has wrong index for layer " + layer + ": expected " + expectedLeaf
                        + " but state is at " + actual);
            }
        }
    }

    public BDS get(int index)
    {
        return bdsState.get(Integers.valueOf(index));
    }

    /**
     * Record that the one-time key this state is sitting on has signed, as the XMSS path does.
     * <p>
     * Only the layer zero state is marked. Its leaf signs the message digest, so it is the one
     * one-time key a second signature must never reuse - the leaves above it sign the root of the
     * subtree below, which does not change while that subtree is being signed through, so those
     * layers legitimately produce the same signature again and are not used up by it.
     * </p>
     */
    void markUsed()
    {
        BDS layerZero = bdsState.get(Integers.valueOf(0));

        // the state is put in place before the signature is built, but the signature can fail
        // before that happens and this runs from the finally that covers it
        if (layerZero != null)
        {
            layerZero.markUsed();
        }
    }

    BDS update(int index, byte[] publicSeed, byte[] secretKeySeed, OTSHashAddress otsHashAddress)
    {
        return bdsState.put(Integers.valueOf(index), bdsState.get(Integers.valueOf(index)).getNextState(publicSeed, secretKeySeed, otsHashAddress));
    }

    void put(int index, BDS bds)
    {
        bdsState.put(Integers.valueOf(index), bds);
    }

    public BDSStateMap withWOTSDigest(ASN1ObjectIdentifier digestName)
    {
        return withWOTSDigest(digestName, -1);
    }

    public BDSStateMap withWOTSDigest(ASN1ObjectIdentifier digestName, int digestSize)
    {
        BDSStateMap newStateMap = new BDSStateMap(this.maxIndex);

        for (Iterator<Integer> keys = bdsState.keySet().iterator(); keys.hasNext();)
        {
            Integer key = keys.next();

            newStateMap.bdsState.put(key, bdsState.get(key).withWOTSDigest(digestName, digestSize));
        }

        return newStateMap;
    }

    private void readObject(
        ObjectInputStream in)
        throws IOException, ClassNotFoundException
    {
        in.defaultReadObject();

        // Java deserialization does not run field initializers, so a crafted stream that declares
        // no bdsState field at all leaves it null, and one that declares it can put nulls in it.
        // The import path rebuilds a state map around the digest its key names before anything
        // validates it - withWOTSDigest() walks the map - so validate()'s own null checks are
        // reached too late to be what rejects this. Refuse it here, where the stream enters.
        if (bdsState == null)
        {
            throw new IOException("no state in BDS state map");
        }
        for (Iterator<Integer> it = bdsState.keySet().iterator(); it.hasNext();)
        {
            Integer layer = it.next();

            // a null key is not merely absent state: TreeMap.get(null) throws in its own right
            if (layer == null || bdsState.get(layer) == null)
            {
                throw new IOException("null state in BDS state map");
            }
        }

        // ObjectInputStream.available() is an estimate of what can be read without blocking, not
        // an end of data test - it answers zero for a stream that cannot supply the next block
        // header without blocking - so reading a byte is what actually says whether the maximum
        // index is there: read() returns -1 only at the end of this object's data.
        int first = in.read();

        if (first < 0)
        {
            // written before the maximum index was recorded. A state map cannot resolve that for
            // itself, holding no tree height of its own the way BDS does, so it marks it with a
            // value no state map can really carry and leaves it to XMSSMTPrivateKeyParameters,
            // which knows the parameter set. Zero, the mark this used to leave, is one a state map
            // really can carry: it is what a single use key shard taken at index 0 carries.
            this.maxIndex = -1L;
        }
        else
        {
            byte[] encoded = new byte[8];

            encoded[0] = (byte)first;
            in.readFully(encoded, 1, encoded.length - 1);

            this.maxIndex = Pack.bigEndianToLong(encoded, 0);
        }
    }

    private void writeObject(
        ObjectOutputStream out)
        throws IOException
    {
        out.defaultWriteObject();

        out.writeLong(this.maxIndex);
    }
}
