package org.bouncycastle.crypto.params;

import java.io.IOException;

import org.bouncycastle.crypto.signers.xmss.BDS;
import org.bouncycastle.crypto.signers.xmss.XMSSEngine;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Encodable;
import org.bouncycastle.util.Exceptions;

/**
 * XMSS Private Key.
 */
public final class XMSSPrivateKeyParameters
    extends XMSSKeyParameters
    implements Encodable
{

    /**
     * XMSS parameters object.
     */
    private final XMSSParameters params;
    /**
     * Secret for the derivation of WOTS+ secret keys.
     */
    private final byte[] secretKeySeed;
    /**
     * Secret for the randomization of message digests during signature
     * creation.
     */
    private final byte[] secretKeyPRF;
    /**
     * Public seed for the randomization of hashes.
     */
    private final byte[] publicSeed;
    /**
     * Public root of binary tree.
     */
    private final byte[] root;
    /**
     * BDS state.
     */
    private volatile BDS bdsState;

    private XMSSPrivateKeyParameters(Builder builder)
    {
        super(true, builder.params.getTreeDigest());
        params = builder.params;
        int n = params.getTreeDigestSize();
        byte[] privateKey = builder.privateKey;
        if (privateKey != null)
        {
            /* import */
            XMSSPrivateKeyCodec codec = XMSSPrivateKeyCodec.decode(privateKey,
                XMSSPrivateKeyCodec.XMSS_INDEX_SIZE, params.getHeight(), n);

            // the codec answers in the width the XMSS^MT index needs; this family's is an int
            // everywhere else in the class, and the index check the codec has already made bounds
            // it by 2^30, so nothing is lost narrowing it here
            int index = (int)codec.getIndex();
            secretKeySeed = codec.getSecretKeySeed();
            secretKeyPRF = codec.getSecretKeyPRF();
            publicSeed = codec.getPublicSeed();
            root = codec.getRoot();
            byte[] bdsStateBinary = codec.getBDSState();
            try
            {
                BDS bdsImport = XMSSEngine.getBDSFromEncoding(bdsStateBinary, publicSeed);
                bdsState = bdsImport.withWOTSDigest(builder.params.getTreeDigestOID(), builder.params.getTreeDigestSize());
                bdsState.validate(params, index);
                bdsState.validateRoot(root);
            }
            catch (IOException e)
            {
                throw Exceptions.illegalArgumentException(e.getMessage(), e);
            }
            catch (ClassNotFoundException e)
            {
                throw Exceptions.illegalArgumentException(e.getMessage(), e);
            }
            catch (IllegalStateException e)
            {
                throw Exceptions.illegalArgumentException(e.getMessage(), e);
            }
        }
        else
        {
            /* set */
            byte[] tmpSecretKeySeed = builder.secretKeySeed;
            secretKeySeed = XMSSEngine.validateOrAllocate(tmpSecretKeySeed, n, "secretKeySeed");
            byte[] tmpSecretKeyPRF = builder.secretKeyPRF;
            secretKeyPRF = XMSSEngine.validateOrAllocate(tmpSecretKeyPRF, n, "secretKeyPRF");
            byte[] tmpPublicSeed = builder.publicSeed;
            publicSeed = XMSSEngine.validateOrAllocate(tmpPublicSeed, n, "publicSeed");
            byte[] tmpRoot = builder.root;
            root = XMSSEngine.validateOrAllocate(tmpRoot, n, "root");
            BDS tmpBDSState = builder.bdsState;
            if (tmpBDSState != null)
            {
                bdsState = tmpBDSState;
            }
            else
            {
                bdsState = XMSSEngine.createBDS(params, tmpPublicSeed, tmpSecretKeySeed, builder.index);
            }
            if (builder.maxIndex >= 0 && builder.maxIndex != bdsState.getMaxIndex())
            {
                throw new IllegalArgumentException("maxIndex set but not reflected in state");
            }
            try
            {
                bdsState.validate(params, builder.index);
                if (builder.bdsState != null)
                {
                    // only a restored state carries a root worth comparing: one built here is
                    // computed from the seeds, and a key built without a root carries zeros
                    bdsState.validateRoot(builder.root);
                }
            }
            catch (IllegalStateException e)
            {
                throw Exceptions.illegalArgumentException(e.getMessage(), e);
            }
        }
    }

    public long getUsagesRemaining()
    {
        synchronized (this)
        {
            return this.bdsState.getMaxIndex() - this.getIndex() + 1;
        }
    }

    public byte[] getEncoded()
        throws IOException
    {
        synchronized (this)
        {
            return toByteArray();
        }
    }

    public XMSSPrivateKeyParameters rollKey()
    {
        synchronized (this)
        {
            /* prepare authentication path for next leaf */
            if (bdsState.getIndex() < bdsState.getMaxIndex())
            {
                bdsState = XMSSEngine.getNextBDSState(bdsState, publicSeed, secretKeySeed);
            }
            else
            {
                bdsState = new BDS(params, bdsState.getMaxIndex(), bdsState.getMaxIndex() + 1); // no more nodes left.
            }

            return this;
        }
    }

    public XMSSPrivateKeyParameters getNextKey()
    {
        synchronized (this)
        {
            return this.extractKeyShard(1);
        }
    }

    /**
     * Return a key that can be used usageCount times.
     * <p>
     * Note: this will use the range [index...index + usageCount) for the current key.
     * </p>
     *
     * @param usageCount the number of usages the key should have.
     * @return a key based on the current key that can be used usageCount times.
     */
    public XMSSPrivateKeyParameters extractKeyShard(int usageCount)
    {
        if (usageCount < 1)
        {
            throw new IllegalArgumentException("cannot ask for a shard with 0 keys");
        }
        synchronized (this)
        {
            /* prepare authentication path for next leaf */
            if (usageCount <= this.getUsagesRemaining())
            {
                XMSSPrivateKeyParameters keyParams = new XMSSPrivateKeyParameters.Builder(params)
                    .withSecretKeySeed(secretKeySeed).withSecretKeyPRF(secretKeyPRF)
                    .withPublicSeed(publicSeed).withRoot(root)
                    .withIndex(getIndex())
                    .withOwnedBDSState(bdsState.withMaxIndex(bdsState.getIndex() + usageCount - 1,
                        params.getTreeDigestOID(), params.getTreeDigestSize())).build();

                if (usageCount == this.getUsagesRemaining())
                {
                    this.bdsState = new BDS(params, bdsState.getMaxIndex(), getIndex() + usageCount);   // we're finished.
                }
                else
                {
                    // update the tree to the new index.
                    for (int i = 0; i != usageCount; i++)
                    {
                        this.bdsState = XMSSEngine.getNextBDSState(bdsState, publicSeed, secretKeySeed);
                    }
                }

                return keyParams;
            }
            else
            {
                throw new IllegalArgumentException("usageCount exceeds usages remaining");
            }
        }
    }

    public static class Builder
    {

        /* mandatory */
        private final XMSSParameters params;
        /* optional */
        private int index = 0;
        private int maxIndex = -1;
        private byte[] secretKeySeed = null;
        private byte[] secretKeyPRF = null;
        private byte[] publicSeed = null;
        private byte[] root = null;
        private BDS bdsState = null;
        private byte[] privateKey = null;

        public Builder(XMSSParameters params)
        {
            if (params == null)
            {
                throw new NullPointerException("params == null");
            }
            this.params = params;
        }

        public Builder withIndex(int val)
        {
            index = val;
            return this;
        }

        public Builder withMaxIndex(int val)
        {
            maxIndex = val;
            return this;
        }

        public Builder withSecretKeySeed(byte[] val)
        {
            secretKeySeed = Arrays.clone(val);
            return this;
        }

        public Builder withSecretKeyPRF(byte[] val)
        {
            secretKeyPRF = Arrays.clone(val);
            return this;
        }

        public Builder withPublicSeed(byte[] val)
        {
            publicSeed = Arrays.clone(val);
            return this;
        }

        public Builder withRoot(byte[] val)
        {
            root = Arrays.clone(val);
            return this;
        }

        public Builder withBDSState(BDS valBDS)
        {
            //
            // Copy, do not adopt, as the XMSS^MT builder does. Rolling the key replaces its state
            // rather than advancing the one it holds, but a signature still marks the state it
            // spent in place - XMSSEngine's markUsed() - so two keys sharing one BDS share that
            // record: one key's signature marks the other's state, and the other is then refused
            // by the check that reads the mark, having signed nothing. It travels the other way
            // too, a caller keeping the state it passed in seeing its own copy marked by a key it
            // has handed it to.
            //
            bdsState = valBDS.withMaxIndex(valBDS.getMaxIndex(), params.getTreeDigestOID(),
                params.getTreeDigestSize());
            return this;
        }

        /**
         * As {@link #withBDSState(BDS)}, for a state the caller has just built and shares with
         * nothing: it is adopted rather than copied a second time. Package private for the reason
         * the XMSS^MT sibling gives - a public way of asking the key to adopt a state is the
         * sharing defect the copy prevents, offered as an option.
         */
        Builder withOwnedBDSState(BDS valBDS)
        {
            bdsState = valBDS;
            return this;
        }

        public Builder withPrivateKey(byte[] privateKeyVal)
        {
            privateKey = Arrays.clone(privateKeyVal);
            return this;
        }

        public XMSSPrivateKeyParameters build()
        {
            if (!((privateKey != null) || (publicSeed != null && secretKeySeed != null)))
            {
                throw new IllegalStateException("publicSeed or secretKeySeed is null");
            }
            return new XMSSPrivateKeyParameters(this);
        }
    }

    /**
     * @deprecated use getEncoded() - this method will become private.
     */
    @Deprecated
    public byte[] toByteArray()
    {
        synchronized (this)
        {
            byte[] bdsStateOut;
            try
            {
                bdsStateOut = XMSSEngine.getEncodedBDSState(bdsState, publicSeed);
            }
            catch (IOException e)
            {
                throw Exceptions.illegalStateException("error encoding BDS state", e);
            }

            return XMSSPrivateKeyCodec.encode(bdsState.getIndex(), XMSSPrivateKeyCodec.XMSS_INDEX_SIZE,
                secretKeySeed, secretKeyPRF, publicSeed, root, bdsStateOut);
        }
    }

    public int getIndex()
    {
        return bdsState.getIndex();
    }

    public byte[] getSecretKeySeed()
    {
        return Arrays.clone(secretKeySeed);
    }

    public byte[] getSecretKeyPRF()
    {
        return Arrays.clone(secretKeyPRF);
    }

    public byte[] getPublicSeed()
    {
        return Arrays.clone(publicSeed);
    }

    public byte[] getRoot()
    {
        return Arrays.clone(root);
    }

    public BDS getBDSState()
    {
        return bdsState;
    }

    public XMSSParameters getParameters()
    {
        return params;
    }

    /**
     * Whether these are the same key at the same position, which for a stateful key means the same
     * traversal state too - so the tail of this is a constant time comparison of the two traversal
     * states as encoded, everything else about the two keys having been compared field by field
     * ahead of it.
     * <p>
     * The comparison belongs here rather than in the provider key that wraps this one because
     * every part of it does: the monitor a signature is taken under is this object's, the fields
     * are this object's, and a caller reaching in through the accessors gets a clone of each array
     * and no way to hold any two of them still. {@code HSSPrivateKeyParameters} does the same for
     * the other stateful family in this package, leaving {@code BCLMSPrivateKey.equals()} a single
     * delegating line, and the two XMSS provider keys are now that line as well. Each of those
     * carries the tree digest a second time, as the OID it was constructed with, and no longer
     * compares it: that OID is {@code params.getTreeDigestOID()} at every route a key is built by
     * - generation, a PKCS#8 round trip, extractKeyShard, and the key a signature hands back - so
     * the first comparison below is the comparison they were making.
     * </p><p>
     * What is in front of the state encoding is the part of the answer that does not need it.
     * Producing one means re-encoding the whole BDS traversal state - the authentication path, the
     * retain queues, the stack, every tree hash and every kept node, and a SHA-256 checksum over
     * the result - and every call did that twice, on both keys, whatever the two keys were. The
     * fields tested first are all written into that encoding, so two keys differing in any of them
     * cannot have equal encodings and the answer is the same one for none of the work: the tree
     * digest, the index, the usages remaining - which alongside an equal index says the maximum
     * index is equal too - and the two public n-byte fields. hashCode() below is over fields that
     * do not move as the key signs, so keys taken from one key pair all land in the same bucket of
     * a Set or a Map and are told apart there by their index, which this answers on without
     * reaching the state.
     * </p><p>
     * The root and the public seed are compared in constant time even though they are the public
     * key - they are what {@code XMSSPublicKeyParameters} publishes, root then SEED, RFC 8391
     * sec. 4.1.7 - because this is a private key's equals(), where every array comparison in the
     * method being constant time is what stops the next field added to this chain from being
     * compared the other way. The two secret seeds are the next fields added to it, and they are
     * why the tail can be the traversal state alone: the encoding it used to compare is the index,
     * those two seeds, the public seed, the root and the state, and the first five are now all
     * above. So the same six things decide the answer, in the same constant time, and the four
     * n-byte comparisons that replace the encoding of a whole key cost nothing against it.
     * </p><p>
     * The chain is joined with {@code |} rather than {@code ||}, so all of it is evaluated
     * whatever the two keys are. Short circuited it answers a key differing in its tree digest
     * after one comparison and a key differing only in its secretKeyPRF after seven, so how long
     * the method takes says which of the fields the two keys first disagree on - and two of those
     * fields are secret material, which is the thing the constant time comparisons above are there
     * to keep out of the timing. Every operand is safe to evaluate unconditionally: the parameter
     * set is mandatory, and the four arrays are allocated when a builder is not given them.
     * </p><p>
     * What is left in the timing is the bit the chain decides - whether the two keys agree on all
     * seven - since that is what says whether the state encoding below runs at all. Two keys that
     * get there agree on both secret seeds, so the longer path is not reachable without already
     * holding what comparing those seeds in constant time is there to withhold. It is also why
     * that encoding stays below the chain rather than being joined onto it with {@code &}: it
     * would encode two whole traversal states for every pair of keys that differ, the Set and Map
     * lookups above among them.
     * </p><p>
     * A key's index and its usages remaining are read together under that key's own monitor, the
     * one XMSSEngine holds for the whole of a signature and the one {@code encodedState()} below
     * takes. Read one at a time, a signature landing between them pairs an index from one side of
     * it with a usage count from the other, a combination the key was never in. One key at a time
     * and never both at once: holding the second key's monitor inside the first would let
     * a.equals(b) on one thread and b.equals(a) on another deadlock against each other, and there
     * is nothing to hold them for - the same reason {@code HSSPrivateKeyParameters.equals()}
     * gives for taking its two monitors in sequence.
     * </p><p>
     * That is still each key's monitor taken twice rather than once - the scalars above, then the
     * state below - so a signature landing between the two leaves the chain answering on a
     * position its key has already left. All it can do from there is answer false, which is the
     * answer for the instant it read; the pairs that reach the state are the ones it found equal,
     * and the state is compared as a snapshot of its own. What that snapshot has to pin down is
     * the position the answer is about, and here it does so on its own account: the encoding
     * {@code BDSStateCodec} writes opens with the maximum index and the index, so two states that
     * compare equal are two keys at one position with the same usages left, which is everything
     * the scalars above decide. The XMSS^MT key reads its index a second time inside that block
     * instead, its global index being a field beside the state map rather than a part of it.
     * Neither key can be compared against a moving target whatever this does; what this gives is
     * that the values an answer is made from are values that key held at one instant.
     * </p>
     */
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

        XMSSPrivateKeyParameters that = (XMSSPrivateKeyParameters)o;

        long thisIndex;
        long thisUsagesRemaining;

        synchronized (this)
        {
            thisIndex = this.getIndex();
            thisUsagesRemaining = this.getUsagesRemaining();
        }

        long thatIndex;
        long thatUsagesRemaining;

        synchronized (that)
        {
            thatIndex = that.getIndex();
            thatUsagesRemaining = that.getUsagesRemaining();
        }

        if (!params.getTreeDigestOID().equals(that.params.getTreeDigestOID())
            | thisIndex != thatIndex
            | thisUsagesRemaining != thatUsagesRemaining
            | !Arrays.constantTimeAreEqual(publicSeed, that.publicSeed)
            | !Arrays.constantTimeAreEqual(root, that.root)
            | !Arrays.constantTimeAreEqual(secretKeySeed, that.secretKeySeed)
            | !Arrays.constantTimeAreEqual(secretKeyPRF, that.secretKeyPRF))
        {
            return false;
        }

        return Arrays.constantTimeAreEqual(this.encodedState(), that.encodedState());
    }

    /**
     * The traversal state of this key, as an encoding of it would carry it. This is the one part
     * of a key's content the field comparisons in equals() cannot reach: a state carries a mark
     * saying the one-time key at its index has already signed, and no accessor reports it.
     * <p>
     * Under the key's own monitor, which is what {@code toByteArray()} takes to read the same two
     * things: a signature landing between the state and the public seed would encode a state under
     * a seed that no longer goes with it.
     * </p>
     */
    private byte[] encodedState()
    {
        synchronized (this)
        {
            try
            {
                return XMSSEngine.getEncodedBDSState(bdsState, publicSeed);
            }
            catch (IOException e)
            {
                throw Exceptions.illegalStateException("error encoding BDS state", e);
            }
        }
    }

    /**
     * The fields that do not move as this key signs: the tree digest, the root and the public
     * seed. Equal keys agree on all three, so the equals() contract holds.
     * <p>
     * Together they are the public key - {@code XMSSPublicKeyParameters} publishes root then SEED
     * under the same parameter set - which is what the provider key hashed by building one and
     * encoding it, an XMSSPublicKeyParameters and a BCXMSSPublicKey and a concatenation of the two
     * fields per call to reach the same three values held here. The two secret seeds are left out
     * for the reason they are compared in constant time above: a hash of secret material is a
     * commitment to it, published to wherever the hash goes, and nothing here needs one - the
     * index is what tells one key of a key pair from another, and equals() answers on it without
     * being asked for a hash at all.
     * </p>
     */
    public int hashCode()
    {
        int hc = params.getTreeDigestOID().hashCode();
        hc = 31 * hc + Arrays.hashCode(root);
        hc = 31 * hc + Arrays.hashCode(publicSeed);
        return hc;
    }
}
