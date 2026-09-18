package org.bouncycastle.crypto.params;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import javax.security.auth.Destroyable;

import org.bouncycastle.crypto.ExhaustedPrivateKeyException;
import org.bouncycastle.crypto.signers.LMSContextBasedSigner;
import org.bouncycastle.crypto.signers.lms.LMSContext;
import org.bouncycastle.crypto.signers.lms.LMSEngine;
import org.bouncycastle.crypto.signers.lms.LMSSignature;
import org.bouncycastle.util.Exceptions;
import org.bouncycastle.util.io.Streams;

public class HSSPrivateKeyParameters
    extends LMSKeyParameters
    implements LMSContextBasedSigner, Destroyable
{
    /**
     * The component keys of an HSS hierarchy together with the chaining signatures that bind them:
     * the public key of level i is signed by the key of level i - 1, and that signature is
     * sig[i - 1].
     * <p>
     * The two move together - replacing an exhausted tree replaces both its key and the signature
     * above it - so they are held as one immutable object and published by a single volatile
     * write. A reader that has the reference has a coherent pair of them without taking the key's
     * monitor, and without a window in which one has been replaced and the other has not.
     * </p>
     */
    private static final class Hierarchy
    {
        static Hierarchy copy(List<LMSPrivateKeyParameters> keys, List<LMSSignature> sig)
        {
            return new Hierarchy(
                keys.toArray(new LMSPrivateKeyParameters[keys.size()]),
                sig.toArray(new LMSSignature[sig.size()]));
        }

        private final LMSPrivateKeyParameters[] keys;
        private final LMSSignature[] sig;

        // Built once with the snapshot rather than per call, since the snapshot cannot change
        private final List<LMSPrivateKeyParameters> keyList;
        private final List<LMSSignature> sigList;

        /**
         * Takes ownership of the arrays, which must not be modified afterwards.
         */
        Hierarchy(LMSPrivateKeyParameters[] keys, LMSSignature[] sig)
        {
            this.keys = keys;
            this.sig = sig;
            this.keyList = Collections.unmodifiableList(Arrays.asList(keys));
            this.sigList = Collections.unmodifiableList(Arrays.asList(sig));
        }

        int size()
        {
            return keys.length;
        }

        LMSPrivateKeyParameters getKey(int index)
        {
            return keys[index];
        }

        LMSSignature getSig(int index)
        {
            return sig[index];
        }

        List<LMSPrivateKeyParameters> getKeyList()
        {
            return keyList;
        }

        List<LMSSignature> getSigList()
        {
            return sigList;
        }

        LMSPrivateKeyParameters[] copyKeys()
        {
            return (LMSPrivateKeyParameters[])keys.clone();
        }

        LMSSignature[] copySig()
        {
            return (LMSSignature[])sig.clone();
        }

        boolean hasUnconstructedLevel()
        {
            return keyList.contains(null) || sigList.contains(null);
        }

        /**
         * The component keys, each as a length-prefixed encoding, followed by the chaining
         * signatures the same way.
         */
        void encodeTo(ByteArrayOutputStream out)
            throws IOException
        {
            for (int i = 0; i < keys.length; i++)
            {
                bytes(keys[i].getEncoded(), out);
            }

            for (int i = 0; i < sig.length; i++)
            {
                bytes(sig[i].getEncoded(), out);
            }
        }
    }

    private final int l;
    private final boolean isShard;
    // Replaced, never modified; written under this key's monitor and read without it (see Hierarchy).
    private volatile Hierarchy hierarchy;
    private final long indexLimit;
    private long index = 0;

    private volatile boolean destroyed;

    /**
     * Generate an HSS private key: a root LMS key drawn from the parameters' random source, with
     * the lower trees derived from it when the key is first positioned at index 0.
     */
    public static HSSPrivateKeyParameters generate(HSSKeyGenerationParameters parameters)
    {
        //
        // LmsPrivateKey can derive and hold the public key so we just use an array of those.
        //
        LMSPrivateKeyParameters[] keys = new LMSPrivateKeyParameters[parameters.getDepth()];
        LMSSignature[] sig = new LMSSignature[parameters.getDepth() - 1];

        LMSParameters rootLms = parameters.getLmsParameters(0);

        //
        // Set the HSS key up with a valid root LMSPrivateKeyParameters and placeholders for the remaining LMS keys.
        // The placeholders pass enough information to allow the HSSPrivateKeyParameters to be properly reset to an
        // index of zero. Rather than repeat the same reset-to-index logic in this static method.
        //

        keys[0] = LMSPrivateKeyParameters.generate(rootLms, parameters.getRandom());

        long hssKeyMaxIndex = 1L << rootLms.getLMSigParam().getH();

        for (int t = 1; t < keys.length; t++)
        {
            LMSParameters lms = parameters.getLmsParameters(t);
            int h = lms.getLMSigParam().getH();

            keys[t] = LMSPrivateKeyParameters.createPlaceholder(lms, 1 << h);

            hssKeyMaxIndex <<= h;
        }

        // if this has happened we're trying to generate a really large key
        // we'll use MAX_VALUE so that it's at least usable until someone upgrades the structure.
        if (hssKeyMaxIndex <= 0)
        {
            hssKeyMaxIndex = Long.MAX_VALUE;
        }

        return new HSSPrivateKeyParameters(
            parameters.getDepth(),
            Arrays.asList(keys),
            Arrays.asList(sig),
            0, hssKeyMaxIndex);
    }

    public HSSPrivateKeyParameters(LMSPrivateKeyParameters key, long index, long indexLimit)
    {
        super(true);

        this.l = 1;
        this.hierarchy = new Hierarchy(new LMSPrivateKeyParameters[]{ key }, new LMSSignature[0]);
        this.index = index;
        this.indexLimit = indexLimit;
        this.isShard = false;

        //
        // Correct Intermediate LMS values will be constructed during reset to index.
        //
        resetKeyToIndex();
    }

    public HSSPrivateKeyParameters(int l, List<LMSPrivateKeyParameters> keys, List<LMSSignature> sig, long index, long indexLimit)
    {
        super(true);

        // the same shape the decoder requires; resetKeyToIndex below indexes both lists against l
        if (l < 1 || l > 8)    // RFC 8554, Section 6.
        {
            throw new IllegalArgumentException("L value of HSS private key out of range: " + l);
        }
        if (keys.size() != l)
        {
            throw new IllegalArgumentException("HSS private key needs one component key per level");
        }
        if (sig.size() != l - 1)
        {
            throw new IllegalArgumentException(
                "HSS private key needs one chaining signature per level below the root");
        }
        if (index < 0 || indexLimit < 0 || index > indexLimit)
        {
            throw new IllegalArgumentException(
                "HSS private key index out of range: index=" + index + " indexLimit=" + indexLimit);
        }

        this.l = l;
        this.hierarchy = Hierarchy.copy(keys, sig);
        this.index = index;
        this.indexLimit = indexLimit;
        this.isShard = false;

        //
        // Correct Intermediate LMS values will be constructed during reset to index.
        //
        resetKeyToIndex();

        // a null level is legitimate on the way in, for the reset above to fill, but not on the way out
        if (hierarchy.hasUnconstructedLevel())
        {
            throw new IllegalArgumentException("HSS private key has a level that was left unconstructed");
        }
    }

    /**
     * Takes the hierarchy as it stands, which is immutable and so may be shared with the key it was
     * taken from.
     */
    private HSSPrivateKeyParameters(int l, Hierarchy hierarchy, long index, long indexLimit, boolean isShard)
    {
        super(true);

        this.l = l;
        this.hierarchy = hierarchy;
        this.index = index;
        this.indexLimit = indexLimit;
        this.isShard = isShard;
    }

    public static HSSPrivateKeyParameters getInstance(byte[] privEnc, byte[] pubEnc)
        throws IOException
    {
        HSSPrivateKeyParameters pKey = getInstance(privEnc);

        HSSPublicKeyParameters pubKey = HSSPublicKeyParameters.getInstance(pubEnc);

        // The public key that arrived alongside the private one is authoritative, so where the root
        // tree already carries its root node in the cache it costs nothing to confirm the two agree.
        // That catches a tree cache which is internally consistent but belongs to a different key -
        // the one corruption the node-by-node check in LMSPrivateKeyParameters cannot see. It is
        // deliberately skipped when the root is not cached: recomputing it there means rebuilding the
        // whole tree, which is the work the cache exists to avoid (github #2414).
        byte[] cachedRoot = pKey.getRootKey().peekRootT();

        if (cachedRoot != null && !org.bouncycastle.util.Arrays.areEqual(
                cachedRoot, pubKey.getLMSPublicKey().getT1()))
        {
            throw new IOException("HSS private key tree cache does not match the public key");
        }

        return pKey;
    }

    /**
     * The HSS index and the component keys' one-time indices are two records of the same position in
     * the key, and a decoded key whose records disagree is refused. RFC 8554 sec. 1 requires each
     * one-time key to be used once; a stored key whose index has been rolled back while its
     * component keys stayed advanced - a partial write, a restore from backup, a buggy storage layer
     * - would otherwise sign a second message under a one-time key already used, and that signature
     * would verify, so nothing would surface it. The check is the identity the two records satisfy:
     * a level below the last contributes (q - 1) leaves of the levels beneath it, because its q has
     * already advanced past the subtree it signed, and the last level contributes its q directly.
     * Verified against every index of a two-level key and across a level boundary of a three-level
     * one (github #2414).
     * <p>
     * Applied at decode only. The constructor is also reached from the hierarchy update, which
     * rebuilds lower levels and is momentarily inconsistent by design; corrupt stored state can only
     * arrive here.
     */
    private static void checkIndexAgainstKeys(int d, LMSPrivateKeyParameters[] keys, long index)
        throws IOException
    {
        long implied = keys[d - 1].getIndex();
        int shift = 0;

        for (int i = d - 2; i >= 0; i--)
        {
            shift += keys[i + 1].getSigParameters().getH();
            if (shift >= 63)
            {
                // taller than the 64-bit index can address, so the two records cannot be compared
                return;
            }
            implied += ((long)keys[i].getIndex() - 1L) << shift;
        }

        if (implied != index)
        {
            throw new IOException("HSS private key index " + index
                + " does not match the component key indices, which imply " + implied);
        }
    }

    public static HSSPrivateKeyParameters getInstance(Object src)
        throws IOException
    {
        if (src instanceof HSSPrivateKeyParameters)
        {
            return (HSSPrivateKeyParameters)src;
        }
        else if (src instanceof DataInputStream)
        {
            int version = ((DataInputStream)src).readInt();
            if (version != 0 && version != 1)
            {
                throw new IOException("unknown version for hss private key");
            }
            int d = ((DataInputStream)src).readInt();
            if (d < 1 || d > 8)    // RFC 8554, Section 6.
            {
                throw new IOException("d value of HSS private key out of range: " + d);
            }
            long index = ((DataInputStream)src).readLong();
            long maxIndex = ((DataInputStream)src).readLong();
            if (index < 0 || maxIndex < 0 || index > maxIndex)
            {
                throw new IOException(
                    "HSS private key index out of range: index=" + index + " maxIndex=" + maxIndex);
            }
            boolean limited = ((DataInputStream)src).readBoolean();

            // Read once here, so every component key is held to the same limit
            int maxSeedLength = LMSPrivateKeyParameters.getMaxSeedLength();

            LMSPrivateKeyParameters[] keys = new LMSPrivateKeyParameters[d];
            for (int t = 0; t < d; t++)
            {
                // The component keys share this stream with the keys and signatures that follow,
                // so whether each one carries the tree-cache field cannot be inferred from the
                // stream having more data - the encoding version says: a version 0 encoding
                // predates the tree cache and its component keys end at the master secret, a
                // version 1 component always carries the cache field (github #2365).
                keys[t] = LMSPrivateKeyParameters.readComponentKey((DataInputStream)src, maxSeedLength, version != 0);
            }

            LMSSignature[] signatures = new LMSSignature[d - 1];
            for (int t = 0; t < d - 1; t++)
            {
                signatures[t] = LMSSignature.getInstance(src);
            }

            checkIndexAgainstKeys(d, keys, index);

            return new HSSPrivateKeyParameters(d, new Hierarchy(keys, signatures), index, maxIndex, limited);
        }
        else if (src instanceof byte[])
        {
            InputStream in = null;
            try // 1.5 / 1.6 compatibility
            {
                in = new DataInputStream(new ByteArrayInputStream((byte[])src));

                Exception hssFailure;

                try
                {
                    return getInstance(in);
                }
                catch (Exception e)
                {
                    hssFailure = e;
                }

                try
                {
                    // old style single LMS key.
                    LMSPrivateKeyParameters lmsKey = LMSPrivateKeyParameters.getInstance(src);
                    return new HSSPrivateKeyParameters(lmsKey, lmsKey.getIndex(), lmsKey.getIndexLimit());
                }
                catch (Exception e)
                {
                    //
                    // Neither shape parsed. The retry as a single LMS key is a compatibility path for
                    // encodings that predate HSS, so when it fails too the HSS failure is the one worth
                    // reporting - it is what the field checks raise - rather than the retry complaining
                    // about a version field it was never going to match. Reporting the retry's exception
                    // masked the real reason a key was rejected, which is how the field checks below
                    // looked absent through this entry point (github #2414).
                    //
                    if (hssFailure instanceof RuntimeException)
                    {
                        throw (RuntimeException)hssFailure;
                    }
                    if (hssFailure instanceof IOException)
                    {
                        throw (IOException)hssFailure;
                    }
                    throw Exceptions.ioException(hssFailure.getMessage(), hssFailure);
                }
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

    public int getL()
    {
        return l;
    }

    public synchronized long getIndex()
    {
        return index;
    }

    public LMSParameters[] getLMSParameters()
    {
        Hierarchy hierarchy = this.hierarchy;
        int len = hierarchy.size();

        LMSParameters[] parms = new LMSParameters[len];

        for (int i = 0; i < len; i++)
        {
            LMSPrivateKeyParameters lmsPrivateKey = hierarchy.getKey(i);

            parms[i] = lmsPrivateKey.getLMSParameters();
        }

        return parms;
    }

    synchronized void incIndex()
    {
        index++;
    }

    /**
     * Advance the key past its current index without signing with it, replacing exhausted lower
     * trees as a signature would. Used by the tests to walk a key through the RFC 8554 vectors.
     */
    synchronized void incrementIndex()
    {
        rangeTestKeys();
        incIndex();
        hierarchy.getKey(l - 1).incIndex();
    }

    private static HSSPrivateKeyParameters makeCopy(HSSPrivateKeyParameters privateKeyParameters)
    {
        try
        {
            return HSSPrivateKeyParameters.getInstance(privateKeyParameters.getEncoded());
        }
        catch (Exception ex)
        {
            throw new RuntimeException(ex.getMessage(), ex);
        }
    }

    /**
     * Return true if this key was split off another with {@link #extractKeyShard(int)} and so
     * covers a sub-range of that key's indexes.
     */
    public boolean isShard()
    {
        return isShard;
    }

    /**
     * Return the index one past the last this key may sign with.
     */
    public long getIndexLimit()
    {
        return indexLimit;
    }

    public long getUsagesRemaining()
    {
        return getIndexLimit() - getIndex();
    }

    LMSPrivateKeyParameters getRootKey()
    {
        return hierarchy.getKey(0);
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
    public HSSPrivateKeyParameters extractKeyShard(int usageCount)
    {
        synchronized (this)
        {
            checkDestroyed();

            if (usageCount < 0)
            {
                throw new IllegalArgumentException("usageCount cannot be negative");
            }
            if (usageCount > indexLimit - index)
            {
                throw new IllegalArgumentException("usageCount exceeds usages remaining in current leaf");
            }

            long shardIndex = index;
            long shardIndexLimit = index + usageCount;

            // Move this key's index along
            index = shardIndexLimit;

            // The hierarchy is shared with this key rather than copied: makeCopy re-parses the
            // encoding, so the shard that escapes has component keys of its own either way.
            HSSPrivateKeyParameters shard = makeCopy(
                new HSSPrivateKeyParameters(l, hierarchy, shardIndex, shardIndexLimit, true));

            resetKeyToIndex();

            return shard;
        }
    }

    List<LMSPrivateKeyParameters> getKeys()
    {
        return hierarchy.getKeyList();
    }

    List<LMSSignature> getSig()
    {
        return hierarchy.getSigList();
    }

    /**
     * Reset to index will ensure that all LMS keys are correct for a given HSS index value.
     * Normally LMS keys are updated in sync with their parent HSS key but in cases of sharding
     * the normal monotonic updating does not apply and the state of the LMS keys needs to be
     * reset to match the current HSS index.
     * <p>
     * Should only be called under the monitor (lock) or during construction before the instance escapes.
     * </p>
     */
    private void resetKeyToIndex()
    {
        // Extract the original keys
        Hierarchy oldHierarchy = hierarchy;

        long[] qTreePath = new long[oldHierarchy.size()];
        long q = getIndex();

        for (int t = oldHierarchy.size() - 1; t >= 0; t--)
        {
            LMSigParameters sigParameters = oldHierarchy.getKey(t).getSigParameters();
            int mask = (1 << sigParameters.getH()) - 1;
            qTreePath[t] = q & mask;
            q >>>= sigParameters.getH();
        }

        boolean changed = false;
        LMSPrivateKeyParameters[] keys = oldHierarchy.copyKeys();
        LMSSignature[] sig = oldHierarchy.copySig();

        LMSPrivateKeyParameters rootKey = keys[0];

        //
        // We need to replace the root key to a new q value; the last level reads the derived
        // value itself, which for a single level hierarchy is the root.
        //
        boolean rootQMatch = (qTreePath.length > 1)
            ? qTreePath[0] == rootKey.getIndex() - 1
            : qTreePath[0] == rootKey.getIndex();

        if (!rootQMatch)
        {
            //
            // Only the position moves - the root's identifier, seed and parameter sets are its own
            // and cannot have changed - so this is the same tree at a different one-time key, and
            // the repositioned key keeps the tree the root has already built.
            //
            rootKey = rootKey.repositionTo((int)qTreePath[0]);

            keys[0] = rootKey;
            changed = true;
        }

        for (int i = 1; i < qTreePath.length; i++)
        {
            LMSPrivateKeyParameters parentKey = keys[i - 1];

            byte[][] child = LMSEngine.deriveChildKey(
                parentKey.getOtsParameters(),
                parentKey.getI(),
                parentKey.getMasterSecret(),
                (int)qTreePath[i - 1]);
            byte[] childI = child[0];
            byte[] childSeed = child[1];

            LMSPrivateKeyParameters oldKey = keys[i];

            //
            // Q values in LMS keys post increment after they are used.
            // For intermediate keys they will always be out by one from the derived q value (qValues[i])
            // For the end key its value will match so no correction is required.
            //
            boolean lmsQMatch =
                (i < qTreePath.length - 1) ? qTreePath[i] == oldKey.getIndex() - 1 : qTreePath[i] == oldKey.getIndex();

            //
            // Equality is I and seed being equal and the lmsQMath.
            // I and seed are derived from this nodes parent and will change if the parent q, I, seed changes.
            //
            boolean seedEquals = org.bouncycastle.util.Arrays.areEqual(childI, oldKey.getI())
                && org.bouncycastle.util.Arrays.constantTimeAreEqual(childSeed, oldKey.getMasterSecret());


            if (!seedEquals)
            {
                //
                // This means the parent has changed.
                //
                replaceLevel(keys, sig, i, oldKey.getLMSParameters(), (int)qTreePath[i], childI, childSeed);
                changed = true;
            }
            else if (!lmsQMatch)
            {

                //
                // Q is different, but seedEquals says the identifier and seed are not, so this is
                // the same tree at a different one-time key: reposition within it rather than
                // rebuild it. The public key is unchanged either way, so the chaining signature
                // above it still stands and does not need making again.
                //
                keys[i] = keys[i].repositionTo((int)qTreePath[i]);
                changed = true;
            }

        }


        if (changed)
        {
            // We mutate the HSS key here! Under the caller's monitor, per the contract above.
            hierarchy = new Hierarchy(keys, sig);
        }

    }

    public synchronized HSSPublicKeyParameters getPublicKey()
    {
        return new HSSPublicKeyParameters(l, getRootKey().getPublicKey());
    }

    /**
     * Check the key has an index left to sign with, and replace every lower tree that has used
     * all of its one-time keys with the next one its parent derives (RFC 8554 sec. 6.1).
     */
    private void rangeTestKeys()
    {
        synchronized (this)
        {
            if (index >= indexLimit)
            {
                throw new ExhaustedPrivateKeyException(
                    "hss private key" +
                        ((isShard) ? " shard" : "") +
                        " is exhausted");
            }


            int L = l;
            int d = L;
            Hierarchy prv = hierarchy;
            // >= rather than ==: an index above 2^h steps straight over an equality test
            // (github #2414). Decode now rejects such a q, so this is belt and braces.
            while (prv.getKey(d - 1).getIndex() >= 1 << (prv.getKey(d - 1).getSigParameters().getH()))
            {
                d = d - 1;
                if (d == 0)
                {
                    throw new ExhaustedPrivateKeyException(
                        "hss private key" +
                            ((isShard) ? " shard" : "") +
                            " is exhausted the maximum limit for this HSS private key");
                }
            }


            if (d < L)
            {
                replaceExhaustedKeys(d);
            }
        }
    }

    /**
     * Replace the exhausted trees, at levels d and below, with fresh ones. Each is derived from the
     * current one-time key of the level above it, and has its public key signed by that key.
     * <p>
     * Should only be called under the monitor (lock): the new trees are derived from the hierarchy
     * this reads, so the read and the write have to be one step. The rebuilt levels are published
     * as a single hierarchy, since one rebuilt only as far as level i pairs the fresh tree at
     * level i with the signature over the exhausted one it replaced.
     * </p>
     */
    private void replaceExhaustedKeys(int d)
    {
        Hierarchy oldHierarchy = hierarchy;

        LMSPrivateKeyParameters[] newKeys = oldHierarchy.copyKeys();
        LMSSignature[] newSig = oldHierarchy.copySig();

        for (; d < l; ++d)
        {
            // Each level below the first takes its parent from the level rebuilt on the previous pass
            byte[][] child = newKeys[d - 1].deriveChildKey();
            byte[] childI = child[0];
            byte[] childSeed = child[1];

            // The replacement keeps the parameters of the key it replaces
            LMSPrivateKeyParameters oldKey = newKeys[d];

            replaceLevel(newKeys, newSig, d, oldKey.getLMSParameters(), 0, childI, childSeed);
        }

        // The replaced keys and the signatures over them reach readers together
        hierarchy = new Hierarchy(newKeys, newSig);
    }

    /**
     * Replace level d of a hierarchy: an LMS private key positioned at index q (RFC 8554 sec. 5.2, Algorithm 5)
     * built from the identifier and seed the level above derived for it, together with the chaining signature
     * over its public key, which the level above makes by consuming one of its one-time keys (sec. 6.1).
     * Writes keys[d] and sig[d - 1]; keys[d - 1] must already be the level above.
     */
    private static void replaceLevel(LMSPrivateKeyParameters[] keys, LMSSignature[] sig, int d,
        LMSParameters lmsParameters, int q, byte[] I, byte[] masterSecret)
    {
        //
        // RFC 8554 recommends the digest used in LMS and LMOTS be of the same strength to protect against
        // attackers going after the weaker of the two digests. This is not enforced here!
        //
        LMSPrivateKeyParameters key = new LMSPrivateKeyParameters(lmsParameters, q, I,
            1 << lmsParameters.getLMSigParam().getH(), masterSecret);

        LMSContext context = keys[d - 1].generateLMSContext();

        byte[] encoded = key.getPublicKey().toByteArray();
        context.update(encoded, 0, encoded.length);

        keys[d] = key;
        sig[d - 1] = LMSEngine.generateSign(context);
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

        HSSPrivateKeyParameters that = (HSSPrivateKeyParameters)o;

        if (this.l != that.l || this.isShard != that.isShard || this.indexLimit != that.indexLimit)
        {
            return false;
        }

        // a destroyed key no longer exposes its value, so it is only equal to itself.
        if (this.destroyed || that.destroyed)
        {
            return false;
        }

        //
        // The index and the hierarchy both move as exhausted trees are replaced, and they move
        // together, so read each key's pair in one synchronized block to get a snapshot no
        // unsynchronized reader could tear. The hierarchy is immutable and replaced rather than
        // modified, so a captured reference stays a coherent view after the lock drops. Neither
        // monitor is held while the other is taken, so a.equals(b) racing b.equals(a) cannot
        // deadlock.
        //
        long thisIndex;
        Hierarchy thisHierarchy;
        synchronized (this)
        {
            thisIndex = this.index;
            thisHierarchy = this.hierarchy;
        }

        long thatIndex;
        Hierarchy thatHierarchy;
        synchronized (that)
        {
            thatIndex = that.index;
            thatHierarchy = that.hierarchy;
        }

        return thisIndex == thatIndex
            && thisHierarchy.getKeyList().equals(thatHierarchy.getKeyList())
            && thisHierarchy.getSigList().equals(thatHierarchy.getSigList());
    }

    @Override
    public synchronized byte[] getEncoded()
        throws IOException
    {
        //
        // Private keys are implementation dependent.
        //

        checkDestroyed();

        // Version 1: the component keys carry the mandatory tree-cache field their getEncoded
        // appends; a version 0 encoding (any release before the tree cache) carries them without
        // it. The version dispatch in getInstance is what keeps the shared stream unambiguous.
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        u32str(1, bOut); // Version.
        u32str(l, bOut);
        u64str(index, bOut);
        u64str(indexLimit, bOut);
        bOut.write(isShard ? 1 : 0); // Depth

        hierarchy.encodeTo(bOut);

        return bOut.toByteArray();
    }

    @Override
    public int hashCode()
    {
        //
        // Deliberately not getPublicKey().hashCode(): that reaches the root key's tree, which is
        // only built if the node cache does not already hold it - 2^h LM-OTS public keys from an
        // implicit call no caller expects to cost anything. The fields used here are the ones that
        // do not move as the key signs: the root key material is fixed (resetKeyToIndex only
        // repositions it, and LMSPrivateKeyParameters.hashCode is itself index-independent),
        // whereas index, keys and sig all change. Equal keys agree on all of these, so the
        // equals() contract holds.
        //
        int hc = l;
        hc = 31 * hc + (isShard ? 1 : 0);
        hc = 31 * hc + (int)(indexLimit ^ (indexLimit >>> 32));
        hc = 31 * hc + getRootKey().hashCode();
        return hc;
    }

    @Override
    protected Object clone()
        throws CloneNotSupportedException
    {
        return makeCopy(this);
    }

    public LMSContext generateLMSContext()
    {
        LMSSignature[] signatures;
        LMSPublicKeyParameters[] publicKeys;
        LMSContext context;
        int L = this.getL();

        // the HSS index and the bottom key's q are two records of one position: claim both here,
        // bottom key first so an exhausted one leaves each untouched.
        synchronized (this)
        {
            checkDestroyed();

            rangeTestKeys();

            // After the range test, which replaces the levels it finds exhausted
            Hierarchy hierarchy = this.hierarchy;

            LMSPrivateKeyParameters nextKey = hierarchy.getKey(L - 1);

            // Step 2. Stand in for sig[L-1]
            int i = 0;
            signatures = new LMSSignature[L - 1];
            publicKeys = new LMSPublicKeyParameters[L - 1];
            while (i < L - 1)
            {
                signatures[i] = hierarchy.getSig(i);
                publicKeys[i] = hierarchy.getKey(i + 1).getPublicKey();
                i = i + 1;
            }

            context = nextKey.generateLMSContext();

            //
            // increment the index.
            //
            this.incIndex();
        }

        return LMSEngine.withSignedPublicKeys(context, signatures, publicKeys);
    }

    public byte[] generateSignature(LMSContext context)
    {
        return LMSEngine.generateHSSSignature(getL(), context);
    }

    /**
     * Destroy this key, zeroizing the master secret of every tree in the hierarchy.
     * <p>
     * The chaining signatures, the indexes and the component keys' identifiers and cached tree
     * nodes are retained - none of them is secret, and the public key stays derivable where the
     * root tree's root node is already cached. After destruction {@link #isDestroyed()} returns
     * true and {@link #getEncoded()}, {@link #generateLMSContext()} and
     * {@link #extractKeyShard(int)} throw {@link IllegalStateException}; a signature attempt
     * fails before its index is claimed. Shards split off this key before it was destroyed are
     * independent copies and are unaffected.
     */
    public synchronized void destroy()
    {
        if (!destroyed)
        {
            destroyed = true;

            for (LMSPrivateKeyParameters key : hierarchy.getKeyList())
            {
                key.destroy();
            }
        }
    }

    public boolean isDestroyed()
    {
        return destroyed;
    }

    private void checkDestroyed()
    {
        if (destroyed)
        {
            throw new IllegalStateException("key destroyed");
        }
    }
}
