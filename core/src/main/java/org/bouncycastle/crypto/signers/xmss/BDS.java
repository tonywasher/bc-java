package org.bouncycastle.crypto.signers.xmss;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Stack;
import java.util.TreeMap;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.crypto.params.XMSSParameters;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

/**
 * BDS.
 */
public final class BDS
    implements Serializable
{
    private static final long serialVersionUID = 1L;
    
    private final transient WOTSPlus wotsPlus;

    private final int treeHeight;
    private final List<BDSTreeHash> treeHashInstances;
    private final int k;
    private XMSSNode root;
    private final List<XMSSNode> authenticationPath;
    private final Map<Integer, List<XMSSNode>> retain;
    private final Stack<XMSSNode> stack;

    private final Map<Integer, XMSSNode> keep;
    private int index;
    private boolean used;

    private transient int maxIndex;

    /**
     * Place holder BDS for when state is exhausted.
     *
     * @param params tree parameters
     * @param index the index that has been reached.
     */
    public BDS(XMSSParameters params, int maxIndex, int index)
    {
        this(XMSSEngine.newWOTSPlus(params), params.getHeight(), params.getK(), index);
        this.maxIndex = maxIndex;
        this.index = index;
        this.used = true;
    }

    /**
     * Set up constructor.
     *
     * @param params tree parameters
     * @param publicSeed public seed for tree
     * @param secretKeySeed secret seed for tree
     * @param otsHashAddress hash address
     */
    BDS(XMSSParameters params, byte[] publicSeed, byte[] secretKeySeed, OTSHashAddress otsHashAddress)
    {
        this(XMSSEngine.newWOTSPlus(params), params.getHeight(), params.getK(), ((1 << params.getHeight()) - 1));
        this.initialize(publicSeed, secretKeySeed, otsHashAddress);
    }

    /**
     * Set up constructor for a tree where the original BDS state was lost.
     *
     * @param params tree parameters
     * @param publicSeed public seed for tree
     * @param secretKeySeed secret seed for tree
     * @param otsHashAddress hash address
     * @param index index counter for the state to be at.
     */
    BDS(XMSSParameters params, byte[] publicSeed, byte[] secretKeySeed, OTSHashAddress otsHashAddress, int index)
    {
        this(XMSSEngine.newWOTSPlus(params), params.getHeight(), params.getK(), ((1 << params.getHeight()) - 1));

        this.initialize(publicSeed, secretKeySeed, otsHashAddress);

        while (this.index < index)
        {
            this.nextAuthenticationPath(publicSeed, secretKeySeed, otsHashAddress);
            this.used = false;
        }
    }

    private BDS(WOTSPlus wotsPlus, int treeHeight, int k, int maxIndex)
    {
        this.wotsPlus = wotsPlus;
        this.treeHeight = treeHeight;
        this.maxIndex = maxIndex;
        this.k = k;
        if (k > treeHeight || k < 2 || ((treeHeight - k) % 2) != 0)
        {
            throw new IllegalArgumentException("illegal value for BDS parameter k");
        }
        authenticationPath = new ArrayList<XMSSNode>();
        retain = new TreeMap<Integer, List<XMSSNode>>();
        stack = new Stack<XMSSNode>();

        treeHashInstances = new ArrayList<BDSTreeHash>();
        for (int height = 0; height < (treeHeight - k); height++)
        {
            treeHashInstances.add(new BDSTreeHash(height));
        }

        keep = new TreeMap<Integer, XMSSNode>();
        index = 0;
        this.used = false;
    }

    BDS(int treeHeight, int k, int maxIndex, int index, boolean used, XMSSNode root,
        List<XMSSNode> authenticationPath, Map<Integer, List<XMSSNode>> retain,
        Stack<XMSSNode> stack, List<BDSTreeHash> treeHashInstances, Map<Integer, XMSSNode> keep)
    {
        this.wotsPlus = null;
        this.treeHeight = treeHeight;
        this.k = k;
        this.maxIndex = maxIndex;
        this.index = index;
        this.used = used;
        this.root = root;
        this.authenticationPath = cloneAuthenticationPath(authenticationPath);
        this.retain = cloneRetain(retain);
        this.stack = cloneStack(stack);
        this.treeHashInstances = cloneTreeHashInstances(treeHashInstances);
        this.keep = new TreeMap<Integer, XMSSNode>(keep);
        this.validate();
    }

    /**
     * The copy the four "carry on from a previous state" constructors below all make, written
     * once. Each of them differs from the others only in the WOTS+ instance it ends up with,
     * whether it keeps the maximum index and the used mark of the state it copies, and what it
     * does after the copy - so those are the arguments, and the rest is this.
     * <p>
     * They had a copy of the block each, which is how a field added to the traversal state has to
     * be threaded through four places by hand: that happened once already, for maxIndex, and
     * missing one of the four leaves that constructor quietly building a state whose new field
     * never came across. Two of the four end in validate(), which would have caught it, and two -
     * the plain copy and the one the signer advances through, both on the per signature path - do
     * not, so the way not to have the problem is to have one copy rather than to check four.
     * </p>
     */
    private BDS(BDS last, WOTSPlus wotsPlus, int maxIndex, boolean used)
    {
        this.wotsPlus = wotsPlus;
        this.treeHeight = last.treeHeight;
        this.k = last.k;
        this.root = last.root;
        this.authenticationPath = cloneAuthenticationPath(last.authenticationPath);
        this.retain = cloneRetain(last.retain);
        this.stack = cloneStack(last.stack);
        this.treeHashInstances = cloneTreeHashInstances(last.treeHashInstances);
        this.keep = new TreeMap<Integer, XMSSNode>(last.keep);
        this.index = last.index;
        this.maxIndex = maxIndex;
        this.used = used;
    }

    BDS(BDS last)
    {
        this(last, new WOTSPlus(last.wotsPlus.getParams()), last.maxIndex, last.used);
    }

    private BDS(BDS last, byte[] publicSeed, byte[] secretKeySeed, OTSHashAddress otsHashAddress)
    {
        // the state being built is the one after last, and it has signed nothing yet
        this(last, new WOTSPlus(last.wotsPlus.getParams()), last.maxIndex, false);

        this.nextAuthenticationPath(publicSeed, secretKeySeed, otsHashAddress);
    }

    private BDS(BDS last, ASN1ObjectIdentifier digest, int digestSize)
    {
        this(last, newWOTSPlus(digest, digestSize), last.maxIndex, last.used);
        this.validate();
    }

    private BDS(BDS last, int maxIndex, ASN1ObjectIdentifier digest, int digestSize)
    {
        this(last, newWOTSPlus(digest, digestSize), maxIndex, last.used);
        this.validate();
    }

    /**
     * The WOTS+ instance the two constructors that rebuild a state around a named digest make -
     * a decoded state carries no WOTS+ parameters of its own, so they cannot take last's. An
     * explicit size is needed for the digests whose output length is not fixed by their name.
     */
    private static WOTSPlus newWOTSPlus(ASN1ObjectIdentifier digest, int digestSize)
    {
        return new WOTSPlus(digestSize > 0
            ? new WOTSPlusParameters(digest, digestSize) : new WOTSPlusParameters(digest));
    }

    // note use of addAll/clone rather than a shared reference to avoid serialization issues
    private static List<XMSSNode> cloneAuthenticationPath(List<XMSSNode> authenticationPath)
    {
        List<XMSSNode> clone = new ArrayList<XMSSNode>();
        clone.addAll(authenticationPath);
        return clone;
    }

    private static Map<Integer, List<XMSSNode>> cloneRetain(Map<Integer, List<XMSSNode>> retain)
    {
        Map<Integer, List<XMSSNode>> clone = new TreeMap<Integer, List<XMSSNode>>();
        for (Iterator it = retain.keySet().iterator(); it.hasNext();)
        {
            Integer key = (Integer)it.next();
            clone.put(key, new LinkedList<XMSSNode>(retain.get(key)));
        }
        return clone;
    }

    private static Stack<XMSSNode> cloneStack(Stack<XMSSNode> stack)
    {
        Stack<XMSSNode> clone = new Stack<XMSSNode>();
        clone.addAll(stack);
        return clone;
    }

    private static List<BDSTreeHash> cloneTreeHashInstances(List<BDSTreeHash> treeHashInstances)
    {
        List<BDSTreeHash> clone = new ArrayList<BDSTreeHash>();
        for (Iterator it = treeHashInstances.iterator(); it.hasNext();)
        {
            clone.add(((BDSTreeHash)it.next()).clone());
        }
        return clone;
    }

    BDS getNextState(byte[] publicSeed, byte[] secretKeySeed, OTSHashAddress otsHashAddress)
    {
        return new BDS(this, publicSeed, secretKeySeed, otsHashAddress);
    }

    private void initialize(byte[] publicSeed, byte[] secretSeed, OTSHashAddress otsHashAddress)
    {
        /* prepare addresses - one encoding each for the whole walk, with the words that change
         * written into them as it goes */
        byte[] lTreeAddress = new LTreeAddress.Builder()
            .withLayerAddress(otsHashAddress.getLayerAddress()).withTreeAddress(otsHashAddress.getTreeAddress())
            .build().toByteArray();
        byte[] hashTreeAddress = new HashTreeAddress.Builder()
            .withLayerAddress(otsHashAddress.getLayerAddress()).withTreeAddress(otsHashAddress.getTreeAddress())
            .build().toByteArray();
        /* and one pair of working buffers for every node hashed below, L-tree and tree alike; see
         * XMSSNodeUtil.randomizeHash for why one pair serves a whole walk */
        int n = wotsPlus.getParams().getTreeDigestSize();
        byte[] nodeKey = new byte[n];
        byte[] nodeMask = new byte[2 * n];

        /* iterate indexes */
        for (int indexLeaf = 0; indexLeaf < (1 << treeHeight); indexLeaf++)
        {
            /* generate leaf */
            otsHashAddress = XMSSNodeUtil.withOTSAddress(otsHashAddress, indexLeaf);
            /*
             * import WOTSPlusSecretKey as its needed to calculate the public
             * key on the fly
             */
            wotsPlus.importKeys(wotsPlus.getWOTSPlusSecretKey(secretSeed, otsHashAddress), publicSeed);
            WOTSPlusPublicKeyParameters wotsPlusPublicKey = wotsPlus.getPublicKey(otsHashAddress);
            Pack.intToBigEndian(indexLeaf, lTreeAddress, LTreeAddress.LTREE_ADDRESS_OFFSET);
            XMSSNode node = XMSSNodeUtil.lTree(wotsPlus, wotsPlusPublicKey, lTreeAddress, nodeKey, nodeMask);

            // the two words of the hash tree encoding the climb below moves, kept beside it so
            // that stepping one is an increment rather than a read back out of the bytes. They
            // are named for the encoding rather than for the field, because this class's own
            // treeHeight is the height of the whole tree - which the loop below reads to decide
            // what is retained - and a local of that name here would hide it silently.
            //
            // The height goes back to 0 for the new leaf rather than being carried over: the loop
            // walks it up, so leaving it where the previous leaf finished would start each leaf
            // at that height.
            int hashTreeHeight = 0;
            int hashTreeIndex = indexLeaf;
            Pack.intToBigEndian(hashTreeHeight, hashTreeAddress, HashTreeAddress.TREE_HEIGHT_OFFSET);
            Pack.intToBigEndian(hashTreeIndex, hashTreeAddress, HashTreeAddress.TREE_INDEX_OFFSET);
            while (!stack.isEmpty() && stack.peek().getHeight() == node.getHeight())
            {
                /* add to authenticationPath if leafIndex == 1 */
                int indexOnHeight = indexLeaf / (1 << node.getHeight());
                if (indexOnHeight == 1)
                {
                    authenticationPath.add(node);
                }
                /* store next right authentication node */
                if (indexOnHeight == 3 && node.getHeight() < (treeHeight - k))
                {
                    treeHashInstances.get(node.getHeight()).setNode(node);
                }
                if (indexOnHeight >= 3 && (indexOnHeight & 1) == 1 && node.getHeight() >= (treeHeight - k)
                    && node.getHeight() <= (treeHeight - 2))
                {
                    if (retain.get(node.getHeight()) == null)
                    {
                        LinkedList<XMSSNode> queue = new LinkedList<XMSSNode>();
                        queue.add(node);
                        retain.put(node.getHeight(), queue);
                    }
                    else
                    {
                        retain.get(node.getHeight()).add(node);
                    }
                }
                hashTreeIndex = (hashTreeIndex - 1) / 2;
                Pack.intToBigEndian(hashTreeIndex, hashTreeAddress, HashTreeAddress.TREE_INDEX_OFFSET);
                node = XMSSNodeUtil.randomizeHash(wotsPlus, stack.pop(), node, hashTreeAddress, nodeKey, nodeMask);
                node = node.incrementHeight();
                Pack.intToBigEndian(++hashTreeHeight, hashTreeAddress, HashTreeAddress.TREE_HEIGHT_OFFSET);
            }
            /* push to stack */
            stack.push(node);
        }
        root = stack.pop();
    }

    private void nextAuthenticationPath(byte[] publicSeed, byte[] secretSeed, OTSHashAddress otsHashAddress)
    {
        if (used)
        {
            throw new IllegalStateException("index already used");
        }
        if (index > maxIndex - 1)
        {
            throw new IllegalStateException("index out of bounds");
        }
        
        /* determine tau */
        int tau = XMSSUtil.calculateTau(index, treeHeight);
        /* parent of leaf on height tau+1 is a left node */
        if (((index >> (tau + 1)) & 1) == 0 && (tau < (treeHeight - 1)))
        {
            keep.put(tau, authenticationPath.get(tau));
        }

        /* prepare addresses */
        byte[] lTreeAddress = new LTreeAddress.Builder()
            .withLayerAddress(otsHashAddress.getLayerAddress()).withTreeAddress(otsHashAddress.getTreeAddress())
            .build().toByteArray();
        byte[] hashTreeAddress = new HashTreeAddress.Builder()
            .withLayerAddress(otsHashAddress.getLayerAddress()).withTreeAddress(otsHashAddress.getTreeAddress())
            .build().toByteArray();
        /* and one pair of working buffers for whichever of the two branches below runs; see
         * XMSSNodeUtil.randomizeHash */
        int n = wotsPlus.getParams().getTreeDigestSize();
        byte[] nodeKey = new byte[n];
        byte[] nodeMask = new byte[2 * n];

        /* leaf is a left node */
        if (tau == 0)
        {
            otsHashAddress = XMSSNodeUtil.withOTSAddress(otsHashAddress, index);
            /*
             * import WOTSPlusSecretKey as its needed to calculate the public
             * key on the fly
             */
            wotsPlus.importKeys(wotsPlus.getWOTSPlusSecretKey(secretSeed, otsHashAddress), publicSeed);
            WOTSPlusPublicKeyParameters wotsPlusPublicKey = wotsPlus.getPublicKey(otsHashAddress);
            Pack.intToBigEndian(index, lTreeAddress, LTreeAddress.LTREE_ADDRESS_OFFSET);
            XMSSNode node = XMSSNodeUtil.lTree(wotsPlus, wotsPlusPublicKey, lTreeAddress, nodeKey, nodeMask);
            authenticationPath.set(0, node);
        }
        else
        {
            /* add new left node on height tau to authentication path */
            Pack.intToBigEndian(tau - 1, hashTreeAddress, HashTreeAddress.TREE_HEIGHT_OFFSET);
            Pack.intToBigEndian(index >> tau, hashTreeAddress, HashTreeAddress.TREE_INDEX_OFFSET);
            /*
             * import WOTSPlusSecretKey as its needed to calculate the public
             * key on the fly
             */
            wotsPlus.importKeys(wotsPlus.getWOTSPlusSecretKey(secretSeed, otsHashAddress), publicSeed);
            // the node this state kept the last time the path passed height tau - 1. One that
            // reached this index by signing always has it; one that arrived by import need not, and
            // reading through the gap raises a NullPointerException from inside the hash rather than
            // saying what is wrong.
            XMSSNode keptNode = keep.get(tau - 1);
            if (keptNode == null)
            {
                throw new IllegalStateException("missing keep node in BDS state");
            }
            XMSSNode node = XMSSNodeUtil.randomizeHash(wotsPlus, authenticationPath.get(tau - 1), keptNode,
                hashTreeAddress, nodeKey, nodeMask);
            node = node.incrementHeight();
            authenticationPath.set(tau, node);
            keep.remove(tau - 1);

            /* add new right nodes to authentication path */
            for (int height = 0; height < tau; height++)
            {
                if (height < (treeHeight - k))
                {
                    authenticationPath.set(height, treeHashInstances.get(height).getTailNode());
                }
                else
                {
                    // as for the kept node above: an imported state can be missing the queue for this
                    // height, or carry it empty, and either is a corrupt state rather than a
                    // NullPointerException or a NoSuchElementException from the queue itself
                    List<XMSSNode> retained = retain.get(height);
                    if (retained == null || retained.isEmpty())
                    {
                        throw new IllegalStateException("missing retain node in BDS state");
                    }
                    authenticationPath.set(height, retained.remove(0));
                }
            }

            /* reinitialize treehash instances */
            int minHeight = Math.min(tau, treeHeight - k);
            for (int height = 0; height < minHeight; height++)
            {
                int startIndex = index + 1 + (3 * (1 << height));
                if (startIndex < (1 << treeHeight))
                {
                    treeHashInstances.get(height).initialize(startIndex);
                }
            }
        }
 
        /* update treehash instances */
        for (int i = 0; i < (treeHeight - k) >> 1; i++)
        {
            BDSTreeHash treeHash = getBDSTreeHashInstanceForUpdate();
            if (treeHash != null)
            {
                treeHash.update(stack, wotsPlus, publicSeed, secretSeed, otsHashAddress);
            }
        }

        index++;
    }

    boolean isUsed()
    {
        return used;
    }

    void markUsed()
    {
        this.used = true;
    }

    private BDSTreeHash getBDSTreeHashInstanceForUpdate()
    {
        BDSTreeHash ret = null;
        for (BDSTreeHash treeHash : treeHashInstances)
        {
            if (treeHash.isFinished() || !treeHash.isInitialized())
            {
                continue;
            }
            if (ret == null)
            {
                ret = treeHash;
                continue;
            }
            if (treeHash.getHeight() < ret.getHeight())
            {
                ret = treeHash;
                continue;
            }
            if (treeHash.getHeight() == ret.getHeight())
            {
                if (treeHash.getIndexLeaf() < ret.getIndexLeaf())
                {
                    ret = treeHash;
                }
            }
        }
        return ret;
    }

    void validate()
    {
        if (authenticationPath == null)
        {
            throw new IllegalStateException("authenticationPath == null");
        }
        if (retain == null)
        {
            throw new IllegalStateException("retain == null");
        }
        if (stack == null)
        {
            throw new IllegalStateException("stack == null");
        }
        if (treeHashInstances == null)
        {
            throw new IllegalStateException("treeHashInstances == null");
        }
        if (keep == null)
        {
            throw new IllegalStateException("keep == null");
        }
        if (treeHeight < 2 || treeHeight > XMSSParameters.MAX_HEIGHT)
        {
            throw new IllegalStateException("treeHeight in BDS state out of bounds");
        }
        if (k > treeHeight || k < 2 || ((treeHeight - k) & 1) != 0)
        {
            throw new IllegalStateException("k in BDS state out of bounds");
        }
        int maxIndexLimit = (1 << treeHeight) - 1;
        if (maxIndex < 0 || maxIndex > maxIndexLimit || index < 0 || index > maxIndex + 1)
        {
            throw new IllegalStateException("index in BDS state out of bounds");
        }
        if (root == null)
        {
            if (!authenticationPath.isEmpty())
            {
                throw new IllegalStateException("authenticationPath present without root");
            }
        }
        else
        {
            if (root.getHeight() != treeHeight || authenticationPath.size() != treeHeight)
            {
                throw new IllegalStateException("inconsistent root or authenticationPath in BDS state");
            }
        }
        if (treeHashInstances.size() != treeHeight - k || retain.size() > k - 1
            || stack.size() > treeHeight || keep.size() > treeHeight)
        {
            throw new IllegalStateException("inconsistent collection size in BDS state");
        }
    }

    public void validate(XMSSParameters params)
    {
        validate();
        if (treeHeight != params.getHeight() || k != params.getK())
        {
            throw new IllegalStateException("BDS state does not match XMSS parameters");
        }

        int digestSize = params.getTreeDigestSize();
        validateNode(root, digestSize, treeHeight, treeHeight);
        for (int i = 0; i < authenticationPath.size(); i++)
        {
            validateRequiredNode(authenticationPath.get(i), digestSize, i, i);
        }

        for (Iterator<Integer> it = retain.keySet().iterator(); it.hasNext();)
        {
            int height = it.next().intValue();
            if (height < treeHeight - k || height > treeHeight - 2)
            {
                throw new IllegalStateException("retain height in BDS state out of bounds");
            }
            List<XMSSNode> nodes = retain.get(height);
            int maximumRetained = (1 << (treeHeight - height - 1)) - 1;
            if (nodes == null || nodes.size() > maximumRetained)
            {
                throw new IllegalStateException("retain queue in BDS state out of bounds");
            }
            validateNodes(nodes, digestSize, height, height);
        }

        validateNodes(stack, digestSize, 0, treeHeight);
        for (int i = 0; i < treeHashInstances.size(); i++)
        {
            BDSTreeHash treeHash = treeHashInstances.get(i);
            if (treeHash == null || treeHash.getInitialHeight() != i || treeHash.getRawHeight() < 0
                || treeHash.getRawHeight() > i || treeHash.getIndexLeaf() < 0
                || treeHash.getIndexLeaf() > (1 << treeHeight) - 1)
            {
                throw new IllegalStateException("tree hash in BDS state out of bounds");
            }
            validateNode(treeHash.getTailNode(), digestSize, 0, i);
        }

        for (Iterator<Integer> it = keep.keySet().iterator(); it.hasNext();)
        {
            int height = it.next().intValue();
            if (height < 0 || height > treeHeight - 2)
            {
                throw new IllegalStateException("keep height in BDS state out of bounds");
            }
            validateRequiredNode(keep.get(height), digestSize, height, height);
        }
    }

    /**
     * Confirm the root this state carries is the one the enclosing private key declares. The two are
     * independent copies of the same value in one encoding and always agree on a genuine key, so a
     * disagreement means the stored key has been corrupted. Left unchecked, a corrupted root is
     * accepted and then poisons every signature the key makes - the root is hashed into the message
     * digest, so the signature simply does not verify, with nothing to say why (github #2414).
     * <p>
     * A null root on either side is not compared: BDS.validate tolerates an absent root node, and a
     * key built without one carries zeros.
     *
     * @param expectedRoot the root the private key declares.
     */
    public void validateRoot(byte[] expectedRoot)
    {
        if (root == null || expectedRoot == null)
        {
            return;
        }

        if (!Arrays.areEqual(root.getValue(), expectedRoot))
        {
            throw new IllegalStateException("BDS state root does not match the private key root");
        }
    }

    public void validate(XMSSParameters params, int expectedIndex)
    {
        validate(params);
        // RFC 8391 Section 1.1 requires each secret-key state to be used only once. Tie restored BDS
        // state to the enclosing private-key index so stale or mismatched traversal state is rejected.
        if (index != expectedIndex)
        {
            throw new IllegalStateException("BDS state has wrong index");
        }
    }

    private static void validateNodes(Iterable<XMSSNode> nodes, int digestSize, int minimumHeight,
        int maximumHeight)
    {
        for (Iterator<XMSSNode> it = nodes.iterator(); it.hasNext();)
        {
            validateRequiredNode(it.next(), digestSize, minimumHeight, maximumHeight);
        }
    }

    private static void validateRequiredNode(XMSSNode node, int digestSize, int minimumHeight,
        int maximumHeight)
    {
        if (node == null)
        {
            throw new IllegalStateException("null XMSS node in BDS state");
        }
        validateNode(node, digestSize, minimumHeight, maximumHeight);
    }

    private static void validateNode(XMSSNode node, int digestSize, int minimumHeight, int maximumHeight)
    {
        if (node != null)
        {
            if (node.getHeight() < minimumHeight || node.getHeight() > maximumHeight
                || !node.hasValueLength(digestSize))
            {
                throw new IllegalStateException("XMSS node in BDS state out of bounds");
            }
        }
    }

    int getTreeHeight()
    {
        return treeHeight;
    }

    XMSSNode getRoot()
    {
        return root;
    }

    List<XMSSNode> getAuthenticationPath()
    {
        List<XMSSNode> authenticationPath = new ArrayList<XMSSNode>();

        for (XMSSNode node : this.authenticationPath)
        {
            authenticationPath.add(node);
        }
        return authenticationPath;
    }

    public int getIndex()
    {
        return index;
    }

    public int getMaxIndex()
    {
        return maxIndex;
    }

    int getK()
    {
        return k;
    }

    Map<Integer, List<XMSSNode>> getRetain()
    {
        Map<Integer, List<XMSSNode>> result = new TreeMap<Integer, List<XMSSNode>>();
        result.putAll(retain);
        return result;
    }

    /*
     * These three hand out a copy, as getAuthenticationPath() and getRetain() beside them do and
     * as the constructors do when they take a state apart: what they are copying is the live
     * traversal state of a one-time key, and a caller that changed it would corrupt the signing
     * position with nothing to catch it. They copy to the same depth the constructors do - the
     * collection, and each tree hash instance, but not the nodes, which are read-only in practice.
     */

    Stack<XMSSNode> getStack()
    {
        return cloneStack(stack);
    }

    List<BDSTreeHash> getTreeHashInstances()
    {
        return cloneTreeHashInstances(treeHashInstances);
    }

    Map<Integer, XMSSNode> getKeep()
    {
        return new TreeMap<Integer, XMSSNode>(keep);
    }

    public BDS withWOTSDigest(ASN1ObjectIdentifier digestName)
    {
        return new BDS(this, digestName, -1);
    }

    public BDS withWOTSDigest(ASN1ObjectIdentifier digestName, int digestSize)
    {
        return new BDS(this, digestName, digestSize);
    }

    public BDS withMaxIndex(int maxIndex, ASN1ObjectIdentifier digestName)
    {
        return new BDS(this, maxIndex, digestName, -1);
    }

    public BDS withMaxIndex(int maxIndex, ASN1ObjectIdentifier digestName, int digestSize)
    {
        return new BDS(this, maxIndex, digestName, digestSize);
    }

    private void readObject(
        ObjectInputStream in)
        throws IOException, ClassNotFoundException
    {
        in.defaultReadObject();

        // Java deserialization does not run field initializers, so a crafted stream that declares
        // no fields leaves every collection this state is made of null, and one that declares them
        // can put nulls inside them. The import path rebuilds a state around the digest its key
        // names before anything validates it - withWOTSDigest() clones all five collections - so
        // the matching checks in validate() are reached too late to be what rejects this. Refuse it
        // here, where the stream enters. The nodes those collections hold are validate()'s to check:
        // it is reached with them, and it reports a null one rather than dereferencing it.
        if (authenticationPath == null || retain == null || stack == null
            || treeHashInstances == null || keep == null)
        {
            throw new IOException("incomplete BDS state");
        }
        for (Iterator<Integer> it = retain.keySet().iterator(); it.hasNext();)
        {
            Integer height = it.next();

            // a null key is not merely absent state: TreeMap.get(null) throws in its own right
            if (height == null || retain.get(height) == null)
            {
                throw new IOException("incomplete BDS state");
            }
        }
        for (Iterator<Integer> it = keep.keySet().iterator(); it.hasNext();)
        {
            Integer height = it.next();

            // as with retain above: a null key is not merely absent state, TreeMap.get(null) throws
            if (height == null || keep.get(height) == null)
            {
                throw new IOException("incomplete BDS state");
            }
        }
        for (Iterator<BDSTreeHash> it = treeHashInstances.iterator(); it.hasNext();)
        {
            if (it.next() == null)
            {
                throw new IOException("incomplete BDS state");
            }
        }

        // as in BDSStateMap.readObject(): ObjectInputStream.available() is an estimate of what can
        // be read without blocking rather than an end of data test, and taking a state that does
        // carry a maximum index for one that does not would widen a key shard back to the whole
        // range of the key it came from. read() returns -1 only at the end of this object's data.
        int first = in.read();

        if (first < 0)
        {
            // written before the maximum index was recorded: a BDS knows its own tree height, so
            // it can resolve that here rather than having to mark it for someone else to resolve
            this.maxIndex = (1 << treeHeight) - 1;
        }
        else
        {
            byte[] encoded = new byte[4];

            encoded[0] = (byte)first;
            in.readFully(encoded, 1, encoded.length - 1);

            this.maxIndex = Pack.bigEndianToInt(encoded, 0);
        }
        if (maxIndex > ((1 << treeHeight) - 1) || index > (maxIndex + 1) || in.read() >= 0)
        {
            throw new IOException("inconsistent BDS data detected");
        }
    }

    private void writeObject(
        ObjectOutputStream out)
        throws IOException
    {
        out.defaultWriteObject();

        out.writeInt(this.maxIndex);
    }
}
