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

    BDS(BDS last)
    {
        this.wotsPlus = new WOTSPlus(last.wotsPlus.getParams());
        this.treeHeight = last.treeHeight;
        this.k = last.k;
        this.root = last.root;
        this.authenticationPath = cloneAuthenticationPath(last.authenticationPath);
        this.retain = cloneRetain(last.retain);
        this.stack = cloneStack(last.stack);
        this.treeHashInstances = cloneTreeHashInstances(last.treeHashInstances);
        this.keep = new TreeMap<Integer, XMSSNode>(last.keep);
        this.index = last.index;
        this.maxIndex = last.maxIndex;
        this.used = last.used;
    }

    private BDS(BDS last, byte[] publicSeed, byte[] secretKeySeed, OTSHashAddress otsHashAddress)
    {
        this.wotsPlus = new WOTSPlus(last.wotsPlus.getParams());
        this.treeHeight = last.treeHeight;
        this.k = last.k;
        this.root = last.root;
        this.authenticationPath = cloneAuthenticationPath(last.authenticationPath);
        this.retain = cloneRetain(last.retain);
        this.stack = cloneStack(last.stack);
        this.treeHashInstances = cloneTreeHashInstances(last.treeHashInstances);
        this.keep = new TreeMap<Integer, XMSSNode>(last.keep);
        this.index = last.index;
        this.maxIndex = last.maxIndex;
        this.used = false;

        this.nextAuthenticationPath(publicSeed, secretKeySeed, otsHashAddress);
    }

    private BDS(BDS last, ASN1ObjectIdentifier digest, int digestSize)
    {
        this.wotsPlus = new WOTSPlus(digestSize > 0 ? new WOTSPlusParameters(digest, digestSize) : new WOTSPlusParameters(digest));
        this.treeHeight = last.treeHeight;
        this.k = last.k;
        this.root = last.root;
        this.authenticationPath = cloneAuthenticationPath(last.authenticationPath);
        this.retain = cloneRetain(last.retain);
        this.stack = cloneStack(last.stack);
        this.treeHashInstances = cloneTreeHashInstances(last.treeHashInstances);
        this.keep = new TreeMap<Integer, XMSSNode>(last.keep);
        this.index = last.index;
        this.maxIndex = last.maxIndex;
        this.used = last.used;
        this.validate();
    }

    private BDS(BDS last, int maxIndex, ASN1ObjectIdentifier digest, int digestSize)
    {
        this.wotsPlus = new WOTSPlus(digestSize > 0 ? new WOTSPlusParameters(digest, digestSize) : new WOTSPlusParameters(digest));
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
        this.used = last.used;
        this.validate();
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
        if (otsHashAddress == null)
        {
            throw new NullPointerException("otsHashAddress == null");
        }
        /* prepare addresses */
        LTreeAddress lTreeAddress = (LTreeAddress)new LTreeAddress.Builder()
            .withLayerAddress(otsHashAddress.getLayerAddress()).withTreeAddress(otsHashAddress.getTreeAddress())
            .build();
        HashTreeAddress hashTreeAddress = (HashTreeAddress)new HashTreeAddress.Builder()
            .withLayerAddress(otsHashAddress.getLayerAddress()).withTreeAddress(otsHashAddress.getTreeAddress())
            .build();

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
            lTreeAddress = withLTreeAddress(lTreeAddress, indexLeaf);
            XMSSNode node = XMSSNodeUtil.lTree(wotsPlus, wotsPlusPublicKey, lTreeAddress);

            // NOT XMSSNodeUtil.withTreeIndex: the tree height is deliberately left out, so that it
            // resets to 0 for the new leaf. The loop below walks it back up, so carrying it over
            // here would start each leaf at the height the previous one finished at.
            hashTreeAddress = (HashTreeAddress)new HashTreeAddress.Builder()
                .withLayerAddress(hashTreeAddress.getLayerAddress())
                .withTreeAddress(hashTreeAddress.getTreeAddress()).withTreeIndex(indexLeaf)
                .withKeyAndMask(hashTreeAddress.getKeyAndMask()).build();
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
                hashTreeAddress = XMSSNodeUtil.withTreeIndex(hashTreeAddress,
                    (hashTreeAddress.getTreeIndex() - 1) / 2);
                node = XMSSNodeUtil.randomizeHash(wotsPlus, stack.pop(), node, hashTreeAddress);
                node = node.incrementHeight();
                hashTreeAddress = XMSSNodeUtil.withTreeHeight(hashTreeAddress,
                    hashTreeAddress.getTreeHeight() + 1);
            }
            /* push to stack */
            stack.push(node);
        }
        root = stack.pop();
    }

    private void nextAuthenticationPath(byte[] publicSeed, byte[] secretSeed, OTSHashAddress otsHashAddress)
    {
        if (otsHashAddress == null)
        {
            throw new NullPointerException("otsHashAddress == null");
        }
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
        LTreeAddress lTreeAddress = (LTreeAddress)new LTreeAddress.Builder()
            .withLayerAddress(otsHashAddress.getLayerAddress()).withTreeAddress(otsHashAddress.getTreeAddress())
            .build();
        HashTreeAddress hashTreeAddress = (HashTreeAddress)new HashTreeAddress.Builder()
            .withLayerAddress(otsHashAddress.getLayerAddress()).withTreeAddress(otsHashAddress.getTreeAddress())
            .build();

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
            lTreeAddress = withLTreeAddress(lTreeAddress, index);
            XMSSNode node = XMSSNodeUtil.lTree(wotsPlus, wotsPlusPublicKey, lTreeAddress);
            authenticationPath.set(0, node);
        }
        else
        {
            /* add new left node on height tau to authentication path */
            // two fields at once, so neither of the single-field helpers fits
            hashTreeAddress = (HashTreeAddress)new HashTreeAddress.Builder()
                .withLayerAddress(hashTreeAddress.getLayerAddress())
                .withTreeAddress(hashTreeAddress.getTreeAddress()).withTreeHeight(tau - 1)
                .withTreeIndex(index >> tau).withKeyAndMask(hashTreeAddress.getKeyAndMask()).build();
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
            XMSSNode node = XMSSNodeUtil.randomizeHash(wotsPlus, authenticationPath.get(tau - 1), keptNode, hashTreeAddress);
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
        if (treeHeight < 2 || treeHeight > 30)
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
            byte[] value = node.getValue();
            if (node.getHeight() < minimumHeight || node.getHeight() > maximumHeight
                || value == null || value.length != digestSize)
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

    Stack<XMSSNode> getStack()
    {
        return stack;
    }

    List<BDSTreeHash> getTreeHashInstances()
    {
        return treeHashInstances;
    }

    Map<Integer, XMSSNode> getKeep()
    {
        return keep;
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

    /**
     * The given address with its L-tree address replaced and every other field carried over, as
     * the leaf walks in initialize() and nextAuthenticationPath() need when they step to the next
     * leaf. An XMSS address is immutable, so setting one field means rebuilding the whole address.
     *
     * @param address      L-tree address to copy.
     * @param lTreeAddress L-tree address value to set.
     * @return address with the given L-tree address.
     */
    private static LTreeAddress withLTreeAddress(LTreeAddress address, int lTreeAddress)
    {
        return (LTreeAddress)new LTreeAddress.Builder()
            .withLayerAddress(address.getLayerAddress()).withTreeAddress(address.getTreeAddress())
            .withLTreeAddress(lTreeAddress).withTreeHeight(address.getTreeHeight())
            .withTreeIndex(address.getTreeIndex()).withKeyAndMask(address.getKeyAndMask()).build();
    }
}
