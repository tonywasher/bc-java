package org.bouncycastle.crypto.signers.xmss;

import java.io.Serializable;
import java.util.Stack;


class BDSTreeHash
    implements Serializable, Cloneable
{
    private static final long serialVersionUID = 1L;

    private XMSSNode tailNode;
    private final int initialHeight;
    private int height;
    private int nextIndex;
    private boolean initialized;
    private boolean finished;

    BDSTreeHash(int initialHeight)
    {
        this.initialHeight = initialHeight;
        initialized = false;
        finished = false;
    }

    BDSTreeHash(int initialHeight, int height, int nextIndex, boolean initialized, boolean finished,
        XMSSNode tailNode)
    {
        this.initialHeight = initialHeight;
        this.height = height;
        this.nextIndex = nextIndex;
        this.initialized = initialized;
        this.finished = finished;
        this.tailNode = tailNode;
    }

    void initialize(int nextIndex)
    {
        tailNode = null;
        height = initialHeight;
        this.nextIndex = nextIndex;
        initialized = true;
        finished = false;
    }

    void update(Stack<XMSSNode> stack, WOTSPlus wotsPlus, byte[] publicSeed, byte[] secretSeed, OTSHashAddress otsHashAddress)
    {
        if (finished || !initialized)
        {
            throw new IllegalStateException("finished or not initialized");
        }
            /* prepare addresses */
        otsHashAddress = XMSSNodeUtil.withOTSAddress(otsHashAddress, nextIndex);
        LTreeAddress lTreeAddress = (LTreeAddress)new LTreeAddress.Builder()
            .withLayerAddress(otsHashAddress.getLayerAddress()).withTreeAddress(otsHashAddress.getTreeAddress())
            .withLTreeAddress(nextIndex).build();
        HashTreeAddress hashTreeAddress = (HashTreeAddress)new HashTreeAddress.Builder()
            .withLayerAddress(otsHashAddress.getLayerAddress()).withTreeAddress(otsHashAddress.getTreeAddress())
            .withTreeIndex(nextIndex).build();
            /* calculate leaf node */
        wotsPlus.importKeys(wotsPlus.getWOTSPlusSecretKey(secretSeed, otsHashAddress), publicSeed);
        WOTSPlusPublicKeyParameters wotsPlusPublicKey = wotsPlus.getPublicKey(otsHashAddress);
        XMSSNode node = XMSSNodeUtil.lTree(wotsPlus, wotsPlusPublicKey, lTreeAddress);

        while (!stack.isEmpty() && stack.peek().getHeight() == node.getHeight()
            && stack.peek().getHeight() != initialHeight)
        {
            hashTreeAddress = XMSSNodeUtil.withTreeIndex(hashTreeAddress,
                (hashTreeAddress.getTreeIndex() - 1) / 2);
            node = XMSSNodeUtil.randomizeHash(wotsPlus, stack.pop(), node, hashTreeAddress);
            node = node.incrementHeight();
            hashTreeAddress = XMSSNodeUtil.withTreeHeight(hashTreeAddress,
                hashTreeAddress.getTreeHeight() + 1);
        }

        if (tailNode == null)
        {
            tailNode = node;
        }
        else
        {
            if (tailNode.getHeight() == node.getHeight())
            {
                hashTreeAddress = XMSSNodeUtil.withTreeIndex(hashTreeAddress,
                    (hashTreeAddress.getTreeIndex() - 1) / 2);
                node = XMSSNodeUtil.randomizeHash(wotsPlus, tailNode, node, hashTreeAddress);
                node = node.incrementHeight();
                tailNode = node;
                // the last step of the same climb the loop above makes - parent, hash, then name
                // the level above. This is the final climb, so nothing reads the result; it is
                // kept so both merges read alike and so the code still matches the unconditional
                // increment that closes the loop of RFC 8391 sec. 4.1.6 algorithm 9. The address
                // names the height of the children, so the hash above is at the right level.
                hashTreeAddress = XMSSNodeUtil.withTreeHeight(hashTreeAddress,
                    hashTreeAddress.getTreeHeight() + 1);
            }
            else
            {
                stack.push(node);
            }
        }

        if (tailNode.getHeight() == initialHeight)
        {
            finished = true;
        }
        else
        {
            height = node.getHeight();
            nextIndex++;
        }
    }

    int getHeight()
    {
        if (!initialized || finished)
        {
            return Integer.MAX_VALUE;
        }
        return height;
    }

    int getIndexLeaf()
    {
        return nextIndex;
    }

    int getInitialHeight()
    {
        return initialHeight;
    }

    int getRawHeight()
    {
        return height;
    }

    void setNode(XMSSNode node)
    {
        tailNode = node;
        height = node.getHeight();
        if (height == initialHeight)
        {
            finished = true;
        }
    }

    boolean isFinished()
    {
        return finished;
    }

    boolean isInitialized()
    {
        return initialized;
    }

    public XMSSNode getTailNode()
    {
        return tailNode;
    }

    protected BDSTreeHash clone()
    {
        BDSTreeHash th = new BDSTreeHash(this.initialHeight);

        th.tailNode = this.tailNode;
        th.height = this.height;
        th.nextIndex = this.nextIndex;
        th.initialized = this.initialized;
        th.finished = this.finished;

        return th;
    }
}
