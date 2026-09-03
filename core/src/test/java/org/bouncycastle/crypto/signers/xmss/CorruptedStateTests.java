package org.bouncycastle.crypto.signers.xmss;

import java.security.SecureRandom;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.XMSSKeyPairGenerator;
import org.bouncycastle.crypto.params.XMSSKeyGenerationParameters;
import org.bouncycastle.crypto.params.XMSSParameters;
import org.bouncycastle.crypto.params.XMSSPrivateKeyParameters;
import org.bouncycastle.crypto.signers.XMSSSigner;
import org.bouncycastle.util.Arrays;

/**
 * The BDS traversal state stored with a private key carries two collections the next authentication
 * path reads from - the node kept when the path last passed a height, and the queue of retained
 * right nodes - and a state that reached its index by signing always has the entries the next step
 * will ask for. A state that arrived by import need not: the structural checks the encoding and
 * BDS.validate() make reject entries that are present and wrong, but say nothing about ones that
 * are simply absent, so the reads used to fall through into a NullPointerException from inside the
 * hash function, or a NoSuchElementException from the queue. Both now say what is wrong.
 */
public class CorruptedStateTests
    extends TestCase
{
    private static final int HEIGHT = 4;

    /**
     * The harness itself: taking a key apart and putting it back together unchanged has to leave a
     * key that still signs, or the corruption tests below would pass for the wrong reason.
     */
    public void testUntouchedStateStillSigns()
        throws Exception
    {
        XMSSPrivateKeyParameters privKey = importRebuilt(1, null);

        assertEquals(1, privKey.getIndex());

        XMSSSigner signer = new XMSSSigner();

        signer.init(true, privKey);
        signer.update((byte)9);
        signer.generateSignature();
    }

    /**
     * Index 1 is the first index whose next authentication path reads the kept node - tau is 1
     * there, so the step needs keep[0], put there by the step at index 0.
     */
    public void testMissingKeepNodeReported()
        throws Exception
    {
        checkReported(1, "keep", "missing keep node in BDS state");
    }

    /**
     * Index 7 is the first index whose next authentication path reaches into the retain queue - tau
     * is 3 there, and heights at or above treeHeight - k are served from retain rather than from a
     * tree hash instance.
     */
    public void testMissingRetainQueueReported()
        throws Exception
    {
        checkReported(7, "retain", "missing retain node in BDS state");
    }

    /**
     * A queue that is present but has nothing left in it: structurally valid, and the read used to
     * come back as a NoSuchElementException raised by the queue itself.
     */
    public void testEmptyRetainQueueReported()
        throws Exception
    {
        checkReported(7, "retain-empty", "missing retain node in BDS state");
    }

    private void checkReported(int atIndex, String drop, String expected)
        throws Exception
    {
        XMSSPrivateKeyParameters privKey = importRebuilt(atIndex, drop);
        XMSSSigner signer = new XMSSSigner();

        signer.init(true, privKey);
        signer.update((byte)9);

        try
        {
            signer.generateSignature();
            fail("corrupt state signed: " + drop);
        }
        catch (IllegalStateException e)
        {
            assertEquals(expected, e.getMessage());
        }
    }

    /**
     * A private key advanced to {@code atIndex}, re-encoded with the named part of its BDS state
     * removed, and imported again through the ordinary encoded-key path.
     */
    private XMSSPrivateKeyParameters importRebuilt(int atIndex, String drop)
        throws Exception
    {
        XMSSParameters params = new XMSSParameters(HEIGHT, new SHA256Digest());
        XMSSKeyPairGenerator kpg = new XMSSKeyPairGenerator();

        kpg.init(new XMSSKeyGenerationParameters(params, new SecureRandom()));

        AsymmetricCipherKeyPair kp = kpg.generateKeyPair();
        XMSSSigner signer = new XMSSSigner();

        signer.init(true, kp.getPrivate());

        for (int i = 0; i != atIndex; i++)
        {
            signer.update((byte)i);
            signer.generateSignature();
        }

        byte[] encoded = ((XMSSPrivateKeyParameters)signer.getUpdatedPrivateKey()).getEncoded();
        int n = params.getTreeDigestSize();
        int prefix = 4 + 4 * n;
        byte[] head = Arrays.copyOfRange(encoded, 0, prefix);
        // head is index(4) || secretKeySeed(n) || secretKeyPRF(n) || publicSeed(n) || root(n)
        byte[] publicSeed = Arrays.copyOfRange(head, 4 + 2 * n, 4 + 3 * n);
        BDS state = BDSStateCodec.decodeBDS(Arrays.copyOfRange(encoded, prefix, encoded.length), publicSeed);

        assertEquals(atIndex, state.getIndex());

        // getKeep(), getRetain() and getTreeHashInstances() below all hand out copies, so the
        // corruption applied here does not reach the state it was decoded from
        Map<Integer, XMSSNode> keep = state.getKeep();
        Map<Integer, List<XMSSNode>> retain = state.getRetain();

        if ("keep".equals(drop))
        {
            assertFalse("nothing kept at index " + atIndex, keep.isEmpty());
            keep.clear();
        }
        else if ("retain".equals(drop))
        {
            assertFalse("nothing retained at index " + atIndex, retain.isEmpty());
            retain = new TreeMap<Integer, List<XMSSNode>>();
        }
        else if ("retain-empty".equals(drop))
        {
            Map<Integer, List<XMSSNode>> emptied = new TreeMap<Integer, List<XMSSNode>>();

            for (Iterator<Integer> it = retain.keySet().iterator(); it.hasNext();)
            {
                emptied.put(it.next(), new LinkedList<XMSSNode>());
            }

            assertFalse("nothing retained at index " + atIndex, emptied.isEmpty());
            retain = emptied;
        }
        else if (drop != null)
        {
            fail("unknown corruption: " + drop);
        }

        BDS rebuilt = new BDS(state.getTreeHeight(), state.getK(), state.getMaxIndex(), state.getIndex(),
            state.isUsed(), state.getRoot(), state.getAuthenticationPath(), retain, state.getStack(),
            state.getTreeHashInstances(), keep);

        return new XMSSPrivateKeyParameters.Builder(params)
            .withPrivateKey(Arrays.concatenate(head, BDSStateCodec.encode(rebuilt, publicSeed))).build();
    }
}
