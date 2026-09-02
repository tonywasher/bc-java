package org.bouncycastle.crypto.signers.xmss;

import java.io.IOException;
import java.security.SecureRandom;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.ExhaustedPrivateKeyException;
import org.bouncycastle.crypto.params.XMSSMTParameters;
import org.bouncycastle.crypto.params.XMSSMTPrivateKeyParameters;
import org.bouncycastle.crypto.params.XMSSMTPublicKeyParameters;
import org.bouncycastle.crypto.params.XMSSParameters;
import org.bouncycastle.crypto.params.XMSSPrivateKeyParameters;
import org.bouncycastle.crypto.params.XMSSPublicKeyParameters;
import org.bouncycastle.util.Arrays;

/**
 * The XMSS and XMSS^MT (RFC 8391) operations the key parameter classes, the key pair generators and
 * the signers are built on: key pair generation, signature generation and verification, the WOTS+
 * and OID parameter derivations, and the handful of encoding helpers the key classes need.
 * <p>
 * This is the only public class of the package besides the two opaque BDS traversal-state types
 * ({@link BDS} and {@link BDSStateMap}, which an XMSS / XMSS^MT private key carries as a field and
 * so cannot be package-private). Everything else here - WOTS+, the hash addressing scheme, the
 * keyed hash functions, the tree arithmetic and the signature structures - is implementation
 * detail, and no compatibility is promised for it.
 */
public final class XMSSEngine
{
    private XMSSEngine()
    {
    }

    /**
     * The OID of a digest by its algorithm name, for the tree digest of an XMSS parameter set.
     */
    public static ASN1ObjectIdentifier getDigestOID(String name)
    {
        return DigestUtil.getDigestOID(name);
    }

    /**
     * The algorithm name of a tree digest OID.
     */
    public static String getDigestName(ASN1ObjectIdentifier oid)
    {
        return DigestUtil.getDigestName(oid);
    }

    /**
     * The output size in bytes of a tree digest, the security parameter n.
     */
    public static int getDigestSize(ASN1ObjectIdentifier oid)
    {
        return XMSSUtil.getDigestSize(DigestUtil.getDigest(oid));
    }

    /**
     * A tree digest by its OID. Note the SP 800-208 SHAKE256/192 and SHAKE256/256 parameter sets
     * name id-shake256-len, which no other algorithm in this package uses.
     */
    public static Digest getDigest(ASN1ObjectIdentifier oid)
    {
        return DigestUtil.getDigest(oid);
    }

    /**
     * The number of n-byte elements in a WOTS+ key or signature, len = len1 + len2 (RFC 8391
     * sec. 3.1.1). Rejects a tree digest and security parameter that are not a registered WOTS+
     * combination, which is where an unusable XMSS parameter set is caught.
     */
    public static int getWOTSPlusLen(ASN1ObjectIdentifier treeDigestOID, int digestSize)
    {
        return new WOTSPlusParameters(treeDigestOID, digestSize).getLen();
    }

    /**
     * The Winternitz parameter w, fixed at 16 by RFC 8391 sec. 5.
     */
    public static int getWinternitzParameter()
    {
        return WOTSPlusParameters.WINTERNITZ_PARAMETER;
    }

    /**
     * The RFC 8391 sec. 5.3 XMSS parameter-set identifier for this combination, or 0 when the
     * combination is not one of the registered sets.
     */
    public static int lookupXMSSOid(String treeDigest, int digestSize, int winternitzParameter, int len, int height)
    {
        DefaultXMSSOid oid = DefaultXMSSOid.lookup(treeDigest, digestSize, winternitzParameter, len, height);

        return (oid != null) ? oid.getOid() : 0;
    }

    /**
     * The RFC 8391 sec. 5.4 XMSS^MT parameter-set identifier for this combination, or 0 when the
     * combination is not one of the registered sets.
     */
    public static int lookupXMSSMTOid(String treeDigest, int digestSize, int winternitzParameter, int len,
                                      int height, int layers)
    {
        DefaultXMSSMTOid oid = DefaultXMSSMTOid.lookup(treeDigest, digestSize, winternitzParameter, len, height, layers);

        return (oid != null) ? oid.getOid() : 0;
    }

    /**
     * Generate an XMSS key pair (RFC 8391 sec. 4.1.7).
     */
    public static AsymmetricCipherKeyPair generateKeyPair(XMSSParameters params, SecureRandom prng)
    {
        int n = params.getTreeDigestSize();
        byte[] secretKeySeed = new byte[n];
        prng.nextBytes(secretKeySeed);
        byte[] secretKeyPRF = new byte[n];
        prng.nextBytes(secretKeyPRF);
        byte[] publicSeed = new byte[n];
        prng.nextBytes(publicSeed);

        BDS bdsState = new BDS(params, publicSeed, secretKeySeed, (OTSHashAddress)new OTSHashAddress.Builder().build());
        byte[] root = bdsState.getRoot().getValue();

        XMSSPrivateKeyParameters privateKey = new XMSSPrivateKeyParameters.Builder(params)
            .withSecretKeySeed(secretKeySeed).withSecretKeyPRF(secretKeyPRF)
            .withPublicSeed(publicSeed).withRoot(root)
            .withBDSState(bdsState).build();

        XMSSPublicKeyParameters publicKey = new XMSSPublicKeyParameters.Builder(params).withRoot(root)
            .withPublicSeed(publicSeed).build();

        return new AsymmetricCipherKeyPair(publicKey, privateKey);
    }

    /**
     * Generate an XMSS^MT key pair (RFC 8391 sec. 4.2.5).
     */
    public static AsymmetricCipherKeyPair generateMTKeyPair(XMSSMTParameters params, SecureRandom prng)
    {
        XMSSParameters xmssParams = params.getXMSSParameters();

        int n = params.getTreeDigestSize();
        byte[] secretKeySeed = new byte[n];
        prng.nextBytes(secretKeySeed);
        byte[] secretKeyPRF = new byte[n];
        prng.nextBytes(secretKeyPRF);
        byte[] publicSeed = new byte[n];
        prng.nextBytes(publicSeed);

        BDSStateMap bdsState = new BDSStateMap((1L << params.getHeight()) - 1);

        /* import to xmss */
        newWOTSPlus(xmssParams).importKeys(new byte[n], publicSeed);

        /* get root */
        int rootLayerIndex = params.getLayers() - 1;
        OTSHashAddress otsHashAddress = (OTSHashAddress)new OTSHashAddress.Builder().withLayerAddress(rootLayerIndex)
            .build();

        /* store BDS instance of root xmss instance */
        BDS bdsRoot = new BDS(xmssParams, publicSeed, secretKeySeed, otsHashAddress);
        byte[] root = bdsRoot.getRoot().getValue();
        bdsState.put(rootLayerIndex, bdsRoot);

        /* set XMSS^MT root / create public key */
        XMSSMTPrivateKeyParameters privateKey = new XMSSMTPrivateKeyParameters.Builder(params)
            .withSecretKeySeed(secretKeySeed).withSecretKeyPRF(secretKeyPRF).withPublicSeed(publicSeed)
            .withRoot(root).withBDSState(bdsState).build();
        XMSSMTPublicKeyParameters publicKey = new XMSSMTPublicKeyParameters.Builder(params).withRoot(root)
            .withPublicSeed(publicSeed).build();

        return new AsymmetricCipherKeyPair(publicKey, privateKey);
    }

    /**
     * Whether the key's BDS traversal state has been initialised, i.e. whether it can sign. A key
     * decoded from an encoding that carried no traversal state has none.
     */
    public static boolean hasTraversalState(XMSSPrivateKeyParameters privateKey)
    {
        return !privateKey.getBDSState().getAuthenticationPath().isEmpty();
    }

    /**
     * Whether the key's BDS traversal state has been initialised, i.e. whether it can sign.
     */
    public static boolean hasTraversalState(XMSSMTPrivateKeyParameters privateKey)
    {
        return !privateKey.getBDSState().isEmpty();
    }

    /**
     * Generate an XMSS signature over {@code message} and advance the key's traversal state
     * (RFC 8391 sec. 4.1.9).
     * <p>
     * The key is held locked across the whole check, sign and advance sequence. RFC 8391 sec. 1.1
     * requires each one-time key to be used exactly once, and this method both reads the index and
     * rolls the key past it: two threads entering with the same key and nothing serializing them
     * sign different messages under the same one-time key, and a WOTS+ key used twice discloses
     * enough of itself to forge. The key's own accessors are individually synchronized, which does
     * not make the compound sequence atomic, so the lock is taken here rather than left to the
     * caller - this is a public entry point and cannot assume one. {@code XMSSSigner} holds the
     * same monitor and Java monitors are reentrant, so that path is unchanged; LMS takes the
     * equivalent lock inside the key itself.
     * </p>
     */
    public static byte[] generateSignature(XMSSPrivateKeyParameters privateKey, byte[] message)
    {
        synchronized (privateKey)
        {
            return doGenerateSignature(privateKey, message);
        }
    }

    private static byte[] doGenerateSignature(XMSSPrivateKeyParameters privateKey, byte[] message)
    {
        XMSSParameters params = privateKey.getParameters();
        WOTSPlus wotsPlus = newWOTSPlus(params);
        KeyedHashFunctions khf = wotsPlus.getKhf();

        if (privateKey.getUsagesRemaining() <= 0)
        {
            throw new ExhaustedPrivateKeyException("no usages of private key remaining");
        }
        if (privateKey.getBDSState().getAuthenticationPath().isEmpty())
        {
            throw new IllegalStateException("not initialized");
        }

        try
        {
            int index = privateKey.getIndex();

            /* create (randomized keyed) messageDigest of message */
            byte[] random = khf.PRF(privateKey.getSecretKeyPRF(), XMSSUtil.toBytesBigEndian(index, 32));
            byte[] concatenated = Arrays.concatenate(random, privateKey.getRoot(),
                XMSSUtil.toBytesBigEndian(index, params.getTreeDigestSize()));
            byte[] messageDigest = khf.HMsg(concatenated, message);

            /* create signature for messageDigest */
            OTSHashAddress otsHashAddress = (OTSHashAddress)new OTSHashAddress.Builder().withOTSAddress(index).build();
            WOTSPlusSignature wotsPlusSignature = wotsSign(wotsPlus, params, privateKey.getSecretKeySeed(),
                privateKey.getPublicSeed(), messageDigest, otsHashAddress);

            return new XMSSSignature.Builder(params).withIndex(index).withRandom(random)
                .withWOTSPlusSignature(wotsPlusSignature)
                .withAuthPath(privateKey.getBDSState().getAuthenticationPath())
                .build().toByteArray();
        }
        finally
        {
            privateKey.getBDSState().markUsed();
            privateKey.rollKey();
        }
    }

    /**
     * Verify an XMSS signature (RFC 8391 sec. 4.1.10). A signature that will not decode at all is
     * reported as a failed verification rather than raised, per the JCA contract the signers above
     * this present.
     */
    public static boolean verifySignature(XMSSPublicKeyParameters publicKey, byte[] message, byte[] signature)
    {
        XMSSParameters params = publicKey.getParameters();
        WOTSPlus wotsPlus = newWOTSPlus(params);
        KeyedHashFunctions khf = wotsPlus.getKhf();

        XMSSSignature sig;
        try
        {
            sig = new XMSSSignature.Builder(params).withSignature(signature).build();
        }
        catch (RuntimeException e)
        {
            // malformed/truncated signature: do not propagate ArrayIndexOutOfBoundsException
            // (short header) or IllegalArgumentException (wrong length)
            return false;
        }

        int index = sig.getIndex();

        /* reinitialize WOTS+ object */
        wotsPlus.importKeys(new byte[params.getTreeDigestSize()], publicKey.getPublicSeed());

        /* create message digest */
        byte[] concatenated = Arrays.concatenate(sig.getRandom(), publicKey.getRoot(),
            XMSSUtil.toBytesBigEndian(index, params.getTreeDigestSize()));
        byte[] messageDigest = khf.HMsg(concatenated, message);

        int xmssHeight = params.getHeight();
        int indexLeaf = XMSSUtil.getLeafIndex(index, xmssHeight);

        /* get root from signature */
        OTSHashAddress otsHashAddress = (OTSHashAddress)new OTSHashAddress.Builder().withOTSAddress(index).build();
        XMSSNode rootNodeFromSignature = XMSSVerifierUtil.getRootNodeFromSignature(wotsPlus, xmssHeight, messageDigest,
            sig, otsHashAddress, indexLeaf);

        return Arrays.constantTimeAreEqual(rootNodeFromSignature.getValue(), publicKey.getRoot());
    }

    /**
     * Generate an XMSS^MT signature over {@code message} and advance the key's traversal state
     * (RFC 8391 sec. 4.2.7). The key is held locked for the whole sequence, for the reason given on
     * {@link #generateSignature(XMSSPrivateKeyParameters, byte[])}.
     */
    public static byte[] generateMTSignature(XMSSMTPrivateKeyParameters privateKey, byte[] message)
    {
        synchronized (privateKey)
        {
            return doGenerateMTSignature(privateKey, message);
        }
    }

    private static byte[] doGenerateMTSignature(XMSSMTPrivateKeyParameters privateKey, byte[] message)
    {
        XMSSMTParameters params = privateKey.getParameters();
        XMSSParameters xmssParams = params.getXMSSParameters();
        WOTSPlus wotsPlus = newWOTSPlus(params);

        if (privateKey.getUsagesRemaining() <= 0)
        {
            throw new ExhaustedPrivateKeyException("no usages of private key remaining");
        }
        if (privateKey.getBDSState().isEmpty())
        {
            throw new IllegalStateException("not initialized");
        }

        try
        {
            BDSStateMap bdsState = privateKey.getBDSState();
            byte[] publicSeed = privateKey.getPublicSeed();
            byte[] secretKeySeed = privateKey.getSecretKeySeed();

            final long globalIndex = privateKey.getIndex();
            final int xmssHeight = xmssParams.getHeight();

            /* compress message */
            byte[] random = wotsPlus.getKhf().PRF(privateKey.getSecretKeyPRF(), XMSSUtil.toBytesBigEndian(globalIndex, 32));
            byte[] concatenated = Arrays.concatenate(random, privateKey.getRoot(),
                XMSSUtil.toBytesBigEndian(globalIndex, params.getTreeDigestSize()));
            byte[] messageDigest = wotsPlus.getKhf().HMsg(concatenated, message);

            XMSSMTSignature signature = new XMSSMTSignature.Builder(params).withIndex(globalIndex).withRandom(random).build();

            /* layer 0 */
            long indexTree = XMSSUtil.getTreeIndex(globalIndex, xmssHeight);
            int indexLeaf = XMSSUtil.getLeafIndex(globalIndex, xmssHeight);

            /* reset xmss */
            wotsPlus.importKeys(new byte[params.getTreeDigestSize()], publicSeed);

            /* create signature with XMSS tree on layer 0 */

            /* adjust addresses */
            OTSHashAddress otsHashAddress = (OTSHashAddress)new OTSHashAddress.Builder().withTreeAddress(indexTree)
                .withOTSAddress(indexLeaf).build();

            /* get authentication path from BDS */
            if (bdsState.get(0) == null || indexLeaf == 0)
            {
                bdsState.put(0, new BDS(xmssParams, publicSeed, secretKeySeed, otsHashAddress));
            }

            /* sign message digest */
            WOTSPlusSignature wotsPlusSignature = wotsSign(wotsPlus, params, secretKeySeed,
                publicSeed, messageDigest, otsHashAddress);

            XMSSReducedSignature reducedSignature = new XMSSReducedSignature.Builder(xmssParams)
                .withWOTSPlusSignature(wotsPlusSignature).withAuthPath(bdsState.get(0).getAuthenticationPath())
                .build();

            signature.getReducedSignatures().add(reducedSignature);

            /* loop over remaining layers */
            for (int layer = 1; layer < params.getLayers(); layer++)
            {
                /* get root of layer - 1 */
                XMSSNode root = bdsState.get(layer - 1).getRoot();

                indexLeaf = XMSSUtil.getLeafIndex(indexTree, xmssHeight);
                indexTree = XMSSUtil.getTreeIndex(indexTree, xmssHeight);

                /* adjust addresses */
                otsHashAddress = (OTSHashAddress)new OTSHashAddress.Builder().withLayerAddress(layer)
                    .withTreeAddress(indexTree).withOTSAddress(indexLeaf).build();

                /* sign root digest of layer - 1 */
                wotsPlusSignature = wotsSign(wotsPlus, params, secretKeySeed,
                    publicSeed, root.getValue(), otsHashAddress);

                /* get authentication path from BDS */
                if (bdsState.get(layer) == null || XMSSUtil.isNewBDSInitNeeded(globalIndex, xmssHeight, layer))
                {
                    bdsState.put(layer, new BDS(xmssParams, publicSeed, secretKeySeed, otsHashAddress));
                }

                reducedSignature = new XMSSReducedSignature.Builder(xmssParams)
                    .withWOTSPlusSignature(wotsPlusSignature)
                    .withAuthPath(bdsState.get(layer).getAuthenticationPath()).build();

                signature.getReducedSignatures().add(reducedSignature);
            }

            return signature.toByteArray();
        }
        finally
        {
            privateKey.rollKey();
        }
    }

    /**
     * Verify an XMSS^MT signature (RFC 8391 sec. 4.2.8). As with XMSS above, a signature that will
     * not decode is reported as a failed verification rather than raised.
     */
    public static boolean verifyMTSignature(XMSSMTPublicKeyParameters publicKey, byte[] message, byte[] signature)
    {
        XMSSMTParameters params = publicKey.getParameters();
        XMSSParameters xmssParams = params.getXMSSParameters();
        WOTSPlus wotsPlus = newWOTSPlus(params);

        XMSSMTSignature sig;
        try
        {
            sig = new XMSSMTSignature.Builder(params).withSignature(signature).build();
        }
        catch (RuntimeException e)
        {
            // malformed/truncated signature: do not propagate IllegalArgumentException
            return false;
        }

        byte[] concatenated = Arrays.concatenate(sig.getRandom(), publicKey.getRoot(),
            XMSSUtil.toBytesBigEndian(sig.getIndex(), params.getTreeDigestSize()));
        byte[] messageDigest = wotsPlus.getKhf().HMsg(concatenated, message);

        long globalIndex = sig.getIndex();
        int xmssHeight = xmssParams.getHeight();
        long indexTree = XMSSUtil.getTreeIndex(globalIndex, xmssHeight);
        int indexLeaf = XMSSUtil.getLeafIndex(globalIndex, xmssHeight);

        /* adjust xmss */
        wotsPlus.importKeys(new byte[params.getTreeDigestSize()], publicKey.getPublicSeed());

        /* prepare addresses */
        OTSHashAddress otsHashAddress = (OTSHashAddress)new OTSHashAddress.Builder().withTreeAddress(indexTree)
            .withOTSAddress(indexLeaf).build();

        /* get root node on layer 0 */
        XMSSReducedSignature xmssMTSignature = sig.getReducedSignatures().get(0);
        XMSSNode rootNode = XMSSVerifierUtil.getRootNodeFromSignature(wotsPlus, xmssHeight, messageDigest,
            xmssMTSignature, otsHashAddress, indexLeaf);
        for (int layer = 1; layer < params.getLayers(); layer++)
        {
            xmssMTSignature = sig.getReducedSignatures().get(layer);
            indexLeaf = XMSSUtil.getLeafIndex(indexTree, xmssHeight);
            indexTree = XMSSUtil.getTreeIndex(indexTree, xmssHeight);

            /* adjust address */
            otsHashAddress = (OTSHashAddress)new OTSHashAddress.Builder().withLayerAddress(layer)
                .withTreeAddress(indexTree).withOTSAddress(indexLeaf).build();

            /* get root node */
            rootNode = XMSSVerifierUtil.getRootNodeFromSignature(wotsPlus, xmssHeight, rootNode.getValue(),
                xmssMTSignature, otsHashAddress, indexLeaf);
        }

        /* compare roots */
        return Arrays.constantTimeAreEqual(rootNode.getValue(), publicKey.getRoot());
    }

    /**
     * A fresh BDS traversal state for a key at {@code index}, built at the all-zero OTS hash
     * address an XMSS key starts from.
     *
     * @throws IllegalArgumentException if {@code index} is out of range for the parameter set.
     */
    public static BDS createBDS(XMSSParameters params, byte[] publicSeed, byte[] secretKeySeed, int index)
    {
        int height = params.getHeight();

        // the state is reached by walking the tree one authentication path at a time, so an index
        // out of range has to be refused before the walk rather than by the walk: it would otherwise
        // cost a full tree of authentication paths - 2^h - 1 of them - to arrive at the same answer,
        // which at the RFC 8391 heights is minutes of work at h = 16 and hours at h = 20. This is
        // the check the encoded-key path (XMSSPrivateKeyParameters) makes on the index it reads, and
        // the one XMSSMTPrivateKeyParameters already made before building a state map.
        if (!isStoredIndexValid(height, index))
        {
            throw new IllegalArgumentException("index out of bounds");
        }

        int maxIndex = (1 << height) - 1;

        if (index > maxIndex)
        {
            // every leaf is spent. There is no traversal state to walk to - the walk would step off
            // the end of the tree - and this is the state rollKey() leaves behind at the same point.
            return new BDS(params, maxIndex, index);
        }

        return new BDS(params, publicSeed, secretKeySeed, (OTSHashAddress)new OTSHashAddress.Builder().build(), index);
    }

    /**
     * The traversal state for the next index, i.e. with the authentication path advanced one leaf.
     */
    public static BDS getNextBDSState(BDS bdsState, byte[] publicSeed, byte[] secretKeySeed)
    {
        return bdsState.getNextState(publicSeed, secretKeySeed, (OTSHashAddress)new OTSHashAddress.Builder().build());
    }

    /**
     * The BDS traversal state as it is carried in an XMSS private key encoding, with its checksum
     * bound to the owning key's public seed (github #2414). This is the legacy Java-serialized
     * form; nothing generates it any more, but keys written by earlier releases carry it and
     * {@link #getBDSFromEncoding(byte[], byte[])} still reads it.
     */
    public static byte[] getEncodedBDSState(BDS bdsState, byte[] publicSeed)
        throws IOException
    {
        return XMSSUtil.serialize(bdsState, publicSeed);
    }

    /**
     * The BDS traversal state as it is carried in an XMSS^MT private key encoding, with its
     * checksum bound to the owning key's public seed (github #2414).
     */
    public static byte[] getEncodedBDSState(BDSStateMap bdsState, byte[] publicSeed)
        throws IOException
    {
        return XMSSUtil.serialize(bdsState, publicSeed);
    }

    /**
     * Advance an XMSS^MT traversal state to the leaf after {@code globalIndex}, for the key
     * parameters class rolling its own key on.
     * <p>
     * This sits here rather than on {@link BDSStateMap} because that type is an opaque handle a
     * caller can obtain from a live private key: advancing the state on its own would leave it
     * past the index the key still reports, and a key whose two records of its position disagree
     * signs twice under one one-time key. Rolling the state is the key's to do, not its holder's.
     * </p>
     */
    public static void rollState(BDSStateMap bdsState, XMSSMTParameters params, long globalIndex,
        byte[] publicSeed, byte[] secretKeySeed)
    {
        bdsState.updateState(params, globalIndex, publicSeed, secretKeySeed);
    }

    /**
     * Recover an XMSS BDS traversal state from a private key encoding, checking its checksum
     * against the owning key's public seed (github #2414).
     */
    public static BDS getBDSFromEncoding(byte[] encoding, byte[] publicSeed)
        throws IOException, ClassNotFoundException
    {
        return (BDS)XMSSUtil.deserialize(encoding, BDS.class, publicSeed);
    }

    /**
     * Recover an XMSS^MT BDS traversal state from a private key encoding, checking its checksum
     * against the owning key's public seed (github #2414).
     */
    public static BDSStateMap getBDSStateMapFromEncoding(byte[] encoding, byte[] publicSeed)
        throws IOException, ClassNotFoundException
    {
        return (BDSStateMap)XMSSUtil.deserialize(encoding, BDSStateMap.class, publicSeed);
    }

    /**
     * Whether {@code index} is in range for a tree of this height, i.e. 0 &lt;= index &lt; 2^height.
     */
    public static boolean isIndexValid(int height, long index)
    {
        return XMSSUtil.isIndexValid(height, index);
    }

    /**
     * Whether {@code index} is in range for the index field of a stored private key over a tree of
     * this height, i.e. 0 &lt;= index &lt;= 2^height.
     * <p>
     * The bound is one leaf wider than {@link #isIndexValid(int, long)} because a key that has been
     * used up carries the index one past its last leaf: that is the placeholder traversal state
     * {@link BDS} installs when the final one-time key is consumed, it is what makes the key report
     * no usages remaining, and both {@code BDS.validate()} and the BDS serialization admit it. A
     * key's final state is the one state that most needs to survive being written out and read
     * back, so the private key encoding has to carry it rather than reject it. The tighter bound
     * against the key's own maximum index is applied by {@code BDS.validate()} once the traversal
     * state itself has been recovered.
     * </p>
     */
    public static boolean isStoredIndexValid(int height, long index)
    {
        return index >= 0 && index <= (1L << height);
    }

    /**
     * {@code value} as a big-endian byte string of {@code sizeInByte} bytes.
     */
    public static byte[] toBytesBigEndian(long value, int sizeInByte)
    {
        return XMSSUtil.toBytesBigEndian(value, sizeInByte);
    }

    /**
     * The {@code size}-byte big-endian value at {@code offset}.
     */
    public static long bytesToXBigEndian(byte[] in, int offset, int size)
    {
        return XMSSUtil.bytesToXBigEndian(in, offset, size);
    }

    /**
     * A copy of {@code in}.
     */
    public static byte[] cloneArray(byte[] in)
    {
        return XMSSUtil.cloneArray(in);
    }

    /**
     * Copy {@code src} into {@code dst} at {@code offset}.
     */
    public static void copyBytesAtOffset(byte[] dst, byte[] src, int offset)
    {
        XMSSUtil.copyBytesAtOffset(dst, src, offset);
    }

    /**
     * The {@code length} bytes of {@code src} at {@code offset}.
     */
    public static byte[] extractBytesAtOffset(byte[] src, int offset, int length)
    {
        return XMSSUtil.extractBytesAtOffset(src, offset, length);
    }

    static WOTSPlus newWOTSPlus(XMSSParameters params)
    {
        return new WOTSPlus(newWOTSPlusParameters(params));
    }

    static WOTSPlusParameters newWOTSPlusParameters(XMSSParameters params)
    {
        return new WOTSPlusParameters(params.getTreeDigestOID(), params.getTreeDigestSize());
    }

    static WOTSPlus newWOTSPlus(XMSSMTParameters params)
    {
        return newWOTSPlus(params.getXMSSParameters());
    }

    private static WOTSPlusSignature wotsSign(WOTSPlus wotsPlus, XMSSParameters params, byte[] secretKeySeed,
                                              byte[] publicSeed, byte[] messageDigest, OTSHashAddress otsHashAddress)
    {
        if (messageDigest.length != params.getTreeDigestSize())
        {
            throw new IllegalArgumentException("size of messageDigest needs to be equal to size of digest");
        }
        if (otsHashAddress == null)
        {
            throw new NullPointerException("otsHashAddress == null");
        }
        /* (re)initialize WOTS+ instance */
        wotsPlus.importKeys(wotsPlus.getWOTSPlusSecretKey(secretKeySeed, otsHashAddress), publicSeed);

        /* create WOTS+ signature */
        return wotsPlus.sign(messageDigest, otsHashAddress);
    }

    private static WOTSPlusSignature wotsSign(WOTSPlus wotsPlus, XMSSMTParameters params, byte[] secretKeySeed,
                                              byte[] publicSeed, byte[] messageDigest, OTSHashAddress otsHashAddress)
    {
        return wotsSign(wotsPlus, params.getXMSSParameters(), secretKeySeed, publicSeed, messageDigest, otsHashAddress);
    }
}
