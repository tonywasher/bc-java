package org.bouncycastle.crypto.signers.xmss;

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Bytes;
import org.bouncycastle.util.Pack;

/**
 * WOTS+.
 */
final class WOTSPlus
{
    /**
     * WOTS+ parameters.
     */
    private final WOTSPlusParameters params;
    /**
     * Randomization functions.
     */
    private final KeyedHashFunctions khf;
    /**
     * WOTS+ secret key seed.
     */
    private final byte[] secretKeySeed;
    /**
     * WOTS+ public seed.
     */
    private final byte[] publicSeed;

    /**
     * Constructs a new WOTS+ one-time signature system based on the given WOTS+
     * parameters.
     *
     * @param params Parameters for WOTSPlus object.
     */
    WOTSPlus(WOTSPlusParameters params)
    {
        this.params = params;
        int n = params.getTreeDigestSize();
        khf = new KeyedHashFunctions(params.getTreeDigest(), n);
        secretKeySeed = new byte[n];
        publicSeed = new byte[n];
    }

    /**
     * Import keys to WOTS+ instance.
     *
     * @param secretKeySeed Secret key seed.
     * @param publicSeed    Public seed.
     */
    void importKeys(byte[] secretKeySeed, byte[] publicSeed)
    {
        int n = params.getTreeDigestSize();

        // through the shared check rather than a copy of its message: a20b761bc3 put the one
        // implementation behind XMSSUtil for the specific reason that six copies of it had already
        // drifted into saying two different things about the same mistake, and these two were a
        // plain string literal duplicate of what that check says - findable by grepping the
        // message, but not by looking for the callers of the check that owns it. The size half of
        // it, without the allocate-when-absent branch: an absent seed here is not an optional
        // field left to be filled in, and taking the allocation would import an all-zero one-time
        // key rather than say so.
        XMSSUtil.validateSize(secretKeySeed, n, "secretKeySeed");
        XMSSUtil.validateSize(publicSeed, n, "publicSeed");

        // copy in rather than take the caller's arrays by reference: getSecretKeySeed() and
        // getPublicSeed() hand out clones, so holding the originals was the one way live WOTS+ key
        // material could still be changed from outside. The destinations are allocated once, in
        // the constructor, and the lengths have just been checked against n, so this costs nothing
        // on the per-leaf walk that calls this for every one-time key in a tree.
        System.arraycopy(secretKeySeed, 0, this.secretKeySeed, 0, this.secretKeySeed.length);
        System.arraycopy(publicSeed, 0, this.publicSeed, 0, this.publicSeed.length);
    }

    /**
     * Creates a signature for the n-byte messageDigest.
     *
     * @param messageDigest  Digest to sign.
     * @param otsHashAddress OTS hash address for randomization.
     * @return WOTS+ signature.
     */
    WOTSPlusSignature sign(byte[] messageDigest, OTSHashAddress otsHashAddress)
    {
        List<Integer> baseWMessage = baseWMessageWithChecksum(messageDigest);

        /* create signature */
        byte[][] signature = new byte[params.getLen()][];
        for (int i = 0; i < params.getLen(); i++)
        {
            otsHashAddress = withChainAddress(otsHashAddress, i);
            signature[i] = chain(expandSecretKeySeed(i), 0, baseWMessage.get(i), otsHashAddress);
        }
        return new WOTSPlusSignature(params, signature);
    }

    /**
     * Calculates a public key based on digest and signature.
     *
     * @param messageDigest  The digest that was signed.
     * @param signature      Signarure on digest.
     * @param otsHashAddress OTS hash address for randomization.
     * @return WOTS+ public key derived from digest and signature.
     */
    WOTSPlusPublicKeyParameters getPublicKeyFromSignature(byte[] messageDigest, WOTSPlusSignature signature,
                                                                    OTSHashAddress otsHashAddress)
    {
        List<Integer> baseWMessage = baseWMessageWithChecksum(messageDigest);

        //
        // The signature's blocks are chained from where they lie rather than out of a copy of the
        // whole signature. toByteArray() deep-copies all len of them, and it had been called inside
        // the loop only to index one out, which made a verification len^2 block copies where it
        // needs none: 4489 for the SHA-256 parameter sets, 17161 for SHA-512, and that again for
        // every layer of a hypertree on the XMSS^MT side. Reading them in place is what getBlock()
        // is for, and it escapes nothing chain() and WOTSPlusPublicKeyParameters did not already
        // settle between them - see that method.
        //
        byte[][] publicKey = new byte[params.getLen()][];
        for (int i = 0; i < params.getLen(); i++)
        {
            otsHashAddress = withChainAddress(otsHashAddress, i);
            publicKey[i] = chain(signature.getBlock(i), baseWMessage.get(i),
                WOTSPlusParameters.WINTERNITZ_PARAMETER - 1 - baseWMessage.get(i), otsHashAddress);
        }
        return new WOTSPlusPublicKeyParameters(params, publicKey);
    }

    /**
     * Computes an iteration of F on an n-byte input using outputs of PRF.
     *
     * @param startHash      Starting point.
     * @param startIndex     Start index.
     * @param steps          Steps to take.
     * @param otsHashAddress OTS hash address for randomization.
     * @return Value obtained by iterating F for steps times on input startHash,
     * using the outputs of PRF.
     */
    private byte[] chain(byte[] startHash, int startIndex, int steps, OTSHashAddress otsHashAddress)
    {
        int n = params.getTreeDigestSize();
        if (startHash.length != n)
        {
            throw new IllegalArgumentException("startHash needs to be " + n + "bytes");
        }
        if ((startIndex + steps) > WOTSPlusParameters.WINTERNITZ_PARAMETER - 1)
        {
            throw new IllegalArgumentException("max chain length must not be greater than w");
        }

        if (steps == 0)
        {
            return startHash;
        }

        //
        // Iteratively, over one encoding of the address and one buffer per value a step produces.
        //
        // The two words a chain step moves are the hash address and the key-and-mask, PRF reads the
        // address as the 32 bytes it is, and nothing here reads the incoming values of either word -
        // withHashAddress() overwrote both at every step - so what the recursion expressed as two
        // rebuilt addresses and two fresh toByteArray() copies per step is three int writes into one
        // encoding taken once. The encoding is this method's own: toByteArray() allocates what it
        // returns, and the caller's address object is left alone exactly as it was when chain()
        // reassigned only its own parameter. Chained from the front rather than unwound from the
        // back, which is the same sequence of hash addresses - startIndex, then upwards - in the
        // same order.
        //
        // The three n-byte results a step produces are written into buffers that last the whole
        // chain rather than allocated per step. The bitmask is produced straight into the array it
        // is masked in, where xorTo turns it into the masked value; F's result goes into out, which
        // the next step reads as tmp and folds into tmpMasked before F writes out again - so out's
        // previous contents are dead by the time they are overwritten, and the reuse rests on that
        // rather than on how coreDigest orders its own work. out does have to stay one array per
        // call: the caller collects the len returns in a byte[][] that WOTSPlusSignature and
        // WOTSPlusPublicKeyParameters clone afterwards, so one shared across a key's chains would
        // leave every entry holding the last chain's value.
        //
        byte[] address = otsHashAddress.toByteArray();
        byte[] key = new byte[n];
        byte[] tmpMasked = new byte[n];
        byte[] out = new byte[n];
        byte[] tmp = startHash;
        for (int i = 0; i != steps; i++)
        {
            Pack.intToBigEndian(startIndex + i, address, OTSHashAddress.HASH_ADDRESS_OFFSET);

            Pack.intToBigEndian(0, address, XMSSAddress.KEY_AND_MASK_OFFSET);
            khf.PRF(publicSeed, address, key);

            Pack.intToBigEndian(1, address, XMSSAddress.KEY_AND_MASK_OFFSET);
            khf.PRF(publicSeed, address, tmpMasked);

            Bytes.xorTo(n, tmp, tmpMasked);
            khf.F(key, tmpMasked, out);
            tmp = out;
        }
        return tmp;
    }

    /**
     * The given address with its chain address replaced and every other field carried over. An
     * XMSS address is immutable, so setting one field means rebuilding the whole address, and the
     * three loops that walk the len chains of a WOTS+ key all step the chain address this way.
     *
     * @param otsHashAddress OTS hash address to copy.
     * @param chainAddress   Chain address to set.
     * @return otsHashAddress with the given chain address.
     */
    private static OTSHashAddress withChainAddress(OTSHashAddress otsHashAddress, int chainAddress)
    {
        return (OTSHashAddress)new OTSHashAddress.Builder()
            .withLayerAddress(otsHashAddress.getLayerAddress()).withTreeAddress(otsHashAddress.getTreeAddress())
            .withOTSAddress(otsHashAddress.getOTSAddress()).withChainAddress(chainAddress)
            .withHashAddress(otsHashAddress.getHashAddress()).withKeyAndMask(otsHashAddress.getKeyAndMask())
            .build();
    }

    /**
     * The len = len1 + len2 base-w digits WOTS+ signs: the digest's own len1 digits followed by
     * the len2 digits of their checksum (RFC 8391 sec. 3.1.1 algorithm 1, steps 1-3). Signing and
     * public-key recovery both need exactly this sequence - one to sign it, the other to verify
     * against it - so it is derived once here rather than in each caller.
     */
    private List<Integer> baseWMessageWithChecksum(byte[] messageDigest)
    {
        List<Integer> baseWMessage = convertToBaseW(messageDigest, WOTSPlusParameters.WINTERNITZ_PARAMETER, params.getLen1());

        /* create checksum */
        int checksum = 0;
        for (int i = 0; i < params.getLen1(); i++)
        {
            checksum += WOTSPlusParameters.WINTERNITZ_PARAMETER - 1 - baseWMessage.get(i);
        }
        checksum <<= (8 - ((params.getLen2() * XMSSUtil.log2(WOTSPlusParameters.WINTERNITZ_PARAMETER)) % 8));
        int len2Bytes = (int)Math
            .ceil((double)(params.getLen2() * XMSSUtil.log2(WOTSPlusParameters.WINTERNITZ_PARAMETER)) / 8);
        List<Integer> baseWChecksum = convertToBaseW(XMSSUtil.toBytesBigEndian(checksum, len2Bytes),
            WOTSPlusParameters.WINTERNITZ_PARAMETER, params.getLen2());

        /* msg || checksum */
        baseWMessage.addAll(baseWChecksum);

        return baseWMessage;
    }

    /**
     * Obtain base w values from Input.
     *
     * @param messageDigest Input data.
     * @param w             Base.
     * @param outLength     Length of output.
     * @return outLength-length list of base w integers.
     */
    private List<Integer> convertToBaseW(byte[] messageDigest, int w, int outLength)
    {
        if (w != 4 && w != 16)
        {
            throw new IllegalArgumentException("w needs to be 4 or 16");
        }
        int logW = XMSSUtil.log2(w);
        if (outLength > ((8 * messageDigest.length) / logW))
        {
            throw new IllegalArgumentException("outLength too big");
        }

        ArrayList<Integer> res = new ArrayList<Integer>();
        for (int i = 0; i < messageDigest.length; i++)
        {
            for (int j = 8 - logW; j >= 0; j -= logW)
            {
                res.add((messageDigest[i] >> j) & (w - 1));
                if (res.size() == outLength)
                {
                    return res;
                }
            }
        }
        return res;
    }

    /**
     * Derive WOTS+ secret key for specific index as in XMSS ref impl Andreas
     * Huelsing.
     *
     * @param secretSeed     the XMSS private key's secret seed, SK_SEED of RFC 8391 sec. 4.1.3 -
     *                       the seed a one-time key is derived from, and not the derived seed this
     *                       instance holds under the near enough same name. The two are the input
     *                       and the output of this one derivation: every caller hands the result
     *                       straight to {@link #importKeys(byte[], byte[])} on the same object.
     * @param otsHashAddress one time hash address.
     * @return WOTS+ secret key at index.
     */
    byte[] getWOTSPlusSecretKey(byte[] secretSeed, OTSHashAddress otsHashAddress)
    {
        otsHashAddress = (OTSHashAddress)new OTSHashAddress.Builder()
            .withLayerAddress(otsHashAddress.getLayerAddress()).withTreeAddress(otsHashAddress.getTreeAddress())
            .withOTSAddress(otsHashAddress.getOTSAddress()).build();
        return khf.PRF(secretSeed, otsHashAddress.toByteArray());
    }

    /**
     * Derive private key at index from secret key seed.
     *
     * @param index Index.
     * @return Private key at index.
     */
    private byte[] expandSecretKeySeed(int index)
    {
        if (index < 0 || index >= params.getLen())
        {
            throw new IllegalArgumentException("index out of bounds");
        }
        return khf.PRF(secretKeySeed, XMSSUtil.toBytesBigEndian(index, 32));
    }

    /**
     * Getter parameters.
     *
     * @return params.
     */
    WOTSPlusParameters getParams()
    {
        return params;
    }

    /**
     * Getter keyed hash functions.
     *
     * @return keyed hash functions.
     */
    KeyedHashFunctions getKhf()
    {
        return khf;
    }

    /**
     * Getter public seed.
     *
     * @return public seed.
     */
    byte[] getPublicSeed()
    {
        return Arrays.clone(publicSeed);
    }

    /**
     * Calculates a new public key based on the state of secretKeySeed,
     * publicSeed and otsHashAddress.
     *
     * @param otsHashAddress OTS hash address for randomization.
     * @return WOTS+ public key.
     */
    WOTSPlusPublicKeyParameters getPublicKey(OTSHashAddress otsHashAddress)
    {
        byte[][] publicKey = new byte[params.getLen()][];
        /* derive public key from secretKeySeed */
        for (int i = 0; i < params.getLen(); i++)
        {
            otsHashAddress = withChainAddress(otsHashAddress, i);
            publicKey[i] = chain(expandSecretKeySeed(i), 0, WOTSPlusParameters.WINTERNITZ_PARAMETER - 1, otsHashAddress);
        }
        return new WOTSPlusPublicKeyParameters(params, publicKey);
    }
}
