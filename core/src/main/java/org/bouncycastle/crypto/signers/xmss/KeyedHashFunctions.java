package org.bouncycastle.crypto.signers.xmss;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Xof;

/**
 * Crypto functions for XMSS: the keyed hash functions F, H, H_msg and PRF of RFC 8391 sec. 4.1.2.
 * <p>
 * Each of them hashes <code>toByte(i, n) || key || in</code> under its own domain separator i, and
 * that concatenation carries no length prefix - so it is unambiguous only because every argument has
 * the fixed length RFC 8391 sec. 4.1.2 gives it: F an n-byte key and an n-byte string, H an n-byte
 * key and a 2n-byte string, H_msg a 3n-byte key and a message of any length, PRF an n-byte key and a
 * 32-byte index, where n is the digestSize this instance was built with.
 * <p>
 * Those lengths are guaranteed by the call sites rather than checked here. This class is
 * package-private and built in exactly one place - {@link WOTSPlus}, with n taken from the owning
 * key's parameters - so the set of callers is closed: every key argument is a return value of one of
 * these functions, a {@code new byte[n]} field of WOTSPlus, or key material one of the key parameter
 * classes has already pinned to n; every in is freshly allocated at the size wanted; every PRF
 * address is an {@link XMSSAddress#toByteArray()} or a toBytesBigEndian(x, 32), both always 32
 * bytes. A new call site has to keep that true: a wrong length is not rejected here, it silently
 * hashes to something else.
 * <p>
 * coreDigest also takes it that digestSize is at most the underlying digest's own output size, which
 * likewise nothing checks - the admissible (digest, n) pairs are fixed by {@link WOTSPlusOid}, and
 * one breaking that would leave the tail of the result zero rather than throw.
 */
final class KeyedHashFunctions
{
    private final Digest digest;
    private final int digestSize;

    KeyedHashFunctions(ASN1ObjectIdentifier treeDigest, int digestSize)
    {
        this.digest = DigestUtil.getDigest(treeDigest);
        this.digestSize = digestSize;
    }

    private byte[] coreDigest(int fixedValue, byte[] key, byte[] index)
    {
        byte[] in = XMSSUtil.toBytesBigEndian(fixedValue, digestSize);
        /* fill first n byte of out buffer */
        digest.update(in, 0, in.length);
        /* add key */
        digest.update(key, 0, key.length);
        /* add index */
        digest.update(index, 0, index.length);

        byte[] out = new byte[digestSize];
        if (digest instanceof Xof)
        {
            ((Xof)digest).doFinal(out, 0, digestSize);
        }
        else if (digestSize < digest.getDigestSize())
        {
            byte[] full = new byte[digest.getDigestSize()];
            digest.doFinal(full, 0);
            System.arraycopy(full, 0, out, 0, digestSize);
        }
        else
        {
            digest.doFinal(out, 0);
        }
        return out;
    }

    byte[] F(byte[] key, byte[] in)
    {
        return coreDigest(0, key, in);
    }

    byte[] H(byte[] key, byte[] in)
    {
        return coreDigest(1, key, in);
    }

    byte[] HMsg(byte[] key, byte[] in)
    {
        return coreDigest(2, key, in);
    }

    byte[] PRF(byte[] key, byte[] address)
    {
        return coreDigest(3, key, address);
    }
}
