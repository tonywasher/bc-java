package org.bouncycastle.crypto.digests;

import java.util.Arrays;

import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.util.Memoable;

/**
 * JH Digest.
 * <p>
 * The embedded JHFastDigest is ported from the C implementation in jh_bitslice_ref64.h in the Round
 * 3 submission package at http://www3.ntu.edu.sg with tweaks to interface to the BouncyCastle
 * libraries
 */
public class JHDigest
        implements ExtendedDigest, Memoable {
    /**
     * The underlying digest.
     */
    private final JHFastDigest theDigest;

    /**
     * The digest length.
     */
    private final int theDigestLen;

    /**
     * Constructor.
     * @param pHashBitLen the hash bit length
     */
    public JHDigest(final int pHashBitLen) {
        theDigest = new JHFastDigest(pHashBitLen);
        theDigestLen = pHashBitLen / Byte.SIZE;
    }

    /**
     * Constructor.
     * @param pDigest the digest to copy
     */
    public JHDigest(final JHDigest pDigest) {
        theDigestLen = pDigest.theDigestLen;
        theDigest = new JHFastDigest(theDigestLen * Byte.SIZE);
        theDigest.copyIn(pDigest.theDigest);
    }

    @Override
    public int doFinal(final byte[] pHash, final int pOffset) {
        theDigest.Final(pHash, pOffset);
        return getDigestSize();
    }

    @Override
    public String getAlgorithmName() {
        return "JH";
    }

    @Override
    public int getDigestSize() {
        return theDigestLen;
    }

    @Override
    public void reset() {
        theDigest.reset();
    }

    @Override
    public void update(final byte arg0) {
        final byte[] myByte = new byte[]
        { arg0 };
        update(myByte, 0, 1);
    }

    @Override
    public void update(final byte[] pData, final int pOffset, final int pLength) {
        theDigest.Update(pData, pOffset, ((long) pLength) * Byte.SIZE);
    }

    @Override
    public int getByteLength() {
        return theDigest.getBufferSize();
    }

    @Override
    public JHDigest copy() {
        return new JHDigest(this);
    }

    @Override
    public void reset(final Memoable pState) {
        final JHDigest d = (JHDigest) pState;
        theDigest.copyIn(d.theDigest);
    }

    /**
     * JH Digest Fast version.
     * <p>
     * Ported from the C implementation in jh_bitslice_ref64.h in the Round 3 submission package at
     * http://www3.ntu.edu.sg with tweaks to interface to the BouncyCastle libraries
     */
    private static class JHFastDigest {
        /**
         * The state.
         */
        private int hashbitlen; /* the message digest size */
        private boolean initialised;
        private long databitlen; /* the message size in bits */
        private long datasizeInBuffer; /*
                                        * the size of the message remained in buffer; assumed to be
                                        * multiple of 8bits except for the last partial block at the
                                        * end of the message
                                        */
        private long[][] x = new long[8][2]; /*
                                              * the 1024-bit state, ( x[i][0] || x[i][1] ) is the
                                              * ith row of the state in the pseudocode
                                              */
        private byte[] buffer = new byte[64]; /* the 512-bit message block to be hashed; */

        /* The initial hash value H(0) */
        private static final byte[] JH224_H0 =
        { (byte) 0x2d, (byte) 0xfe, (byte) 0xdd, (byte) 0x62, (byte) 0xf9, (byte) 0x9a, (byte) 0x98, (byte) 0xac, (byte) 0xae, (byte) 0x7c, (byte) 0xac, (byte) 0xd6, (byte) 0x19, (byte) 0xd6,
                (byte) 0x34, (byte) 0xe7, (byte) 0xa4, (byte) 0x83, (byte) 0x10, (byte) 0x5, (byte) 0xbc, (byte) 0x30, (byte) 0x12, (byte) 0x16, (byte) 0xb8, (byte) 0x60, (byte) 0x38, (byte) 0xc6,
                (byte) 0xc9, (byte) 0x66, (byte) 0x14, (byte) 0x94, (byte) 0x66, (byte) 0xd9, (byte) 0x89, (byte) 0x9f, (byte) 0x25, (byte) 0x80, (byte) 0x70, (byte) 0x6f, (byte) 0xce, (byte) 0x9e,
                (byte) 0xa3, (byte) 0x1b, (byte) 0x1d, (byte) 0x9b, (byte) 0x1a, (byte) 0xdc, (byte) 0x11, (byte) 0xe8, (byte) 0x32, (byte) 0x5f, (byte) 0x7b, (byte) 0x36, (byte) 0x6e, (byte) 0x10,
                (byte) 0xf9, (byte) 0x94, (byte) 0x85, (byte) 0x7f, (byte) 0x2, (byte) 0xfa, (byte) 0x6, (byte) 0xc1, (byte) 0x1b, (byte) 0x4f, (byte) 0x1b, (byte) 0x5c, (byte) 0xd8, (byte) 0xc8,
                (byte) 0x40, (byte) 0xb3, (byte) 0x97, (byte) 0xf6, (byte) 0xa1, (byte) 0x7f, (byte) 0x6e, (byte) 0x73, (byte) 0x80, (byte) 0x99, (byte) 0xdc, (byte) 0xdf, (byte) 0x93, (byte) 0xa5,
                (byte) 0xad, (byte) 0xea, (byte) 0xa3, (byte) 0xd3, (byte) 0xa4, (byte) 0x31, (byte) 0xe8, (byte) 0xde, (byte) 0xc9, (byte) 0x53, (byte) 0x9a, (byte) 0x68, (byte) 0x22, (byte) 0xb4,
                (byte) 0xa9, (byte) 0x8a, (byte) 0xec, (byte) 0x86, (byte) 0xa1, (byte) 0xe4, (byte) 0xd5, (byte) 0x74, (byte) 0xac, (byte) 0x95, (byte) 0x9c, (byte) 0xe5, (byte) 0x6c, (byte) 0xf0,
                (byte) 0x15, (byte) 0x96, (byte) 0xd, (byte) 0xea, (byte) 0xb5, (byte) 0xab, (byte) 0x2b, (byte) 0xbf, (byte) 0x96, (byte) 0x11, (byte) 0xdc, (byte) 0xf0, (byte) 0xdd, (byte) 0x64,
                (byte) 0xea, (byte) 0x6e };
        private static final byte[] JH256_H0 =
        { (byte) 0xeb, (byte) 0x98, (byte) 0xa3, (byte) 0x41, (byte) 0x2c, (byte) 0x20, (byte) 0xd3, (byte) 0xeb, (byte) 0x92, (byte) 0xcd, (byte) 0xbe, (byte) 0x7b, (byte) 0x9c, (byte) 0xb2,
                (byte) 0x45, (byte) 0xc1, (byte) 0x1c, (byte) 0x93, (byte) 0x51, (byte) 0x91, (byte) 0x60, (byte) 0xd4, (byte) 0xc7, (byte) 0xfa, (byte) 0x26, (byte) 0x0, (byte) 0x82, (byte) 0xd6,
                (byte) 0x7e, (byte) 0x50, (byte) 0x8a, (byte) 0x3, (byte) 0xa4, (byte) 0x23, (byte) 0x9e, (byte) 0x26, (byte) 0x77, (byte) 0x26, (byte) 0xb9, (byte) 0x45, (byte) 0xe0, (byte) 0xfb,
                (byte) 0x1a, (byte) 0x48, (byte) 0xd4, (byte) 0x1a, (byte) 0x94, (byte) 0x77, (byte) 0xcd, (byte) 0xb5, (byte) 0xab, (byte) 0x26, (byte) 0x2, (byte) 0x6b, (byte) 0x17, (byte) 0x7a,
                (byte) 0x56, (byte) 0xf0, (byte) 0x24, (byte) 0x42, (byte) 0xf, (byte) 0xff, (byte) 0x2f, (byte) 0xa8, (byte) 0x71, (byte) 0xa3, (byte) 0x96, (byte) 0x89, (byte) 0x7f, (byte) 0x2e,
                (byte) 0x4d, (byte) 0x75, (byte) 0x1d, (byte) 0x14, (byte) 0x49, (byte) 0x8, (byte) 0xf7, (byte) 0x7d, (byte) 0xe2, (byte) 0x62, (byte) 0x27, (byte) 0x76, (byte) 0x95, (byte) 0xf7,
                (byte) 0x76, (byte) 0x24, (byte) 0x8f, (byte) 0x94, (byte) 0x87, (byte) 0xd5, (byte) 0xb6, (byte) 0x57, (byte) 0x47, (byte) 0x80, (byte) 0x29, (byte) 0x6c, (byte) 0x5c, (byte) 0x5e,
                (byte) 0x27, (byte) 0x2d, (byte) 0xac, (byte) 0x8e, (byte) 0xd, (byte) 0x6c, (byte) 0x51, (byte) 0x84, (byte) 0x50, (byte) 0xc6, (byte) 0x57, (byte) 0x5, (byte) 0x7a, (byte) 0xf,
                (byte) 0x7b, (byte) 0xe4, (byte) 0xd3, (byte) 0x67, (byte) 0x70, (byte) 0x24, (byte) 0x12, (byte) 0xea, (byte) 0x89, (byte) 0xe3, (byte) 0xab, (byte) 0x13, (byte) 0xd3, (byte) 0x1c,
                (byte) 0xd7, (byte) 0x69 };
        private static final byte[] JH384_H0 =
        { (byte) 0x48, (byte) 0x1e, (byte) 0x3b, (byte) 0xc6, (byte) 0xd8, (byte) 0x13, (byte) 0x39, (byte) 0x8a, (byte) 0x6d, (byte) 0x3b, (byte) 0x5e, (byte) 0x89, (byte) 0x4a, (byte) 0xde,
                (byte) 0x87, (byte) 0x9b, (byte) 0x63, (byte) 0xfa, (byte) 0xea, (byte) 0x68, (byte) 0xd4, (byte) 0x80, (byte) 0xad, (byte) 0x2e, (byte) 0x33, (byte) 0x2c, (byte) 0xcb, (byte) 0x21,
                (byte) 0x48, (byte) 0xf, (byte) 0x82, (byte) 0x67, (byte) 0x98, (byte) 0xae, (byte) 0xc8, (byte) 0x4d, (byte) 0x90, (byte) 0x82, (byte) 0xb9, (byte) 0x28, (byte) 0xd4, (byte) 0x55,
                (byte) 0xea, (byte) 0x30, (byte) 0x41, (byte) 0x11, (byte) 0x42, (byte) 0x49, (byte) 0x36, (byte) 0xf5, (byte) 0x55, (byte) 0xb2, (byte) 0x92, (byte) 0x48, (byte) 0x47, (byte) 0xec,
                (byte) 0xc7, (byte) 0x25, (byte) 0xa, (byte) 0x93, (byte) 0xba, (byte) 0xf4, (byte) 0x3c, (byte) 0xe1, (byte) 0x56, (byte) 0x9b, (byte) 0x7f, (byte) 0x8a, (byte) 0x27, (byte) 0xdb,
                (byte) 0x45, (byte) 0x4c, (byte) 0x9e, (byte) 0xfc, (byte) 0xbd, (byte) 0x49, (byte) 0x63, (byte) 0x97, (byte) 0xaf, (byte) 0xe, (byte) 0x58, (byte) 0x9f, (byte) 0xc2, (byte) 0x7d,
                (byte) 0x26, (byte) 0xaa, (byte) 0x80, (byte) 0xcd, (byte) 0x80, (byte) 0xc0, (byte) 0x8b, (byte) 0x8c, (byte) 0x9d, (byte) 0xeb, (byte) 0x2e, (byte) 0xda, (byte) 0x8a, (byte) 0x79,
                (byte) 0x81, (byte) 0xe8, (byte) 0xf8, (byte) 0xd5, (byte) 0x37, (byte) 0x3a, (byte) 0xf4, (byte) 0x39, (byte) 0x67, (byte) 0xad, (byte) 0xdd, (byte) 0xd1, (byte) 0x7a, (byte) 0x71,
                (byte) 0xa9, (byte) 0xb4, (byte) 0xd3, (byte) 0xbd, (byte) 0xa4, (byte) 0x75, (byte) 0xd3, (byte) 0x94, (byte) 0x97, (byte) 0x6c, (byte) 0x3f, (byte) 0xba, (byte) 0x98, (byte) 0x42,
                (byte) 0x73, (byte) 0x7f };
        private static final byte[] JH512_H0 =
        { (byte) 0x6f, (byte) 0xd1, (byte) 0x4b, (byte) 0x96, (byte) 0x3e, (byte) 0x0, (byte) 0xaa, (byte) 0x17, (byte) 0x63, (byte) 0x6a, (byte) 0x2e, (byte) 0x5, (byte) 0x7a, (byte) 0x15,
                (byte) 0xd5, (byte) 0x43, (byte) 0x8a, (byte) 0x22, (byte) 0x5e, (byte) 0x8d, (byte) 0xc, (byte) 0x97, (byte) 0xef, (byte) 0xb, (byte) 0xe9, (byte) 0x34, (byte) 0x12, (byte) 0x59,
                (byte) 0xf2, (byte) 0xb3, (byte) 0xc3, (byte) 0x61, (byte) 0x89, (byte) 0x1d, (byte) 0xa0, (byte) 0xc1, (byte) 0x53, (byte) 0x6f, (byte) 0x80, (byte) 0x1e, (byte) 0x2a, (byte) 0xa9,
                (byte) 0x5, (byte) 0x6b, (byte) 0xea, (byte) 0x2b, (byte) 0x6d, (byte) 0x80, (byte) 0x58, (byte) 0x8e, (byte) 0xcc, (byte) 0xdb, (byte) 0x20, (byte) 0x75, (byte) 0xba, (byte) 0xa6,
                (byte) 0xa9, (byte) 0xf, (byte) 0x3a, (byte) 0x76, (byte) 0xba, (byte) 0xf8, (byte) 0x3b, (byte) 0xf7, (byte) 0x1, (byte) 0x69, (byte) 0xe6, (byte) 0x5, (byte) 0x41, (byte) 0xe3,
                (byte) 0x4a, (byte) 0x69, (byte) 0x46, (byte) 0xb5, (byte) 0x8a, (byte) 0x8e, (byte) 0x2e, (byte) 0x6f, (byte) 0xe6, (byte) 0x5a, (byte) 0x10, (byte) 0x47, (byte) 0xa7, (byte) 0xd0,
                (byte) 0xc1, (byte) 0x84, (byte) 0x3c, (byte) 0x24, (byte) 0x3b, (byte) 0x6e, (byte) 0x71, (byte) 0xb1, (byte) 0x2d, (byte) 0x5a, (byte) 0xc1, (byte) 0x99, (byte) 0xcf, (byte) 0x57,
                (byte) 0xf6, (byte) 0xec, (byte) 0x9d, (byte) 0xb1, (byte) 0xf8, (byte) 0x56, (byte) 0xa7, (byte) 0x6, (byte) 0x88, (byte) 0x7c, (byte) 0x57, (byte) 0x16, (byte) 0xb1, (byte) 0x56,
                (byte) 0xe3, (byte) 0xc2, (byte) 0xfc, (byte) 0xdf, (byte) 0xe6, (byte) 0x85, (byte) 0x17, (byte) 0xfb, (byte) 0x54, (byte) 0x5a, (byte) 0x46, (byte) 0x78, (byte) 0xcc, (byte) 0x8c,
                (byte) 0xdd, (byte) 0x4b };

        /* 42 round constants, each round constant is 32-byte (256-bit) */
        private static final byte[][] E8_bitslice_roundconstant =
        {
                { (byte) 0x72, (byte) 0xd5, (byte) 0xde, (byte) 0xa2, (byte) 0xdf, (byte) 0x15, (byte) 0xf8, (byte) 0x67, (byte) 0x7b, (byte) 0x84, (byte) 0x15, (byte) 0xa, (byte) 0xb7, (byte) 0x23,
                        (byte) 0x15, (byte) 0x57, (byte) 0x81, (byte) 0xab, (byte) 0xd6, (byte) 0x90, (byte) 0x4d, (byte) 0x5a, (byte) 0x87, (byte) 0xf6, (byte) 0x4e, (byte) 0x9f, (byte) 0x4f,
                        (byte) 0xc5, (byte) 0xc3, (byte) 0xd1, (byte) 0x2b, (byte) 0x40 },
                { (byte) 0xea, (byte) 0x98, (byte) 0x3a, (byte) 0xe0, (byte) 0x5c, (byte) 0x45, (byte) 0xfa, (byte) 0x9c, (byte) 0x3, (byte) 0xc5, (byte) 0xd2, (byte) 0x99, (byte) 0x66, (byte) 0xb2,
                        (byte) 0x99, (byte) 0x9a, (byte) 0x66, (byte) 0x2, (byte) 0x96, (byte) 0xb4, (byte) 0xf2, (byte) 0xbb, (byte) 0x53, (byte) 0x8a, (byte) 0xb5, (byte) 0x56, (byte) 0x14,
                        (byte) 0x1a, (byte) 0x88, (byte) 0xdb, (byte) 0xa2, (byte) 0x31 },
                { (byte) 0x3, (byte) 0xa3, (byte) 0x5a, (byte) 0x5c, (byte) 0x9a, (byte) 0x19, (byte) 0xe, (byte) 0xdb, (byte) 0x40, (byte) 0x3f, (byte) 0xb2, (byte) 0xa, (byte) 0x87, (byte) 0xc1,
                        (byte) 0x44, (byte) 0x10, (byte) 0x1c, (byte) 0x5, (byte) 0x19, (byte) 0x80, (byte) 0x84, (byte) 0x9e, (byte) 0x95, (byte) 0x1d, (byte) 0x6f, (byte) 0x33, (byte) 0xeb,
                        (byte) 0xad, (byte) 0x5e, (byte) 0xe7, (byte) 0xcd, (byte) 0xdc },
                { (byte) 0x10, (byte) 0xba, (byte) 0x13, (byte) 0x92, (byte) 0x2, (byte) 0xbf, (byte) 0x6b, (byte) 0x41, (byte) 0xdc, (byte) 0x78, (byte) 0x65, (byte) 0x15, (byte) 0xf7, (byte) 0xbb,
                        (byte) 0x27, (byte) 0xd0, (byte) 0xa, (byte) 0x2c, (byte) 0x81, (byte) 0x39, (byte) 0x37, (byte) 0xaa, (byte) 0x78, (byte) 0x50, (byte) 0x3f, (byte) 0x1a, (byte) 0xbf,
                        (byte) 0xd2, (byte) 0x41, (byte) 0x0, (byte) 0x91, (byte) 0xd3 },
                { (byte) 0x42, (byte) 0x2d, (byte) 0x5a, (byte) 0xd, (byte) 0xf6, (byte) 0xcc, (byte) 0x7e, (byte) 0x90, (byte) 0xdd, (byte) 0x62, (byte) 0x9f, (byte) 0x9c, (byte) 0x92, (byte) 0xc0,
                        (byte) 0x97, (byte) 0xce, (byte) 0x18, (byte) 0x5c, (byte) 0xa7, (byte) 0xb, (byte) 0xc7, (byte) 0x2b, (byte) 0x44, (byte) 0xac, (byte) 0xd1, (byte) 0xdf, (byte) 0x65,
                        (byte) 0xd6, (byte) 0x63, (byte) 0xc6, (byte) 0xfc, (byte) 0x23 },
                { (byte) 0x97, (byte) 0x6e, (byte) 0x6c, (byte) 0x3, (byte) 0x9e, (byte) 0xe0, (byte) 0xb8, (byte) 0x1a, (byte) 0x21, (byte) 0x5, (byte) 0x45, (byte) 0x7e, (byte) 0x44, (byte) 0x6c,
                        (byte) 0xec, (byte) 0xa8, (byte) 0xee, (byte) 0xf1, (byte) 0x3, (byte) 0xbb, (byte) 0x5d, (byte) 0x8e, (byte) 0x61, (byte) 0xfa, (byte) 0xfd, (byte) 0x96, (byte) 0x97,
                        (byte) 0xb2, (byte) 0x94, (byte) 0x83, (byte) 0x81, (byte) 0x97 },
                { (byte) 0x4a, (byte) 0x8e, (byte) 0x85, (byte) 0x37, (byte) 0xdb, (byte) 0x3, (byte) 0x30, (byte) 0x2f, (byte) 0x2a, (byte) 0x67, (byte) 0x8d, (byte) 0x2d, (byte) 0xfb, (byte) 0x9f,
                        (byte) 0x6a, (byte) 0x95, (byte) 0x8a, (byte) 0xfe, (byte) 0x73, (byte) 0x81, (byte) 0xf8, (byte) 0xb8, (byte) 0x69, (byte) 0x6c, (byte) 0x8a, (byte) 0xc7, (byte) 0x72,
                        (byte) 0x46, (byte) 0xc0, (byte) 0x7f, (byte) 0x42, (byte) 0x14 },
                { (byte) 0xc5, (byte) 0xf4, (byte) 0x15, (byte) 0x8f, (byte) 0xbd, (byte) 0xc7, (byte) 0x5e, (byte) 0xc4, (byte) 0x75, (byte) 0x44, (byte) 0x6f, (byte) 0xa7, (byte) 0x8f, (byte) 0x11,
                        (byte) 0xbb, (byte) 0x80, (byte) 0x52, (byte) 0xde, (byte) 0x75, (byte) 0xb7, (byte) 0xae, (byte) 0xe4, (byte) 0x88, (byte) 0xbc, (byte) 0x82, (byte) 0xb8, (byte) 0x0,
                        (byte) 0x1e, (byte) 0x98, (byte) 0xa6, (byte) 0xa3, (byte) 0xf4 },
                { (byte) 0x8e, (byte) 0xf4, (byte) 0x8f, (byte) 0x33, (byte) 0xa9, (byte) 0xa3, (byte) 0x63, (byte) 0x15, (byte) 0xaa, (byte) 0x5f, (byte) 0x56, (byte) 0x24, (byte) 0xd5, (byte) 0xb7,
                        (byte) 0xf9, (byte) 0x89, (byte) 0xb6, (byte) 0xf1, (byte) 0xed, (byte) 0x20, (byte) 0x7c, (byte) 0x5a, (byte) 0xe0, (byte) 0xfd, (byte) 0x36, (byte) 0xca, (byte) 0xe9,
                        (byte) 0x5a, (byte) 0x6, (byte) 0x42, (byte) 0x2c, (byte) 0x36 },
                { (byte) 0xce, (byte) 0x29, (byte) 0x35, (byte) 0x43, (byte) 0x4e, (byte) 0xfe, (byte) 0x98, (byte) 0x3d, (byte) 0x53, (byte) 0x3a, (byte) 0xf9, (byte) 0x74, (byte) 0x73, (byte) 0x9a,
                        (byte) 0x4b, (byte) 0xa7, (byte) 0xd0, (byte) 0xf5, (byte) 0x1f, (byte) 0x59, (byte) 0x6f, (byte) 0x4e, (byte) 0x81, (byte) 0x86, (byte) 0xe, (byte) 0x9d, (byte) 0xad,
                        (byte) 0x81, (byte) 0xaf, (byte) 0xd8, (byte) 0x5a, (byte) 0x9f },
                { (byte) 0xa7, (byte) 0x5, (byte) 0x6, (byte) 0x67, (byte) 0xee, (byte) 0x34, (byte) 0x62, (byte) 0x6a, (byte) 0x8b, (byte) 0xb, (byte) 0x28, (byte) 0xbe, (byte) 0x6e, (byte) 0xb9,
                        (byte) 0x17, (byte) 0x27, (byte) 0x47, (byte) 0x74, (byte) 0x7, (byte) 0x26, (byte) 0xc6, (byte) 0x80, (byte) 0x10, (byte) 0x3f, (byte) 0xe0, (byte) 0xa0, (byte) 0x7e,
                        (byte) 0x6f, (byte) 0xc6, (byte) 0x7e, (byte) 0x48, (byte) 0x7b },
                { (byte) 0xd, (byte) 0x55, (byte) 0xa, (byte) 0xa5, (byte) 0x4a, (byte) 0xf8, (byte) 0xa4, (byte) 0xc0, (byte) 0x91, (byte) 0xe3, (byte) 0xe7, (byte) 0x9f, (byte) 0x97, (byte) 0x8e,
                        (byte) 0xf1, (byte) 0x9e, (byte) 0x86, (byte) 0x76, (byte) 0x72, (byte) 0x81, (byte) 0x50, (byte) 0x60, (byte) 0x8d, (byte) 0xd4, (byte) 0x7e, (byte) 0x9e, (byte) 0x5a,
                        (byte) 0x41, (byte) 0xf3, (byte) 0xe5, (byte) 0xb0, (byte) 0x62 },
                { (byte) 0xfc, (byte) 0x9f, (byte) 0x1f, (byte) 0xec, (byte) 0x40, (byte) 0x54, (byte) 0x20, (byte) 0x7a, (byte) 0xe3, (byte) 0xe4, (byte) 0x1a, (byte) 0x0, (byte) 0xce, (byte) 0xf4,
                        (byte) 0xc9, (byte) 0x84, (byte) 0x4f, (byte) 0xd7, (byte) 0x94, (byte) 0xf5, (byte) 0x9d, (byte) 0xfa, (byte) 0x95, (byte) 0xd8, (byte) 0x55, (byte) 0x2e, (byte) 0x7e,
                        (byte) 0x11, (byte) 0x24, (byte) 0xc3, (byte) 0x54, (byte) 0xa5 },
                { (byte) 0x5b, (byte) 0xdf, (byte) 0x72, (byte) 0x28, (byte) 0xbd, (byte) 0xfe, (byte) 0x6e, (byte) 0x28, (byte) 0x78, (byte) 0xf5, (byte) 0x7f, (byte) 0xe2, (byte) 0xf, (byte) 0xa5,
                        (byte) 0xc4, (byte) 0xb2, (byte) 0x5, (byte) 0x89, (byte) 0x7c, (byte) 0xef, (byte) 0xee, (byte) 0x49, (byte) 0xd3, (byte) 0x2e, (byte) 0x44, (byte) 0x7e, (byte) 0x93,
                        (byte) 0x85, (byte) 0xeb, (byte) 0x28, (byte) 0x59, (byte) 0x7f },
                { (byte) 0x70, (byte) 0x5f, (byte) 0x69, (byte) 0x37, (byte) 0xb3, (byte) 0x24, (byte) 0x31, (byte) 0x4a, (byte) 0x5e, (byte) 0x86, (byte) 0x28, (byte) 0xf1, (byte) 0x1d, (byte) 0xd6,
                        (byte) 0xe4, (byte) 0x65, (byte) 0xc7, (byte) 0x1b, (byte) 0x77, (byte) 0x4, (byte) 0x51, (byte) 0xb9, (byte) 0x20, (byte) 0xe7, (byte) 0x74, (byte) 0xfe, (byte) 0x43,
                        (byte) 0xe8, (byte) 0x23, (byte) 0xd4, (byte) 0x87, (byte) 0x8a },
                { (byte) 0x7d, (byte) 0x29, (byte) 0xe8, (byte) 0xa3, (byte) 0x92, (byte) 0x76, (byte) 0x94, (byte) 0xf2, (byte) 0xdd, (byte) 0xcb, (byte) 0x7a, (byte) 0x9, (byte) 0x9b, (byte) 0x30,
                        (byte) 0xd9, (byte) 0xc1, (byte) 0x1d, (byte) 0x1b, (byte) 0x30, (byte) 0xfb, (byte) 0x5b, (byte) 0xdc, (byte) 0x1b, (byte) 0xe0, (byte) 0xda, (byte) 0x24, (byte) 0x49,
                        (byte) 0x4f, (byte) 0xf2, (byte) 0x9c, (byte) 0x82, (byte) 0xbf },
                { (byte) 0xa4, (byte) 0xe7, (byte) 0xba, (byte) 0x31, (byte) 0xb4, (byte) 0x70, (byte) 0xbf, (byte) 0xff, (byte) 0xd, (byte) 0x32, (byte) 0x44, (byte) 0x5, (byte) 0xde, (byte) 0xf8,
                        (byte) 0xbc, (byte) 0x48, (byte) 0x3b, (byte) 0xae, (byte) 0xfc, (byte) 0x32, (byte) 0x53, (byte) 0xbb, (byte) 0xd3, (byte) 0x39, (byte) 0x45, (byte) 0x9f, (byte) 0xc3,
                        (byte) 0xc1, (byte) 0xe0, (byte) 0x29, (byte) 0x8b, (byte) 0xa0 },
                { (byte) 0xe5, (byte) 0xc9, (byte) 0x5, (byte) 0xfd, (byte) 0xf7, (byte) 0xae, (byte) 0x9, (byte) 0xf, (byte) 0x94, (byte) 0x70, (byte) 0x34, (byte) 0x12, (byte) 0x42, (byte) 0x90,
                        (byte) 0xf1, (byte) 0x34, (byte) 0xa2, (byte) 0x71, (byte) 0xb7, (byte) 0x1, (byte) 0xe3, (byte) 0x44, (byte) 0xed, (byte) 0x95, (byte) 0xe9, (byte) 0x3b, (byte) 0x8e,
                        (byte) 0x36, (byte) 0x4f, (byte) 0x2f, (byte) 0x98, (byte) 0x4a },
                { (byte) 0x88, (byte) 0x40, (byte) 0x1d, (byte) 0x63, (byte) 0xa0, (byte) 0x6c, (byte) 0xf6, (byte) 0x15, (byte) 0x47, (byte) 0xc1, (byte) 0x44, (byte) 0x4b, (byte) 0x87, (byte) 0x52,
                        (byte) 0xaf, (byte) 0xff, (byte) 0x7e, (byte) 0xbb, (byte) 0x4a, (byte) 0xf1, (byte) 0xe2, (byte) 0xa, (byte) 0xc6, (byte) 0x30, (byte) 0x46, (byte) 0x70, (byte) 0xb6,
                        (byte) 0xc5, (byte) 0xcc, (byte) 0x6e, (byte) 0x8c, (byte) 0xe6 },
                { (byte) 0xa4, (byte) 0xd5, (byte) 0xa4, (byte) 0x56, (byte) 0xbd, (byte) 0x4f, (byte) 0xca, (byte) 0x0, (byte) 0xda, (byte) 0x9d, (byte) 0x84, (byte) 0x4b, (byte) 0xc8, (byte) 0x3e,
                        (byte) 0x18, (byte) 0xae, (byte) 0x73, (byte) 0x57, (byte) 0xce, (byte) 0x45, (byte) 0x30, (byte) 0x64, (byte) 0xd1, (byte) 0xad, (byte) 0xe8, (byte) 0xa6, (byte) 0xce,
                        (byte) 0x68, (byte) 0x14, (byte) 0x5c, (byte) 0x25, (byte) 0x67 },
                { (byte) 0xa3, (byte) 0xda, (byte) 0x8c, (byte) 0xf2, (byte) 0xcb, (byte) 0xe, (byte) 0xe1, (byte) 0x16, (byte) 0x33, (byte) 0xe9, (byte) 0x6, (byte) 0x58, (byte) 0x9a, (byte) 0x94,
                        (byte) 0x99, (byte) 0x9a, (byte) 0x1f, (byte) 0x60, (byte) 0xb2, (byte) 0x20, (byte) 0xc2, (byte) 0x6f, (byte) 0x84, (byte) 0x7b, (byte) 0xd1, (byte) 0xce, (byte) 0xac,
                        (byte) 0x7f, (byte) 0xa0, (byte) 0xd1, (byte) 0x85, (byte) 0x18 },
                { (byte) 0x32, (byte) 0x59, (byte) 0x5b, (byte) 0xa1, (byte) 0x8d, (byte) 0xdd, (byte) 0x19, (byte) 0xd3, (byte) 0x50, (byte) 0x9a, (byte) 0x1c, (byte) 0xc0, (byte) 0xaa, (byte) 0xa5,
                        (byte) 0xb4, (byte) 0x46, (byte) 0x9f, (byte) 0x3d, (byte) 0x63, (byte) 0x67, (byte) 0xe4, (byte) 0x4, (byte) 0x6b, (byte) 0xba, (byte) 0xf6, (byte) 0xca, (byte) 0x19,
                        (byte) 0xab, (byte) 0xb, (byte) 0x56, (byte) 0xee, (byte) 0x7e },
                { (byte) 0x1f, (byte) 0xb1, (byte) 0x79, (byte) 0xea, (byte) 0xa9, (byte) 0x28, (byte) 0x21, (byte) 0x74, (byte) 0xe9, (byte) 0xbd, (byte) 0xf7, (byte) 0x35, (byte) 0x3b, (byte) 0x36,
                        (byte) 0x51, (byte) 0xee, (byte) 0x1d, (byte) 0x57, (byte) 0xac, (byte) 0x5a, (byte) 0x75, (byte) 0x50, (byte) 0xd3, (byte) 0x76, (byte) 0x3a, (byte) 0x46, (byte) 0xc2,
                        (byte) 0xfe, (byte) 0xa3, (byte) 0x7d, (byte) 0x70, (byte) 0x1 },
                { (byte) 0xf7, (byte) 0x35, (byte) 0xc1, (byte) 0xaf, (byte) 0x98, (byte) 0xa4, (byte) 0xd8, (byte) 0x42, (byte) 0x78, (byte) 0xed, (byte) 0xec, (byte) 0x20, (byte) 0x9e, (byte) 0x6b,
                        (byte) 0x67, (byte) 0x79, (byte) 0x41, (byte) 0x83, (byte) 0x63, (byte) 0x15, (byte) 0xea, (byte) 0x3a, (byte) 0xdb, (byte) 0xa8, (byte) 0xfa, (byte) 0xc3, (byte) 0x3b,
                        (byte) 0x4d, (byte) 0x32, (byte) 0x83, (byte) 0x2c, (byte) 0x83 },
                { (byte) 0xa7, (byte) 0x40, (byte) 0x3b, (byte) 0x1f, (byte) 0x1c, (byte) 0x27, (byte) 0x47, (byte) 0xf3, (byte) 0x59, (byte) 0x40, (byte) 0xf0, (byte) 0x34, (byte) 0xb7, (byte) 0x2d,
                        (byte) 0x76, (byte) 0x9a, (byte) 0xe7, (byte) 0x3e, (byte) 0x4e, (byte) 0x6c, (byte) 0xd2, (byte) 0x21, (byte) 0x4f, (byte) 0xfd, (byte) 0xb8, (byte) 0xfd, (byte) 0x8d,
                        (byte) 0x39, (byte) 0xdc, (byte) 0x57, (byte) 0x59, (byte) 0xef },
                { (byte) 0x8d, (byte) 0x9b, (byte) 0xc, (byte) 0x49, (byte) 0x2b, (byte) 0x49, (byte) 0xeb, (byte) 0xda, (byte) 0x5b, (byte) 0xa2, (byte) 0xd7, (byte) 0x49, (byte) 0x68, (byte) 0xf3,
                        (byte) 0x70, (byte) 0xd, (byte) 0x7d, (byte) 0x3b, (byte) 0xae, (byte) 0xd0, (byte) 0x7a, (byte) 0x8d, (byte) 0x55, (byte) 0x84, (byte) 0xf5, (byte) 0xa5, (byte) 0xe9,
                        (byte) 0xf0, (byte) 0xe4, (byte) 0xf8, (byte) 0x8e, (byte) 0x65 },
                { (byte) 0xa0, (byte) 0xb8, (byte) 0xa2, (byte) 0xf4, (byte) 0x36, (byte) 0x10, (byte) 0x3b, (byte) 0x53, (byte) 0xc, (byte) 0xa8, (byte) 0x7, (byte) 0x9e, (byte) 0x75, (byte) 0x3e,
                        (byte) 0xec, (byte) 0x5a, (byte) 0x91, (byte) 0x68, (byte) 0x94, (byte) 0x92, (byte) 0x56, (byte) 0xe8, (byte) 0x88, (byte) 0x4f, (byte) 0x5b, (byte) 0xb0, (byte) 0x5c,
                        (byte) 0x55, (byte) 0xf8, (byte) 0xba, (byte) 0xbc, (byte) 0x4c },
                { (byte) 0xe3, (byte) 0xbb, (byte) 0x3b, (byte) 0x99, (byte) 0xf3, (byte) 0x87, (byte) 0x94, (byte) 0x7b, (byte) 0x75, (byte) 0xda, (byte) 0xf4, (byte) 0xd6, (byte) 0x72, (byte) 0x6b,
                        (byte) 0x1c, (byte) 0x5d, (byte) 0x64, (byte) 0xae, (byte) 0xac, (byte) 0x28, (byte) 0xdc, (byte) 0x34, (byte) 0xb3, (byte) 0x6d, (byte) 0x6c, (byte) 0x34, (byte) 0xa5,
                        (byte) 0x50, (byte) 0xb8, (byte) 0x28, (byte) 0xdb, (byte) 0x71 },
                { (byte) 0xf8, (byte) 0x61, (byte) 0xe2, (byte) 0xf2, (byte) 0x10, (byte) 0x8d, (byte) 0x51, (byte) 0x2a, (byte) 0xe3, (byte) 0xdb, (byte) 0x64, (byte) 0x33, (byte) 0x59, (byte) 0xdd,
                        (byte) 0x75, (byte) 0xfc, (byte) 0x1c, (byte) 0xac, (byte) 0xbc, (byte) 0xf1, (byte) 0x43, (byte) 0xce, (byte) 0x3f, (byte) 0xa2, (byte) 0x67, (byte) 0xbb, (byte) 0xd1,
                        (byte) 0x3c, (byte) 0x2, (byte) 0xe8, (byte) 0x43, (byte) 0xb0 },
                { (byte) 0x33, (byte) 0xa, (byte) 0x5b, (byte) 0xca, (byte) 0x88, (byte) 0x29, (byte) 0xa1, (byte) 0x75, (byte) 0x7f, (byte) 0x34, (byte) 0x19, (byte) 0x4d, (byte) 0xb4, (byte) 0x16,
                        (byte) 0x53, (byte) 0x5c, (byte) 0x92, (byte) 0x3b, (byte) 0x94, (byte) 0xc3, (byte) 0xe, (byte) 0x79, (byte) 0x4d, (byte) 0x1e, (byte) 0x79, (byte) 0x74, (byte) 0x75,
                        (byte) 0xd7, (byte) 0xb6, (byte) 0xee, (byte) 0xaf, (byte) 0x3f },
                { (byte) 0xea, (byte) 0xa8, (byte) 0xd4, (byte) 0xf7, (byte) 0xbe, (byte) 0x1a, (byte) 0x39, (byte) 0x21, (byte) 0x5c, (byte) 0xf4, (byte) 0x7e, (byte) 0x9, (byte) 0x4c, (byte) 0x23,
                        (byte) 0x27, (byte) 0x51, (byte) 0x26, (byte) 0xa3, (byte) 0x24, (byte) 0x53, (byte) 0xba, (byte) 0x32, (byte) 0x3c, (byte) 0xd2, (byte) 0x44, (byte) 0xa3, (byte) 0x17,
                        (byte) 0x4a, (byte) 0x6d, (byte) 0xa6, (byte) 0xd5, (byte) 0xad },
                { (byte) 0xb5, (byte) 0x1d, (byte) 0x3e, (byte) 0xa6, (byte) 0xaf, (byte) 0xf2, (byte) 0xc9, (byte) 0x8, (byte) 0x83, (byte) 0x59, (byte) 0x3d, (byte) 0x98, (byte) 0x91, (byte) 0x6b,
                        (byte) 0x3c, (byte) 0x56, (byte) 0x4c, (byte) 0xf8, (byte) 0x7c, (byte) 0xa1, (byte) 0x72, (byte) 0x86, (byte) 0x60, (byte) 0x4d, (byte) 0x46, (byte) 0xe2, (byte) 0x3e,
                        (byte) 0xcc, (byte) 0x8, (byte) 0x6e, (byte) 0xc7, (byte) 0xf6 },
                { (byte) 0x2f, (byte) 0x98, (byte) 0x33, (byte) 0xb3, (byte) 0xb1, (byte) 0xbc, (byte) 0x76, (byte) 0x5e, (byte) 0x2b, (byte) 0xd6, (byte) 0x66, (byte) 0xa5, (byte) 0xef, (byte) 0xc4,
                        (byte) 0xe6, (byte) 0x2a, (byte) 0x6, (byte) 0xf4, (byte) 0xb6, (byte) 0xe8, (byte) 0xbe, (byte) 0xc1, (byte) 0xd4, (byte) 0x36, (byte) 0x74, (byte) 0xee, (byte) 0x82,
                        (byte) 0x15, (byte) 0xbc, (byte) 0xef, (byte) 0x21, (byte) 0x63 },
                { (byte) 0xfd, (byte) 0xc1, (byte) 0x4e, (byte) 0xd, (byte) 0xf4, (byte) 0x53, (byte) 0xc9, (byte) 0x69, (byte) 0xa7, (byte) 0x7d, (byte) 0x5a, (byte) 0xc4, (byte) 0x6, (byte) 0x58,
                        (byte) 0x58, (byte) 0x26, (byte) 0x7e, (byte) 0xc1, (byte) 0x14, (byte) 0x16, (byte) 0x6, (byte) 0xe0, (byte) 0xfa, (byte) 0x16, (byte) 0x7e, (byte) 0x90, (byte) 0xaf,
                        (byte) 0x3d, (byte) 0x28, (byte) 0x63, (byte) 0x9d, (byte) 0x3f },
                { (byte) 0xd2, (byte) 0xc9, (byte) 0xf2, (byte) 0xe3, (byte) 0x0, (byte) 0x9b, (byte) 0xd2, (byte) 0xc, (byte) 0x5f, (byte) 0xaa, (byte) 0xce, (byte) 0x30, (byte) 0xb7, (byte) 0xd4,
                        (byte) 0xc, (byte) 0x30, (byte) 0x74, (byte) 0x2a, (byte) 0x51, (byte) 0x16, (byte) 0xf2, (byte) 0xe0, (byte) 0x32, (byte) 0x98, (byte) 0xd, (byte) 0xeb, (byte) 0x30,
                        (byte) 0xd8, (byte) 0xe3, (byte) 0xce, (byte) 0xf8, (byte) 0x9a },
                { (byte) 0x4b, (byte) 0xc5, (byte) 0x9e, (byte) 0x7b, (byte) 0xb5, (byte) 0xf1, (byte) 0x79, (byte) 0x92, (byte) 0xff, (byte) 0x51, (byte) 0xe6, (byte) 0x6e, (byte) 0x4, (byte) 0x86,
                        (byte) 0x68, (byte) 0xd3, (byte) 0x9b, (byte) 0x23, (byte) 0x4d, (byte) 0x57, (byte) 0xe6, (byte) 0x96, (byte) 0x67, (byte) 0x31, (byte) 0xcc, (byte) 0xe6, (byte) 0xa6,
                        (byte) 0xf3, (byte) 0x17, (byte) 0xa, (byte) 0x75, (byte) 0x5 },
                { (byte) 0xb1, (byte) 0x76, (byte) 0x81, (byte) 0xd9, (byte) 0x13, (byte) 0x32, (byte) 0x6c, (byte) 0xce, (byte) 0x3c, (byte) 0x17, (byte) 0x52, (byte) 0x84, (byte) 0xf8, (byte) 0x5,
                        (byte) 0xa2, (byte) 0x62, (byte) 0xf4, (byte) 0x2b, (byte) 0xcb, (byte) 0xb3, (byte) 0x78, (byte) 0x47, (byte) 0x15, (byte) 0x47, (byte) 0xff, (byte) 0x46, (byte) 0x54,
                        (byte) 0x82, (byte) 0x23, (byte) 0x93, (byte) 0x6a, (byte) 0x48 },
                { (byte) 0x38, (byte) 0xdf, (byte) 0x58, (byte) 0x7, (byte) 0x4e, (byte) 0x5e, (byte) 0x65, (byte) 0x65, (byte) 0xf2, (byte) 0xfc, (byte) 0x7c, (byte) 0x89, (byte) 0xfc, (byte) 0x86,
                        (byte) 0x50, (byte) 0x8e, (byte) 0x31, (byte) 0x70, (byte) 0x2e, (byte) 0x44, (byte) 0xd0, (byte) 0xb, (byte) 0xca, (byte) 0x86, (byte) 0xf0, (byte) 0x40, (byte) 0x9,
                        (byte) 0xa2, (byte) 0x30, (byte) 0x78, (byte) 0x47, (byte) 0x4e },
                { (byte) 0x65, (byte) 0xa0, (byte) 0xee, (byte) 0x39, (byte) 0xd1, (byte) 0xf7, (byte) 0x38, (byte) 0x83, (byte) 0xf7, (byte) 0x5e, (byte) 0xe9, (byte) 0x37, (byte) 0xe4, (byte) 0x2c,
                        (byte) 0x3a, (byte) 0xbd, (byte) 0x21, (byte) 0x97, (byte) 0xb2, (byte) 0x26, (byte) 0x1, (byte) 0x13, (byte) 0xf8, (byte) 0x6f, (byte) 0xa3, (byte) 0x44, (byte) 0xed,
                        (byte) 0xd1, (byte) 0xef, (byte) 0x9f, (byte) 0xde, (byte) 0xe7 },
                { (byte) 0x8b, (byte) 0xa0, (byte) 0xdf, (byte) 0x15, (byte) 0x76, (byte) 0x25, (byte) 0x92, (byte) 0xd9, (byte) 0x3c, (byte) 0x85, (byte) 0xf7, (byte) 0xf6, (byte) 0x12, (byte) 0xdc,
                        (byte) 0x42, (byte) 0xbe, (byte) 0xd8, (byte) 0xa7, (byte) 0xec, (byte) 0x7c, (byte) 0xab, (byte) 0x27, (byte) 0xb0, (byte) 0x7e, (byte) 0x53, (byte) 0x8d, (byte) 0x7d,
                        (byte) 0xda, (byte) 0xaa, (byte) 0x3e, (byte) 0xa8, (byte) 0xde },
                { (byte) 0xaa, (byte) 0x25, (byte) 0xce, (byte) 0x93, (byte) 0xbd, (byte) 0x2, (byte) 0x69, (byte) 0xd8, (byte) 0x5a, (byte) 0xf6, (byte) 0x43, (byte) 0xfd, (byte) 0x1a, (byte) 0x73,
                        (byte) 0x8, (byte) 0xf9, (byte) 0xc0, (byte) 0x5f, (byte) 0xef, (byte) 0xda, (byte) 0x17, (byte) 0x4a, (byte) 0x19, (byte) 0xa5, (byte) 0x97, (byte) 0x4d, (byte) 0x66,
                        (byte) 0x33, (byte) 0x4c, (byte) 0xfd, (byte) 0x21, (byte) 0x6a },
                { (byte) 0x35, (byte) 0xb4, (byte) 0x98, (byte) 0x31, (byte) 0xdb, (byte) 0x41, (byte) 0x15, (byte) 0x70, (byte) 0xea, (byte) 0x1e, (byte) 0xf, (byte) 0xbb, (byte) 0xed, (byte) 0xcd,
                        (byte) 0x54, (byte) 0x9b, (byte) 0x9a, (byte) 0xd0, (byte) 0x63, (byte) 0xa1, (byte) 0x51, (byte) 0x97, (byte) 0x40, (byte) 0x72, (byte) 0xf6, (byte) 0x75, (byte) 0x9d,
                        (byte) 0xbf, (byte) 0x91, (byte) 0x47, (byte) 0x6f, (byte) 0xe2 } };

        /**
         * Constructor.
         * @param pHashBitLen the hash bit length
         */
        JHFastDigest(int pHashBitLen) {
            /* Check the hashBitLength */
            switch (pHashBitLen) {
                case 224:
                case 256:
                case 384:
                case 512:
                    break;
                default:
                    throw new IllegalArgumentException("JH digest restricted to one of [224, 256, 384, 512]");
            }

            /* Store value and initialise */
            hashbitlen = pHashBitLen;
        }

        /**
         * Ensure that the digest is initialised.
         */
        private void ensureInitialised() {
            if (!initialised) {
                Init();
                initialised = true;
            }
        }

        /**
         * Obtain the buffer size.
         * @return the bufferSize
         */
        int getBufferSize() {
            return buffer.length;
        }

        /* swapping bit 2i with bit 2i+1 of 64-bit x */
        private static long SWAP1(long x) {
            return (((x & 0x5555555555555555L) << 1) | ((x & 0xaaaaaaaaaaaaaaaaL) >>> 1));
        }

        /* swapping bits 4i||4i+1 with bits 4i+2||4i+3 of 64-bit x */
        private static long SWAP2(long x) {
            return (((x & 0x3333333333333333L) << 2) | ((x & 0xccccccccccccccccL) >>> 2));
        }

        /* swapping bits 8i||8i+1||8i+2||8i+3 with bits 8i+4||8i+5||8i+6||8i+7 of 64-bit x */
        private static long SWAP4(long x) {
            return (((x & 0x0f0f0f0f0f0f0f0fL) << 4) | ((x & 0xf0f0f0f0f0f0f0f0L) >>> 4));
        }

        /*
         * swapping bits 16i||16i+1||......||16i+7 with bits 16i+8||16i+9||......||16i+15 of 64-bit
         * x
         */
        private static long SWAP8(long x) {
            return (((x & 0x00ff00ff00ff00ffL) << 8) | ((x & 0xff00ff00ff00ff00L) >>> 8));
        }

        /*
         * swapping bits 32i||32i+1||......||32i+15 with bits 32i+16||32i+17||......||32i+31 of
         * 64-bit x
         */
        private static long SWAP16(long x) {
            return (((x & 0x0000ffff0000ffffL) << 16) | ((x & 0xffff0000ffff0000L) >>> 16));
        }

        /*
         * swapping bits 64i||64i+1||......||64i+31 with bits 64i+32||64i+33||......||64i+63 of
         * 64-bit x
         */
        private static long SWAP32(long x) {
            return ((x << 32) | (x >>> 32));
        }

        /* The MDS transform */
        private void L(int i) {
            x[1][i] ^= x[2][i];
            x[3][i] ^= x[4][i];
            x[5][i] ^= x[0][i] ^ x[6][i];
            x[7][i] ^= x[0][i];
            x[0][i] ^= x[3][i];
            x[2][i] ^= x[5][i];
            x[4][i] ^= x[1][i] ^ x[7][i];
            x[6][i] ^= x[1][i];
        }

        /* littleEndianBytes to long */
        private static long leBytesToLong(byte[] pBuffer, int pIndex) {
            pIndex *= 8;
            long value = 0;
            int i = 7;
            while (i > 0) {
                value += pBuffer[pIndex + i--] & 0xff;
                value <<= 8;
            }
            value += pBuffer[pIndex] & 0xff;
            return value;
        }

        /* long to littleEndianBytes */
        private static void longToLeBytes(long pValue, byte[] pBuffer, int pOffset, int pLength) {
            int i = 8;
            while (i > pLength) {
                pValue >>= 8;
                i--;
            }

            int pos = pOffset + pLength - i;
            while (i-- > 0) {
                pBuffer[pos++] = (byte) (pValue & 0xff);
                pValue >>= 8;
            }
        }

        /* The Sbox */
        private void Sbox(int i, int j, int roundnumber) {
            byte[] round = E8_bitslice_roundconstant[roundnumber];
            int index = i + (j * 2);
            long cc = leBytesToLong(round, index);
            x[6 + j][i] = ~x[6 + j][i];
            x[0 + j][i] ^= ((~x[4 + j][i]) & (cc));
            long temp0 = (cc) ^ (x[0 + j][i] & x[2 + j][i]);
            x[0 + j][i] ^= (x[4 + j][i] & x[6 + j][i]);
            x[6 + j][i] ^= ((~x[2 + j][i]) & x[4 + j][i]);
            x[2 + j][i] ^= (x[0 + j][i] & x[4 + j][i]);
            x[4 + j][i] ^= (x[0 + j][i] & (~x[6 + j][i]));
            x[0 + j][i] ^= (x[2 + j][i] | x[6 + j][i]);
            x[6 + j][i] ^= (x[2 + j][i] & x[4 + j][i]);
            x[2 + j][i] ^= (temp0 & x[0 + j][i]);
            x[4 + j][i] ^= temp0;
        }

        /* The round function of E8, in bitslice form */
        private void RoundFunction(int roundnumber) {
            int i, j;
            long temp0;

            /* Sbox and MDS layer */
            for (i = 0; i < 2; i++) {
                Sbox(i, 0, roundnumber);
                Sbox(i, 1, roundnumber);
                L(i);
            }

            /* swapping layer */
            switch (roundnumber % 7) {
                case 0:
                    for (j = 1; j < 8; j = j + 2)
                        for (i = 0; i < 2; i++)
                            x[j][i] = SWAP1(x[j][i]);
                    break;
                case 1:
                    for (j = 1; j < 8; j = j + 2)
                        for (i = 0; i < 2; i++)
                            x[j][i] = SWAP2(x[j][i]);
                    break;
                case 2:
                    for (j = 1; j < 8; j = j + 2)
                        for (i = 0; i < 2; i++)
                            x[j][i] = SWAP4(x[j][i]);
                    break;
                case 3:
                    for (j = 1; j < 8; j = j + 2)
                        for (i = 0; i < 2; i++)
                            x[j][i] = SWAP8(x[j][i]);
                    break;
                case 4:
                    for (j = 1; j < 8; j = j + 2)
                        for (i = 0; i < 2; i++)
                            x[j][i] = SWAP16(x[j][i]);
                    break;
                case 5:
                    for (j = 1; j < 8; j = j + 2)
                        for (i = 0; i < 2; i++)
                            x[j][i] = SWAP32(x[j][i]);
                    break;
                case 6:
                    for (j = 1; j < 8; j = j + 2) {
                        temp0 = x[j][0];
                        x[j][0] = x[j][1];
                        x[j][1] = temp0;
                    }
                    break;
            }
        }

        /* The bijective function E8, in bitslice form */
        private void E8() {
            int i;

            /* perform 42 rounds */
            for (i = 0; i < 42; i++)
                RoundFunction(i);
        }

        /* The compression function F8 */
        private void F8() {
            int i;

            /* xor the 512-bit message with the first half of the 1024-bit hash state */
            for (i = 0; i < 8; i++)
                x[i >> 1][i & 1] ^= leBytesToLong(buffer, i);

            /* the bijective function E8 */
            E8();

            /* xor the 512-bit message with the second half of the 1024-bit hash state */
            for (i = 0; i < 8; i++)
                x[(8 + i) >> 1][(8 + i) & 1] ^= leBytesToLong(buffer, i);
        }

        /* Build state from byte buffer */
        private void buildStateFromBytes(byte[] pBytes) {
            int index = 0;
            for (int i = 0; i < 8; i++) {
                for (int j = 0; j < 2; j++) {
                    x[i][j] = leBytesToLong(pBytes, index++);
                }
            }
        }

        /* before hashing a message, initialize the hash state as H0 */
        private void Init() {
            databitlen = 0;
            datasizeInBuffer = 0;

            /* load the initial hash value into state */
            switch (hashbitlen) {
                case 224:
                    buildStateFromBytes(JH224_H0);
                    break;
                case 256:
                    buildStateFromBytes(JH256_H0);
                    break;
                case 384:
                    buildStateFromBytes(JH384_H0);
                    break;
                case 512:
                    buildStateFromBytes(JH512_H0);
                    break;
            }
        }

        /* CopyIn a state */
        void copyIn(JHFastDigest pState) {
            /* Ensure that we are copying similar digest */
            if (this.hashbitlen != pState.hashbitlen)
                throw new IllegalArgumentException();

            /* Copy state */
            initialised = pState.initialised;
            databitlen = pState.databitlen;
            datasizeInBuffer = pState.datasizeInBuffer;
            System.arraycopy(pState.buffer, 0, buffer, 0, buffer.length);
            for (int i = 0; i < 8; i++) {
                for (int j = 0; j < 2; j++) {
                    x[i][j] = pState.x[i][j];
                }
            }
        }

        /**
         * Reset the digest.
         */
        void reset() {
            /* Clear the initialised flag */
            initialised = false;
        }

        /* hash each 512-bit message block, except the last partial block */
        void Update(byte[] data, int pOffset, long pDatabitlen) {
            int index; /* the starting address of the data to be compressed */

            /* Ensure that we are initialised */
            ensureInitialised();

            databitlen += pDatabitlen;
            index = 0;

            /* if there is remaining data in the buffer, fill it to a full message block first */
            /*
             * we assume that the size of the data in the buffer is the multiple of 8 bits if it is
             * not at the end of a message
             */

            /*
             * There is data in the buffer, but the incoming data is insufficient for a full block
             */
            if ((datasizeInBuffer > 0) && ((datasizeInBuffer + pDatabitlen) < 512)) {
                int copyDataLen = (int) (pDatabitlen >> 3);
                if ((pDatabitlen & 7) != 0) {
                    copyDataLen++;
                }
                System.arraycopy(data, pOffset, buffer, (int) (datasizeInBuffer >> 3), copyDataLen);
                datasizeInBuffer += pDatabitlen;
                pDatabitlen = 0;
            }

            /* There is data in the buffer, and the incoming data is sufficient for a full block */
            if ((datasizeInBuffer > 0) && ((datasizeInBuffer + pDatabitlen) >= 512)) {
                System.arraycopy(data, pOffset, buffer, (int) (datasizeInBuffer >> 3), (int) (64 - (datasizeInBuffer >> 3)));
                index = (int) (64 - (datasizeInBuffer >> 3));
                pDatabitlen = pDatabitlen - (512 - (int) datasizeInBuffer);
                F8();
                datasizeInBuffer = 0;
            }

            /* hash the remaining full message blocks */
            for (; pDatabitlen >= 512; index = index + 64, pDatabitlen = pDatabitlen - 512) {
                System.arraycopy(data, pOffset + index, buffer, 0, 64);
                F8();
            }

            /*
             * store the partial block into buffer, assume that -- if part of the last byte is not
             * part of the message, then that part consists of 0 bits
             */
            if (pDatabitlen > 0) {
                if ((pDatabitlen & 7) == 0)
                    System.arraycopy(data, pOffset + index, buffer, 0, (int) ((databitlen & 0x1ff) >> 3));
                else
                    System.arraycopy(data, pOffset + index, buffer, 0, (int) (((databitlen & 0x1ff) >> 3) + 1));
                datasizeInBuffer = pDatabitlen;
            }
        }

        /* Build hash from state buffer */
        private void buildHashFromState(byte[] pHashVal, int pOffset, int pLength) {
            for (int i = 7; i >= 0 && pLength > 0; i--) {
                for (int j = 1; j >= 0 && pLength > 0; j--) {
                    longToLeBytes(x[i][j], pHashVal, pOffset, pLength);
                    pLength -= 8;
                }
            }
        }

        /*
         * pad the message, process the padded block(s), truncate the hash value H to obtain the
         * message digest
         */
        void Final(byte[] hashval, int pOffset) {
            int i;

            /* Ensure that we are initialised */
            ensureInitialised();

            if ((databitlen & 0x1ff) == 0) {
                /*
                 * pad the message when databitlen is multiple of 512 bits, then process the padded
                 * block
                 */
                Arrays.fill(buffer, (byte) 0);
                buffer[0] = (byte) 0x80;
                buffer[63] = (byte) (databitlen & 0xff);
                buffer[62] = (byte) ((databitlen >> 8) & 0xff);
                buffer[61] = (byte) ((databitlen >> 16) & 0xff);
                buffer[60] = (byte) ((databitlen >> 24) & 0xff);
                buffer[59] = (byte) ((databitlen >> 32) & 0xff);
                buffer[58] = (byte) ((databitlen >> 40) & 0xff);
                buffer[57] = (byte) ((databitlen >> 48) & 0xff);
                buffer[56] = (byte) ((databitlen >> 56) & 0xff);
                F8();
            } else {
                /* set the rest of the bytes in the buffer to 0 */
                if ((datasizeInBuffer & 7) == 0)
                    for (i = (int) (databitlen & 0x1ff) >> 3; i < 64; i++)
                        buffer[i] = 0;
                else
                    for (i = (int) ((databitlen & 0x1ff) >> 3) + 1; i < 64; i++)
                        buffer[i] = 0;

                /*
                 * pad and process the partial block when databitlen is not multiple of 512 bits,
                 * then hash the padded blocks
                 */
                buffer[(int) ((databitlen & 0x1ff) >> 3)] |= 1 << (7 - (databitlen & 7));
                F8();
                Arrays.fill(buffer, (byte) 0);
                buffer[63] = (byte) (databitlen & 0xff);
                buffer[62] = (byte) ((databitlen >> 8) & 0xff);
                buffer[61] = (byte) ((databitlen >> 16) & 0xff);
                buffer[60] = (byte) ((databitlen >> 24) & 0xff);
                buffer[59] = (byte) ((databitlen >> 32) & 0xff);
                buffer[58] = (byte) ((databitlen >> 40) & 0xff);
                buffer[57] = (byte) ((databitlen >> 48) & 0xff);
                buffer[56] = (byte) ((databitlen >> 56) & 0xff);
                F8();
            }

            /* truncating the final hash value to generate the message digest */
            switch (hashbitlen) {
                case 224:
                    buildHashFromState(hashval, pOffset, 28);
                    break;
                case 256:
                    buildHashFromState(hashval, pOffset, 32);
                    break;
                case 384:
                    buildHashFromState(hashval, pOffset, 48);
                    break;
                case 512:
                    buildHashFromState(hashval, pOffset, 64);
                    break;
            }

            /* Reset the digest */
            reset();
        }
    }
}
