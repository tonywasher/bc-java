package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Memoable;

/**
 * Snow3GEngine implementation.
 * Based on https://www.gsma.com/aboutus/wp-content/uploads/2014/12/snow3gspec.pdf
 */
public class Snow3GEngine implements StreamCipher, Memoable {
    /* Rijndael S-box SR */
    private static final byte[] SR = {
            (byte)0x63,(byte)0x7C,(byte)0x77,(byte)0x7B,(byte)0xF2,(byte)0x6B,(byte)0x6F,(byte)0xC5,(byte)0x30,(byte)0x01,(byte)0x67,(byte)0x2B,(byte)0xFE,(byte)0xD7,(byte)0xAB,(byte)0x76,
            (byte)0xCA,(byte)0x82,(byte)0xC9,(byte)0x7D,(byte)0xFA,(byte)0x59,(byte)0x47,(byte)0xF0,(byte)0xAD,(byte)0xD4,(byte)0xA2,(byte)0xAF,(byte)0x9C,(byte)0xA4,(byte)0x72,(byte)0xC0,
            (byte)0xB7,(byte)0xFD,(byte)0x93,(byte)0x26,(byte)0x36,(byte)0x3F,(byte)0xF7,(byte)0xCC,(byte)0x34,(byte)0xA5,(byte)0xE5,(byte)0xF1,(byte)0x71,(byte)0xD8,(byte)0x31,(byte)0x15,
            (byte)0x04,(byte)0xC7,(byte)0x23,(byte)0xC3,(byte)0x18,(byte)0x96,(byte)0x05,(byte)0x9A,(byte)0x07,(byte)0x12,(byte)0x80,(byte)0xE2,(byte)0xEB,(byte)0x27,(byte)0xB2,(byte)0x75,
            (byte)0x09,(byte)0x83,(byte)0x2C,(byte)0x1A,(byte)0x1B,(byte)0x6E,(byte)0x5A,(byte)0xA0,(byte)0x52,(byte)0x3B,(byte)0xD6,(byte)0xB3,(byte)0x29,(byte)0xE3,(byte)0x2F,(byte)0x84,
            (byte)0x53,(byte)0xD1,(byte)0x00,(byte)0xED,(byte)0x20,(byte)0xFC,(byte)0xB1,(byte)0x5B,(byte)0x6A,(byte)0xCB,(byte)0xBE,(byte)0x39,(byte)0x4A,(byte)0x4C,(byte)0x58,(byte)0xCF,
            (byte)0xD0,(byte)0xEF,(byte)0xAA,(byte)0xFB,(byte)0x43,(byte)0x4D,(byte)0x33,(byte)0x85,(byte)0x45,(byte)0xF9,(byte)0x02,(byte)0x7F,(byte)0x50,(byte)0x3C,(byte)0x9F,(byte)0xA8,
            (byte)0x51,(byte)0xA3,(byte)0x40,(byte)0x8F,(byte)0x92,(byte)0x9D,(byte)0x38,(byte)0xF5,(byte)0xBC,(byte)0xB6,(byte)0xDA,(byte)0x21,(byte)0x10,(byte)0xFF,(byte)0xF3,(byte)0xD2,
            (byte)0xCD,(byte)0x0C,(byte)0x13,(byte)0xEC,(byte)0x5F,(byte)0x97,(byte)0x44,(byte)0x17,(byte)0xC4,(byte)0xA7,(byte)0x7E,(byte)0x3D,(byte)0x64,(byte)0x5D,(byte)0x19,(byte)0x73,
            (byte)0x60,(byte)0x81,(byte)0x4F,(byte)0xDC,(byte)0x22,(byte)0x2A,(byte)0x90,(byte)0x88,(byte)0x46,(byte)0xEE,(byte)0xB8,(byte)0x14,(byte)0xDE,(byte)0x5E,(byte)0x0B,(byte)0xDB,
            (byte)0xE0,(byte)0x32,(byte)0x3A,(byte)0x0A,(byte)0x49,(byte)0x06,(byte)0x24,(byte)0x5C,(byte)0xC2,(byte)0xD3,(byte)0xAC,(byte)0x62,(byte)0x91,(byte)0x95,(byte)0xE4,(byte)0x79,
            (byte)0xE7,(byte)0xC8,(byte)0x37,(byte)0x6D,(byte)0x8D,(byte)0xD5,(byte)0x4E,(byte)0xA9,(byte)0x6C,(byte)0x56,(byte)0xF4,(byte)0xEA,(byte)0x65,(byte)0x7A,(byte)0xAE,(byte)0x08,
            (byte)0xBA,(byte)0x78,(byte)0x25,(byte)0x2E,(byte)0x1C,(byte)0xA6,(byte)0xB4,(byte)0xC6,(byte)0xE8,(byte)0xDD,(byte)0x74,(byte)0x1F,(byte)0x4B,(byte)0xBD,(byte)0x8B,(byte)0x8A,
            (byte)0x70,(byte)0x3E,(byte)0xB5,(byte)0x66,(byte)0x48,(byte)0x03,(byte)0xF6,(byte)0x0E,(byte)0x61,(byte)0x35,(byte)0x57,(byte)0xB9,(byte)0x86,(byte)0xC1,(byte)0x1D,(byte)0x9E,
            (byte)0xE1,(byte)0xF8,(byte)0x98,(byte)0x11,(byte)0x69,(byte)0xD9,(byte)0x8E,(byte)0x94,(byte)0x9B,(byte)0x1E,(byte)0x87,(byte)0xE9,(byte)0xCE,(byte)0x55,(byte)0x28,(byte)0xDF,
            (byte)0x8C,(byte)0xA1,(byte)0x89,(byte)0x0D,(byte)0xBF,(byte)0xE6,(byte)0x42,(byte)0x68,(byte)0x41,(byte)0x99,(byte)0x2D,(byte)0x0F,(byte)0xB0,(byte)0x54,(byte)0xBB,(byte)0x16
    };
    /* S-box SQ */
    private static final byte[] SQ = {
            (byte)0x25,(byte)0x24,(byte)0x73,(byte)0x67,(byte)0xD7,(byte)0xAE,(byte)0x5C,(byte)0x30,(byte)0xA4,(byte)0xEE,(byte)0x6E,(byte)0xCB,(byte)0x7D,(byte)0xB5,(byte)0x82,(byte)0xDB,
            (byte)0xE4,(byte)0x8E,(byte)0x48,(byte)0x49,(byte)0x4F,(byte)0x5D,(byte)0x6A,(byte)0x78,(byte)0x70,(byte)0x88,(byte)0xE8,(byte)0x5F,(byte)0x5E,(byte)0x84,(byte)0x65,(byte)0xE2,
            (byte)0xD8,(byte)0xE9,(byte)0xCC,(byte)0xED,(byte)0x40,(byte)0x2F,(byte)0x11,(byte)0x28,(byte)0x57,(byte)0xD2,(byte)0xAC,(byte)0xE3,(byte)0x4A,(byte)0x15,(byte)0x1B,(byte)0xB9,
            (byte)0xB2,(byte)0x80,(byte)0x85,(byte)0xA6,(byte)0x2E,(byte)0x02,(byte)0x47,(byte)0x29,(byte)0x07,(byte)0x4B,(byte)0x0E,(byte)0xC1,(byte)0x51,(byte)0xAA,(byte)0x89,(byte)0xD4,
            (byte)0xCA,(byte)0x01,(byte)0x46,(byte)0xB3,(byte)0xEF,(byte)0xDD,(byte)0x44,(byte)0x7B,(byte)0xC2,(byte)0x7F,(byte)0xBE,(byte)0xC3,(byte)0x9F,(byte)0x20,(byte)0x4C,(byte)0x64,
            (byte)0x83,(byte)0xA2,(byte)0x68,(byte)0x42,(byte)0x13,(byte)0xB4,(byte)0x41,(byte)0xCD,(byte)0xBA,(byte)0xC6,(byte)0xBB,(byte)0x6D,(byte)0x4D,(byte)0x71,(byte)0x21,(byte)0xF4,
            (byte)0x8D,(byte)0xB0,(byte)0xE5,(byte)0x93,(byte)0xFE,(byte)0x8F,(byte)0xE6,(byte)0xCF,(byte)0x43,(byte)0x45,(byte)0x31,(byte)0x22,(byte)0x37,(byte)0x36,(byte)0x96,(byte)0xFA,
            (byte)0xBC,(byte)0x0F,(byte)0x08,(byte)0x52,(byte)0x1D,(byte)0x55,(byte)0x1A,(byte)0xC5,(byte)0x4E,(byte)0x23,(byte)0x69,(byte)0x7A,(byte)0x92,(byte)0xFF,(byte)0x5B,(byte)0x5A,
            (byte)0xEB,(byte)0x9A,(byte)0x1C,(byte)0xA9,(byte)0xD1,(byte)0x7E,(byte)0x0D,(byte)0xFC,(byte)0x50,(byte)0x8A,(byte)0xB6,(byte)0x62,(byte)0xF5,(byte)0x0A,(byte)0xF8,(byte)0xDC,
            (byte)0x03,(byte)0x3C,(byte)0x0C,(byte)0x39,(byte)0xF1,(byte)0xB8,(byte)0xF3,(byte)0x3D,(byte)0xF2,(byte)0xD5,(byte)0x97,(byte)0x66,(byte)0x81,(byte)0x32,(byte)0xA0,(byte)0x00,
            (byte)0x06,(byte)0xCE,(byte)0xF6,(byte)0xEA,(byte)0xB7,(byte)0x17,(byte)0xF7,(byte)0x8C,(byte)0x79,(byte)0xD6,(byte)0xA7,(byte)0xBF,(byte)0x8B,(byte)0x3F,(byte)0x1F,(byte)0x53,
            (byte)0x63,(byte)0x75,(byte)0x35,(byte)0x2C,(byte)0x60,(byte)0xFD,(byte)0x27,(byte)0xD3,(byte)0x94,(byte)0xA5,(byte)0x7C,(byte)0xA1,(byte)0x05,(byte)0x58,(byte)0x2D,(byte)0xBD,
            (byte)0xD9,(byte)0xC7,(byte)0xAF,(byte)0x6B,(byte)0x54,(byte)0x0B,(byte)0xE0,(byte)0x38,(byte)0x04,(byte)0xC8,(byte)0x9D,(byte)0xE7,(byte)0x14,(byte)0xB1,(byte)0x87,(byte)0x9C,
            (byte)0xDF,(byte)0x6F,(byte)0xF9,(byte)0xDA,(byte)0x2A,(byte)0xC4,(byte)0x59,(byte)0x16,(byte)0x74,(byte)0x91,(byte)0xAB,(byte)0x26,(byte)0x61,(byte)0x76,(byte)0x34,(byte)0x2B,
            (byte)0xAD,(byte)0x99,(byte)0xFB,(byte)0x72,(byte)0xEC,(byte)0x33,(byte)0x12,(byte)0xDE,(byte)0x98,(byte)0x3B,(byte)0xC0,(byte)0x9B,(byte)0x3E,(byte)0x18,(byte)0x10,(byte)0x3A,
            (byte)0x56,(byte)0xE1,(byte)0x77,(byte)0xC9,(byte)0x1E,(byte)0x9E,(byte)0x95,(byte)0xA3,(byte)0x90,(byte)0x19,(byte)0xA8,(byte)0x6C,(byte)0x09,(byte)0xD0,(byte)0xF0,(byte)0x86
    };

    /**
     * State.
     */
    private final int[] LFSR = new int[16];
    private final int[] FSM = new int[3];

    /**
     * index of next byte in keyStream.
     */
    private int theIndex;

    /**
     * Advanced stream.
     */
    private final byte[] keyStream = new byte[Integer.BYTES];

    /**
     * The iterations.
     */
    private int theIterations;

    /**
     * Reset state.
     */
    private Snow3GEngine theResetState;

    /**
     * Constructor.
     */
    public Snow3GEngine() {
    }

    /**
     * Constructor.
     * @param pSource the source engine
     */
    private Snow3GEngine(Snow3GEngine pSource) {
        reset(pSource);
    }

    /**
     * initialise a Snow3G cipher.
     * @param forEncryption whether or not we are for encryption.
     * @param params the parameters required to set up the cipher.
     * @exception IllegalArgumentException if the params argument is inappropriate.
     */
    public void init(final boolean forEncryption,
                     final CipherParameters params) {
        /*
         * encryption and decryption is completely symmetrical, so the 'forEncryption' is
         * irrelevant. (Like 90% of stream ciphers)
         */

        /* Determine parameters */
        CipherParameters myParams = params;
        byte[] newKey = null;
        byte[] newIV = null;
        if ((myParams instanceof ParametersWithIV)) {
            final ParametersWithIV ivParams = (ParametersWithIV) myParams;
            newIV = ivParams.getIV();
            myParams = ivParams.getParameters();
        }
        if (myParams instanceof KeyParameter) {
            final KeyParameter keyParam = (KeyParameter) myParams;
            newKey = keyParam.getKey();
        }

        /* Initialise engine and mark as initialised */
        theIndex = 0;
        theIterations = 0;
        setKeyAndIV(newKey, newIV);

        /* Save reset state */
        theResetState = copy();
    }

    /**
     * Obtain Max iterations.
     * @return the maximum iterations
     */
    protected int getMaxIterations() {
        return 625;
    }

    @Override
    public String getAlgorithmName() {
        return "Snow3G";
    }

    @Override
    public int processBytes(final byte[] in,
                            final int inOff,
                            final int len,
                            final byte[] out,
                            final int outOff) {
        /* Check for errors */
        if (theResetState == null) {
            throw new IllegalStateException(getAlgorithmName() + " not initialised");
        }
        if ((inOff + len) > in.length) {
            throw new DataLengthException("input buffer too short");
        }
        if ((outOff + len) > out.length) {
            throw new OutputLengthException("output buffer too short");
        }

        /* Loop through the input bytes */
        for (int i = 0; i < len; i++) {
            out[i + outOff] = returnByte(in[i + inOff]);
        }
        return len;
    }

    @Override
    public void reset() {
        if (theResetState != null) {
            reset(theResetState);
        }
    }

    @Override
    public byte returnByte(final byte in) {
        /* Make the keyStream if required */
        if (theIndex == 0) {
            makeKeyStream();
        }

        /* Map the next byte and adjust index */
        final byte out = (byte) (keyStream[theIndex] ^ in);
        theIndex = (theIndex + 1) % Integer.BYTES;

        /* Return the mapped character */
        return out;
    }

    /**
     * Decode a 32-bit value from a buffer (little-endian).
     *
     * @param buf the input buffer
     * @param off the input offset
     * @return the decoded value
     */
    private static int decode32be(byte[] buf, int off) {
        return ((buf[off] & 0xFF) << 24)
                | ((buf[off + 1] & 0xFF) << 16)
                | ((buf[off + 2] & 0xFF) << 8)
                | (buf[off + 3] & 0xFF);
    }

    /**
     * Encode a 32-bit value into a buffer (little-endian).
     *
     * @param val the value to encode
     * @param buf the output buffer
     * @param off the output offset
     */
    private static void encode32be(int val, byte[] buf, int off) {
        buf[off] = (byte) (val >> 24);
        buf[off + 1] = (byte) (val >> 16);
        buf[off + 2] = (byte) (val >> 8);
        buf[off + 3] = (byte) (val);
    }

    /* MULx.
     * Input V: an 8-bit input.
     * Input c: an 8-bit input.
     * Output : an 8-bit output.
     * See section 3.1.1 for details.
     */
    int MULx(byte V, int c)
    {
        if ((V & 0x80) != 0)
            return ((V << 1) ^ c) & 0xFF;
        else
            return (V << 1) & 0xFF;
    }

    /* MULxPOW.
     * Input V: an 8-bit input.
     * Input i: a positive integer.
     * Input c: an 8-bit input.
     * Output : an 8-bit output.
     * See section 3.1.2 for details.
     */
    int MULxPOW(byte V, int i, int c)
    {
        if (i == 0)
            return V & 0xFF;
        else
            return MULx((byte) MULxPOW(V, i - 1, c), c);
    }

    /* The function MUL alpha.
     * Input c: 8-bit input.
     * Output : 32-bit output.
     * See section 3.4.2 for details.
     */
    int MULalpha(byte c)
    {
        return (((MULxPOW(c, 23, 0xa9)) << 24) |
                ((MULxPOW(c, 245, 0xa9)) << 16) |
                ((MULxPOW(c, 48, 0xa9)) << 8) |
                ((MULxPOW(c, 239, 0xa9))));
    }

    /* The function DIV alpha.
     * Input c: 8-bit input.
     * Output : 32-bit output.
     * See section 3.4.3 for details.
     */
    int DIValpha(byte c)
    {
        return (((MULxPOW(c, 16, 0xa9)) << 24) |
                ((MULxPOW(c, 39, 0xa9)) << 16) |
                ((MULxPOW(c, 6, 0xa9)) << 8) |
                ((MULxPOW(c, 64, 0xa9))));
    }

    /* The 32x32-bit S-Box S1
     * Input: a 32-bit input.
     * Output: a 32-bit output of S1 box.
     * See section 3.3.1.
     */
    int S1(int w)
    {
        int r0 = 0, r1 = 0, r2 = 0, r3 = 0;
        byte srw0 = (byte) SR[((w >> 24) & 0xff)];
        byte srw1 = (byte) SR[((w >> 16) & 0xff)];
        byte srw2 = (byte) SR[((w >> 8) & 0xff)];
        byte srw3 = (byte) SR[((w) & 0xff)];
        r0 = ((MULx(srw0, 0x1b)) ^
                (srw1) ^
                (srw2) ^
                ((MULx(srw3, 0x1b)) ^ srw3)
        ) & 0xFF;
        r1 = (((MULx(srw0, 0x1b)) ^ srw0) ^
                (MULx(srw1, 0x1b)) ^
                (srw2) ^
                (srw3)
        ) & 0xFF;
        r2 = ((srw0) ^
                ((MULx(srw1, 0x1b)) ^ srw1) ^
                (MULx(srw2, 0x1b)) ^
                (srw3)
        ) & 0xFF;
        r3 = ((srw0) ^
                (srw1) ^
                ((MULx(srw2, 0x1b)) ^ srw2) ^
                (MULx(srw3, 0x1b))
        ) & 0xFF;
        return (((r0) << 24) | ((r1) << 16) | ((r2) << 8) |
                ((r3)));
    }

    /* The 32x32-bit S-Box S2
     * Input: a 32-bit input.
     * Output: a 32-bit output of S2 box.
     * See section 3.3.2.
     */
    int S2(int w)
    {
        int r0 = 0, r1 = 0, r2 = 0, r3 = 0;
        byte sqw0 = (byte) SQ[((w >> 24) & 0xff)];
        byte sqw1 = (byte) SQ[((w >> 16) & 0xff)];
        byte sqw2 = (byte) SQ[((w >> 8) & 0xff)];
        byte sqw3 = (byte) SQ[((w) & 0xff)];
        r0 = ((MULx(sqw0, 0x69)) ^
                (sqw1) ^
                (sqw2) ^
                ((MULx(sqw3, 0x69)) ^ sqw3)
        ) & 0xFF;
        r1 = (((MULx(sqw0, 0x69)) ^ sqw0) ^
                (MULx(sqw1, 0x69)) ^
                (sqw2) ^
                (sqw3)
        ) & 0xFF;
        r2 = ((sqw0) ^
                ((MULx(sqw1, 0x69)) ^ sqw1) ^
                (MULx(sqw2, 0x69)) ^
                (sqw3)
        ) & 0xFF;
        r3 = ((sqw0) ^
                (sqw1) ^
                ((MULx(sqw2, 0x69)) ^ sqw2) ^
                (MULx(sqw3, 0x69))
        ) & 0xFF;
        return (((r0) << 24) | ((r1) << 16) | ((r2) << 8) |
                ((r3)));
    }

    /* Clocking LFSR in initialization mode.
     * LFSR Registers S0 to S15 are updated as the LFSR receives a single clock.
     * Input F: a 32-bit word comes from output of FSM.
     * See section 3.4.4.
     */
    void ClockLFSRInitializationMode(int F)
    {
        int v = (((LFSR[0] << 8) & 0xffffff00) ^
                (MULalpha((byte)((LFSR[0] >>> 24) & 0xff))) ^
                (LFSR[2]) ^
                ((LFSR[11] >>> 8) & 0x00ffffff) ^
                (DIValpha((byte)((LFSR[11]) & 0xff))) ^
                (F)
        );
        LFSR[0] = LFSR[1];
        LFSR[1] = LFSR[2];
        LFSR[2] = LFSR[3];
        LFSR[3] = LFSR[4];
        LFSR[4] = LFSR[5];
        LFSR[5] = LFSR[6];
        LFSR[6] = LFSR[7];
        LFSR[7] = LFSR[8];
        LFSR[8] = LFSR[9];
        LFSR[9] = LFSR[10];
        LFSR[10] = LFSR[11];
        LFSR[11] = LFSR[12];
        LFSR[12] = LFSR[13];
        LFSR[13] = LFSR[14];
        LFSR[14] = LFSR[15];
        LFSR[15] = v;
    }

    /* Clocking LFSR in keystream mode.
     * LFSR Registers S0 to S15 are updated as the LFSR receives a single clock.
     * See section 3.4.5.
     */
    void ClockLFSRKeyStreamMode()
    {
        int v = (((LFSR[0] << 8) & 0xffffff00) ^
                (MULalpha((byte)((LFSR[0] >>> 24) & 0xff))) ^
                (LFSR[2]) ^
                ((LFSR[11] >>> 8) & 0x00ffffff) ^
                (DIValpha((byte) ((LFSR[11]) & 0xff)))
        );
        LFSR[0] = LFSR[1];
        LFSR[1] = LFSR[2];
        LFSR[2] = LFSR[3];
        LFSR[3] = LFSR[4];
        LFSR[4] = LFSR[5];
        LFSR[5] = LFSR[6];
        LFSR[6] = LFSR[7];
        LFSR[7] = LFSR[8];
        LFSR[8] = LFSR[9];
        LFSR[9] = LFSR[10];
        LFSR[10] = LFSR[11];
        LFSR[11] = LFSR[12];
        LFSR[12] = LFSR[13];
        LFSR[13] = LFSR[14];
        LFSR[14] = LFSR[15];
        LFSR[15] = v;
    }

    /* Clocking FSM.
     * Produces a 32-bit word F.
     * Updates FSM registers R1, R2, R3.
     * See Section 3.4.6.
     */
    int ClockFSM()
    {
        int F = ((LFSR[15] + FSM[0]) & 0xffffffff) ^ FSM[1];
        int r = (FSM[1] + (FSM[2] ^ LFSR[5])) & 0xffffffff;
        FSM[2] = S2(FSM[1]);
        FSM[1] = S1(FSM[0]);
        FSM[0] = r;
        return F;
    }

    /* Initialization.
    * Input k[4]: Four 32-bit words making up 128-bit key.
    * Input IV[4]: Four 32-bit words making 128-bit initialization variable.
    * Output: All the LFSRs and FSM are initialized for key generation.
    * See Section 4.1.
    */
    void setKeyAndIV(byte[] key, byte[] iv)
    {
        /* Check lengths */
        if (key == null || key.length != 16) {
            throw new IllegalArgumentException("A key of 16 bytes is needed");
        }
        if (iv == null || iv.length != 16) {
            throw new IllegalArgumentException("An IV of 16 bytes is needed");
        }

        /* Temporary variables */
        int k0, k1, k2, k3, i0, i1, i2, i3;

        /* Generate four subkeys */
        k0 = decode32be(key, 12);
        k1 = decode32be(key, 8);
        k2 = decode32be(key, 4);
        k3 = decode32be(key, 0);

        /* Generate four subvectors */
        i0 = decode32be(iv, 12);
        i1 = decode32be(iv, 8);
        i2 = decode32be(iv, 4);
        i3 = decode32be(iv, 0);

        LFSR[15] = k3 ^ i0;
        LFSR[14] = k2;
        LFSR[13] = k1;
        LFSR[12] = k0 ^ i1;
        LFSR[11] = k3 ^ 0xffffffff;
        LFSR[10] = k2 ^ 0xffffffff ^ i2;
        LFSR[9] = k1 ^ 0xffffffff ^ i3;
        LFSR[8] = k0 ^ 0xffffffff;
        LFSR[7] = k3;
        LFSR[6] = k2;
        LFSR[5] = k1;
        LFSR[4] = k0;
        LFSR[3] = k3 ^ 0xffffffff;
        LFSR[2] = k2 ^ 0xffffffff;
        LFSR[1] = k1 ^ 0xffffffff;
        LFSR[0] = k0 ^ 0xffffffff;
        FSM[0] = 0x0;
        FSM[1] = 0x0;
        FSM[2] = 0x0;
        for (int i = 0; i<32; i++)
        {
            int F = ClockFSM();
            ClockLFSRInitializationMode(F);
        }
        ClockFSM(); /* Clock FSM once. Discard the output. */
        ClockLFSRKeyStreamMode(); /* Clock LFSR in keystream mode once. */
    }

    /* Generation of Keystream.
     * input n: number of 32-bit words of keystream.
     * input z: space for the generated keystream, assumes
     * memory is allocated already.
     * output: generated keystream which is filled in z
     * See section 4.2.
     */
    void makeKeyStream()
    {
        if (theIterations++ >= getMaxIterations()) {
            throw new IllegalStateException("Too much data processed by singleKey/IV");
        }
        int F = ClockFSM(); /* STEP 1 */
        encode32be(F ^ LFSR[0], keyStream, 0); /* STEP 2 */
        /* Note that ks[t] corresponds to z_{t+1} in section 4.2 */
        ClockLFSRKeyStreamMode(); /* STEP 3 */
    }

    @Override
    public Snow3GEngine copy() {
        return new Snow3GEngine(this);
    }

    @Override
    public void reset(final Memoable pState) {
        final Snow3GEngine e = (Snow3GEngine) pState;
        System.arraycopy(e.LFSR, 0, LFSR, 0, LFSR.length);
        System.arraycopy(e.FSM, 0, FSM, 0, FSM.length);
        System.arraycopy(e.keyStream, 0, keyStream, 0, keyStream.length);
        theIterations = e.theIterations;
        theIndex = e.theIndex;
    }
}
