package org.bouncycastle.crypto.digests;

import java.util.Arrays;

import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.util.Memoable;

/**
 * Groestl Digest.
 * <p>
 * The embedded GroestlFastDigest class is ported from the C implementation in
 * groestl_opt.h/tables.h in the "NIST submission package" at http://www.groestl.info with tweaks to
 * interface to the BouncyCastle libraries
 */
public class GroestlDigest
        implements ExtendedDigest, Memoable {
    /**
     * The underlying digest.
     */
    private final GroestlFastDigest theDigest;

    /**
     * The digest length.
     */
    private final int theDigestLen;

    /**
     * Constructor.
     * @param pHashBitLen the hash bit length
     */
    public GroestlDigest(final int pHashBitLen) {
        theDigest = new GroestlFastDigest(pHashBitLen);
        theDigestLen = pHashBitLen / Byte.SIZE;
    }

    /**
     * Constructor.
     * @param pDigest the digest to copy
     */
    public GroestlDigest(final GroestlDigest pDigest) {
        theDigestLen = pDigest.theDigestLen;
        theDigest = new GroestlFastDigest(theDigestLen * Byte.SIZE);
        theDigest.copyIn(pDigest.theDigest);
    }

    @Override
    public int doFinal(final byte[] pHash, final int pOffset) {
        theDigest.Final(pHash, pOffset);
        return getDigestSize();
    }

    @Override
    public String getAlgorithmName() {
        return "Groestl";
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
    public GroestlDigest copy() {
        return new GroestlDigest(this);
    }

    @Override
    public void reset(final Memoable pState) {
        final GroestlDigest d = (GroestlDigest) pState;
        theDigest.copyIn(d.theDigest);
    }

    /**
     * Groestl Digest Fast version.
     * <p>
     * Ported from the C implementation in groestl_opt.h/tables.h in the "NIST submission package"
     * at http://www.groestl.info with tweaks to interface to the BouncyCastle libraries
     */
    private static class GroestlFastDigest {
        /* Constants */
        private static final int ROWS = 8;
        private static final int LENGTHFIELDLEN = ROWS;
        private static final int COLS512 = 8;
        private static final int COLS1024 = 16;
        private static final int SIZE512 = (ROWS * COLS512);
        private static final int SIZE1024 = (ROWS * COLS1024);
        private static final int ROUNDS512 = 10;
        private static final int ROUNDS1024 = 14;

        /* State */
        private final int hashbitlen; /* output length in bits */
        private final int size; /* LONG or SHORT */
        private final boolean isShort; /* LONG or SHORT */
        private boolean initialised;
        private long block_counter; /* message block counter */
        private long[] chaining; /* actual state */
        private byte[] buffer; /* data buffer */
        private int buf_ptr; /* data buffer pointer */
        private int bits_in_last_byte; /*
                                        * no. of message bits in last byte of data buffer
                                        */

        /* Work ScratchPad fields */
        private long[] tmpY;
        private long[] tmpZ;
        private long[] tmpOutQ;
        private long[] tmpInP;

        /* Lookup Table */
        private static final long[] T =
        {
                0xc6a597f4a5f432c6L, 0xf884eb9784976ff8L, 0xee99c7b099b05eeeL, 0xf68df78c8d8c7af6L, 0xff0de5170d17e8ffL, 0xd6bdb7dcbddc0ad6L, 0xdeb1a7c8b1c816deL, 0x915439fc54fc6d91L,
                0x6050c0f050f09060L, 0x0203040503050702L, 0xcea987e0a9e02eceL, 0x567dac877d87d156L, 0xe719d52b192bcce7L, 0xb56271a662a613b5L, 0x4de69a31e6317c4dL, 0xec9ac3b59ab559ecL,
                0x8f4505cf45cf408fL, 0x1f9d3ebc9dbca31fL, 0x894009c040c04989L, 0xfa87ef92879268faL, 0xef15c53f153fd0efL, 0xb2eb7f26eb2694b2L, 0x8ec90740c940ce8eL, 0xfb0bed1d0b1de6fbL,
                0x41ec822fec2f6e41L, 0xb3677da967a91ab3L, 0x5ffdbe1cfd1c435fL, 0x45ea8a25ea256045L, 0x23bf46dabfdaf923L, 0x53f7a602f7025153L, 0xe496d3a196a145e4L, 0x9b5b2ded5bed769bL,
                0x75c2ea5dc25d2875L, 0xe11cd9241c24c5e1L, 0x3dae7ae9aee9d43dL, 0x4c6a98be6abef24cL, 0x6c5ad8ee5aee826cL, 0x7e41fcc341c3bd7eL, 0xf502f1060206f3f5L, 0x834f1dd14fd15283L,
                0x685cd0e45ce48c68L, 0x51f4a207f4075651L, 0xd134b95c345c8dd1L, 0xf908e9180818e1f9L, 0xe293dfae93ae4ce2L, 0xab734d9573953eabL, 0x6253c4f553f59762L, 0x2a3f54413f416b2aL,
                0x080c10140c141c08L, 0x955231f652f66395L, 0x46658caf65afe946L, 0x9d5e21e25ee27f9dL, 0x3028607828784830L, 0x37a16ef8a1f8cf37L, 0x0a0f14110f111b0aL, 0x2fb55ec4b5c4eb2fL,
                0x0e091c1b091b150eL, 0x2436485a365a7e24L, 0x1b9b36b69bb6ad1bL, 0xdf3da5473d4798dfL, 0xcd26816a266aa7cdL, 0x4e699cbb69bbf54eL, 0x7fcdfe4ccd4c337fL, 0xea9fcfba9fba50eaL,
                0x121b242d1b2d3f12L, 0x1d9e3ab99eb9a41dL, 0x5874b09c749cc458L, 0x342e68722e724634L, 0x362d6c772d774136L, 0xdcb2a3cdb2cd11dcL, 0xb4ee7329ee299db4L, 0x5bfbb616fb164d5bL,
                0xa4f65301f601a5a4L, 0x764decd74dd7a176L, 0xb76175a361a314b7L, 0x7dcefa49ce49347dL, 0x527ba48d7b8ddf52L, 0xdd3ea1423e429fddL, 0x5e71bc937193cd5eL, 0x139726a297a2b113L,
                0xa6f55704f504a2a6L, 0xb96869b868b801b9L, 0x0000000000000000L, 0xc12c99742c74b5c1L, 0x406080a060a0e040L, 0xe31fdd211f21c2e3L, 0x79c8f243c8433a79L, 0xb6ed772ced2c9ab6L,
                0xd4beb3d9bed90dd4L, 0x8d4601ca46ca478dL, 0x67d9ce70d9701767L, 0x724be4dd4bddaf72L, 0x94de3379de79ed94L, 0x98d42b67d467ff98L, 0xb0e87b23e82393b0L, 0x854a11de4ade5b85L,
                0xbb6b6dbd6bbd06bbL, 0xc52a917e2a7ebbc5L, 0x4fe59e34e5347b4fL, 0xed16c13a163ad7edL, 0x86c51754c554d286L, 0x9ad72f62d762f89aL, 0x6655ccff55ff9966L, 0x119422a794a7b611L,
                0x8acf0f4acf4ac08aL, 0xe910c9301030d9e9L, 0x0406080a060a0e04L, 0xfe81e798819866feL, 0xa0f05b0bf00baba0L, 0x7844f0cc44ccb478L, 0x25ba4ad5bad5f025L, 0x4be3963ee33e754bL,
                0xa2f35f0ef30eaca2L, 0x5dfeba19fe19445dL, 0x80c01b5bc05bdb80L, 0x058a0a858a858005L, 0x3fad7eecadecd33fL, 0x21bc42dfbcdffe21L, 0x7048e0d848d8a870L, 0xf104f90c040cfdf1L,
                0x63dfc67adf7a1963L, 0x77c1ee58c1582f77L, 0xaf75459f759f30afL, 0x426384a563a5e742L, 0x2030405030507020L, 0xe51ad12e1a2ecbe5L, 0xfd0ee1120e12effdL, 0xbf6d65b76db708bfL,
                0x814c19d44cd45581L, 0x1814303c143c2418L, 0x26354c5f355f7926L, 0xc32f9d712f71b2c3L, 0xbee16738e13886beL, 0x35a26afda2fdc835L, 0x88cc0b4fcc4fc788L, 0x2e395c4b394b652eL,
                0x93573df957f96a93L, 0x55f2aa0df20d5855L, 0xfc82e39d829d61fcL, 0x7a47f4c947c9b37aL, 0xc8ac8befacef27c8L, 0xbae76f32e73288baL, 0x322b647d2b7d4f32L, 0xe695d7a495a442e6L,
                0xc0a09bfba0fb3bc0L, 0x199832b398b3aa19L, 0x9ed12768d168f69eL, 0xa37f5d817f8122a3L, 0x446688aa66aaee44L, 0x547ea8827e82d654L, 0x3bab76e6abe6dd3bL, 0x0b83169e839e950bL,
                0x8cca0345ca45c98cL, 0xc729957b297bbcc7L, 0x6bd3d66ed36e056bL, 0x283c50443c446c28L, 0xa779558b798b2ca7L, 0xbce2633de23d81bcL, 0x161d2c271d273116L, 0xad76419a769a37adL,
                0xdb3bad4d3b4d96dbL, 0x6456c8fa56fa9e64L, 0x744ee8d24ed2a674L, 0x141e28221e223614L, 0x92db3f76db76e492L, 0x0c0a181e0a1e120cL, 0x486c90b46cb4fc48L, 0xb8e46b37e4378fb8L,
                0x9f5d25e75de7789fL, 0xbd6e61b26eb20fbdL, 0x43ef862aef2a6943L, 0xc4a693f1a6f135c4L, 0x39a872e3a8e3da39L, 0x31a462f7a4f7c631L, 0xd337bd5937598ad3L, 0xf28bff868b8674f2L,
                0xd532b156325683d5L, 0x8b430dc543c54e8bL, 0x6e59dceb59eb856eL, 0xdab7afc2b7c218daL, 0x018c028f8c8f8e01L, 0xb16479ac64ac1db1L, 0x9cd2236dd26df19cL, 0x49e0923be03b7249L,
                0xd8b4abc7b4c71fd8L, 0xacfa4315fa15b9acL, 0xf307fd090709faf3L, 0xcf25856f256fa0cfL, 0xcaaf8feaafea20caL, 0xf48ef3898e897df4L, 0x47e98e20e9206747L, 0x1018202818283810L,
                0x6fd5de64d5640b6fL, 0xf088fb83888373f0L, 0x4a6f94b16fb1fb4aL, 0x5c72b8967296ca5cL, 0x3824706c246c5438L, 0x57f1ae08f1085f57L, 0x73c7e652c7522173L, 0x975135f351f36497L,
                0xcb238d652365aecbL, 0xa17c59847c8425a1L, 0xe89ccbbf9cbf57e8L, 0x3e217c6321635d3eL, 0x96dd377cdd7cea96L, 0x61dcc27fdc7f1e61L, 0x0d861a9186919c0dL, 0x0f851e9485949b0fL,
                0xe090dbab90ab4be0L, 0x7c42f8c642c6ba7cL, 0x71c4e257c4572671L, 0xccaa83e5aae529ccL, 0x90d83b73d873e390L, 0x06050c0f050f0906L, 0xf701f5030103f4f7L, 0x1c12383612362a1cL,
                0xc2a39ffea3fe3cc2L, 0x6a5fd4e15fe18b6aL, 0xaef94710f910beaeL, 0x69d0d26bd06b0269L, 0x17912ea891a8bf17L, 0x995829e858e87199L, 0x3a2774692769533aL, 0x27b94ed0b9d0f727L,
                0xd938a948384891d9L, 0xeb13cd351335deebL, 0x2bb356ceb3cee52bL, 0x2233445533557722L, 0xd2bbbfd6bbd604d2L, 0xa9704990709039a9L, 0x07890e8089808707L, 0x33a766f2a7f2c133L,
                0x2db65ac1b6c1ec2dL, 0x3c22786622665a3cL, 0x15922aad92adb815L, 0xc92089602060a9c9L, 0x874915db49db5c87L, 0xaaff4f1aff1ab0aaL, 0x5078a0887888d850L, 0xa57a518e7a8e2ba5L,
                0x038f068a8f8a8903L, 0x59f8b213f8134a59L, 0x0980129b809b9209L, 0x1a1734391739231aL, 0x65daca75da751065L, 0xd731b553315384d7L, 0x84c61351c651d584L, 0xd0b8bbd3b8d303d0L,
                0x82c31f5ec35edc82L, 0x29b052cbb0cbe229L, 0x5a77b4997799c35aL, 0x1e113c3311332d1eL, 0x7bcbf646cb463d7bL, 0xa8fc4b1ffc1fb7a8L, 0x6dd6da61d6610c6dL, 0x2c3a584e3a4e622cL,
                0xa597f4a5f432c6c6L, 0x84eb9784976ff8f8L, 0x99c7b099b05eeeeeL, 0x8df78c8d8c7af6f6L, 0x0de5170d17e8ffffL, 0xbdb7dcbddc0ad6d6L, 0xb1a7c8b1c816dedeL, 0x5439fc54fc6d9191L,
                0x50c0f050f0906060L, 0x0304050305070202L, 0xa987e0a9e02ececeL, 0x7dac877d87d15656L, 0x19d52b192bcce7e7L, 0x6271a662a613b5b5L, 0xe69a31e6317c4d4dL, 0x9ac3b59ab559ececL,
                0x4505cf45cf408f8fL, 0x9d3ebc9dbca31f1fL, 0x4009c040c0498989L, 0x87ef92879268fafaL, 0x15c53f153fd0efefL, 0xeb7f26eb2694b2b2L, 0xc90740c940ce8e8eL, 0x0bed1d0b1de6fbfbL,
                0xec822fec2f6e4141L, 0x677da967a91ab3b3L, 0xfdbe1cfd1c435f5fL, 0xea8a25ea25604545L, 0xbf46dabfdaf92323L, 0xf7a602f702515353L, 0x96d3a196a145e4e4L, 0x5b2ded5bed769b9bL,
                0xc2ea5dc25d287575L, 0x1cd9241c24c5e1e1L, 0xae7ae9aee9d43d3dL, 0x6a98be6abef24c4cL, 0x5ad8ee5aee826c6cL, 0x41fcc341c3bd7e7eL, 0x02f1060206f3f5f5L, 0x4f1dd14fd1528383L,
                0x5cd0e45ce48c6868L, 0xf4a207f407565151L, 0x34b95c345c8dd1d1L, 0x08e9180818e1f9f9L, 0x93dfae93ae4ce2e2L, 0x734d9573953eababL, 0x53c4f553f5976262L, 0x3f54413f416b2a2aL,
                0x0c10140c141c0808L, 0x5231f652f6639595L, 0x658caf65afe94646L, 0x5e21e25ee27f9d9dL, 0x2860782878483030L, 0xa16ef8a1f8cf3737L, 0x0f14110f111b0a0aL, 0xb55ec4b5c4eb2f2fL,
                0x091c1b091b150e0eL, 0x36485a365a7e2424L, 0x9b36b69bb6ad1b1bL, 0x3da5473d4798dfdfL, 0x26816a266aa7cdcdL, 0x699cbb69bbf54e4eL, 0xcdfe4ccd4c337f7fL, 0x9fcfba9fba50eaeaL,
                0x1b242d1b2d3f1212L, 0x9e3ab99eb9a41d1dL, 0x74b09c749cc45858L, 0x2e68722e72463434L, 0x2d6c772d77413636L, 0xb2a3cdb2cd11dcdcL, 0xee7329ee299db4b4L, 0xfbb616fb164d5b5bL,
                0xf65301f601a5a4a4L, 0x4decd74dd7a17676L, 0x6175a361a314b7b7L, 0xcefa49ce49347d7dL, 0x7ba48d7b8ddf5252L, 0x3ea1423e429fddddL, 0x71bc937193cd5e5eL, 0x9726a297a2b11313L,
                0xf55704f504a2a6a6L, 0x6869b868b801b9b9L, 0x0000000000000000L, 0x2c99742c74b5c1c1L, 0x6080a060a0e04040L, 0x1fdd211f21c2e3e3L, 0xc8f243c8433a7979L, 0xed772ced2c9ab6b6L,
                0xbeb3d9bed90dd4d4L, 0x4601ca46ca478d8dL, 0xd9ce70d970176767L, 0x4be4dd4bddaf7272L, 0xde3379de79ed9494L, 0xd42b67d467ff9898L, 0xe87b23e82393b0b0L, 0x4a11de4ade5b8585L,
                0x6b6dbd6bbd06bbbbL, 0x2a917e2a7ebbc5c5L, 0xe59e34e5347b4f4fL, 0x16c13a163ad7ededL, 0xc51754c554d28686L, 0xd72f62d762f89a9aL, 0x55ccff55ff996666L, 0x9422a794a7b61111L,
                0xcf0f4acf4ac08a8aL, 0x10c9301030d9e9e9L, 0x06080a060a0e0404L, 0x81e798819866fefeL, 0xf05b0bf00baba0a0L, 0x44f0cc44ccb47878L, 0xba4ad5bad5f02525L, 0xe3963ee33e754b4bL,
                0xf35f0ef30eaca2a2L, 0xfeba19fe19445d5dL, 0xc01b5bc05bdb8080L, 0x8a0a858a85800505L, 0xad7eecadecd33f3fL, 0xbc42dfbcdffe2121L, 0x48e0d848d8a87070L, 0x04f90c040cfdf1f1L,
                0xdfc67adf7a196363L, 0xc1ee58c1582f7777L, 0x75459f759f30afafL, 0x6384a563a5e74242L, 0x3040503050702020L, 0x1ad12e1a2ecbe5e5L, 0x0ee1120e12effdfdL, 0x6d65b76db708bfbfL,
                0x4c19d44cd4558181L, 0x14303c143c241818L, 0x354c5f355f792626L, 0x2f9d712f71b2c3c3L, 0xe16738e13886bebeL, 0xa26afda2fdc83535L, 0xcc0b4fcc4fc78888L, 0x395c4b394b652e2eL,
                0x573df957f96a9393L, 0xf2aa0df20d585555L, 0x82e39d829d61fcfcL, 0x47f4c947c9b37a7aL, 0xac8befacef27c8c8L, 0xe76f32e73288babaL, 0x2b647d2b7d4f3232L, 0x95d7a495a442e6e6L,
                0xa09bfba0fb3bc0c0L, 0x9832b398b3aa1919L, 0xd12768d168f69e9eL, 0x7f5d817f8122a3a3L, 0x6688aa66aaee4444L, 0x7ea8827e82d65454L, 0xab76e6abe6dd3b3bL, 0x83169e839e950b0bL,
                0xca0345ca45c98c8cL, 0x29957b297bbcc7c7L, 0xd3d66ed36e056b6bL, 0x3c50443c446c2828L, 0x79558b798b2ca7a7L, 0xe2633de23d81bcbcL, 0x1d2c271d27311616L, 0x76419a769a37adadL,
                0x3bad4d3b4d96dbdbL, 0x56c8fa56fa9e6464L, 0x4ee8d24ed2a67474L, 0x1e28221e22361414L, 0xdb3f76db76e49292L, 0x0a181e0a1e120c0cL, 0x6c90b46cb4fc4848L, 0xe46b37e4378fb8b8L,
                0x5d25e75de7789f9fL, 0x6e61b26eb20fbdbdL, 0xef862aef2a694343L, 0xa693f1a6f135c4c4L, 0xa872e3a8e3da3939L, 0xa462f7a4f7c63131L, 0x37bd5937598ad3d3L, 0x8bff868b8674f2f2L,
                0x32b156325683d5d5L, 0x430dc543c54e8b8bL, 0x59dceb59eb856e6eL, 0xb7afc2b7c218dadaL, 0x8c028f8c8f8e0101L, 0x6479ac64ac1db1b1L, 0xd2236dd26df19c9cL, 0xe0923be03b724949L,
                0xb4abc7b4c71fd8d8L, 0xfa4315fa15b9acacL, 0x07fd090709faf3f3L, 0x25856f256fa0cfcfL, 0xaf8feaafea20cacaL, 0x8ef3898e897df4f4L, 0xe98e20e920674747L, 0x1820281828381010L,
                0xd5de64d5640b6f6fL, 0x88fb83888373f0f0L, 0x6f94b16fb1fb4a4aL, 0x72b8967296ca5c5cL, 0x24706c246c543838L, 0xf1ae08f1085f5757L, 0xc7e652c752217373L, 0x5135f351f3649797L,
                0x238d652365aecbcbL, 0x7c59847c8425a1a1L, 0x9ccbbf9cbf57e8e8L, 0x217c6321635d3e3eL, 0xdd377cdd7cea9696L, 0xdcc27fdc7f1e6161L, 0x861a9186919c0d0dL, 0x851e9485949b0f0fL,
                0x90dbab90ab4be0e0L, 0x42f8c642c6ba7c7cL, 0xc4e257c457267171L, 0xaa83e5aae529ccccL, 0xd83b73d873e39090L, 0x050c0f050f090606L, 0x01f5030103f4f7f7L, 0x12383612362a1c1cL,
                0xa39ffea3fe3cc2c2L, 0x5fd4e15fe18b6a6aL, 0xf94710f910beaeaeL, 0xd0d26bd06b026969L, 0x912ea891a8bf1717L, 0x5829e858e8719999L, 0x2774692769533a3aL, 0xb94ed0b9d0f72727L,
                0x38a948384891d9d9L, 0x13cd351335deebebL, 0xb356ceb3cee52b2bL, 0x3344553355772222L, 0xbbbfd6bbd604d2d2L, 0x704990709039a9a9L, 0x890e808980870707L, 0xa766f2a7f2c13333L,
                0xb65ac1b6c1ec2d2dL, 0x22786622665a3c3cL, 0x922aad92adb81515L, 0x2089602060a9c9c9L, 0x4915db49db5c8787L, 0xff4f1aff1ab0aaaaL, 0x78a0887888d85050L, 0x7a518e7a8e2ba5a5L,
                0x8f068a8f8a890303L, 0xf8b213f8134a5959L, 0x80129b809b920909L, 0x1734391739231a1aL, 0xdaca75da75106565L, 0x31b553315384d7d7L, 0xc61351c651d58484L, 0xb8bbd3b8d303d0d0L,
                0xc31f5ec35edc8282L, 0xb052cbb0cbe22929L, 0x77b4997799c35a5aL, 0x113c3311332d1e1eL, 0xcbf646cb463d7b7bL, 0xfc4b1ffc1fb7a8a8L, 0xd6da61d6610c6d6dL, 0x3a584e3a4e622c2cL,
                0x97f4a5f432c6c6a5L, 0xeb9784976ff8f884L, 0xc7b099b05eeeee99L, 0xf78c8d8c7af6f68dL, 0xe5170d17e8ffff0dL, 0xb7dcbddc0ad6d6bdL, 0xa7c8b1c816dedeb1L, 0x39fc54fc6d919154L,
                0xc0f050f090606050L, 0x0405030507020203L, 0x87e0a9e02ececea9L, 0xac877d87d156567dL, 0xd52b192bcce7e719L, 0x71a662a613b5b562L, 0x9a31e6317c4d4de6L, 0xc3b59ab559ecec9aL,
                0x05cf45cf408f8f45L, 0x3ebc9dbca31f1f9dL, 0x09c040c049898940L, 0xef92879268fafa87L, 0xc53f153fd0efef15L, 0x7f26eb2694b2b2ebL, 0x0740c940ce8e8ec9L, 0xed1d0b1de6fbfb0bL,
                0x822fec2f6e4141ecL, 0x7da967a91ab3b367L, 0xbe1cfd1c435f5ffdL, 0x8a25ea25604545eaL, 0x46dabfdaf92323bfL, 0xa602f702515353f7L, 0xd3a196a145e4e496L, 0x2ded5bed769b9b5bL,
                0xea5dc25d287575c2L, 0xd9241c24c5e1e11cL, 0x7ae9aee9d43d3daeL, 0x98be6abef24c4c6aL, 0xd8ee5aee826c6c5aL, 0xfcc341c3bd7e7e41L, 0xf1060206f3f5f502L, 0x1dd14fd15283834fL,
                0xd0e45ce48c68685cL, 0xa207f407565151f4L, 0xb95c345c8dd1d134L, 0xe9180818e1f9f908L, 0xdfae93ae4ce2e293L, 0x4d9573953eabab73L, 0xc4f553f597626253L, 0x54413f416b2a2a3fL,
                0x10140c141c08080cL, 0x31f652f663959552L, 0x8caf65afe9464665L, 0x21e25ee27f9d9d5eL, 0x6078287848303028L, 0x6ef8a1f8cf3737a1L, 0x14110f111b0a0a0fL, 0x5ec4b5c4eb2f2fb5L,
                0x1c1b091b150e0e09L, 0x485a365a7e242436L, 0x36b69bb6ad1b1b9bL, 0xa5473d4798dfdf3dL, 0x816a266aa7cdcd26L, 0x9cbb69bbf54e4e69L, 0xfe4ccd4c337f7fcdL, 0xcfba9fba50eaea9fL,
                0x242d1b2d3f12121bL, 0x3ab99eb9a41d1d9eL, 0xb09c749cc4585874L, 0x68722e724634342eL, 0x6c772d774136362dL, 0xa3cdb2cd11dcdcb2L, 0x7329ee299db4b4eeL, 0xb616fb164d5b5bfbL,
                0x5301f601a5a4a4f6L, 0xecd74dd7a176764dL, 0x75a361a314b7b761L, 0xfa49ce49347d7dceL, 0xa48d7b8ddf52527bL, 0xa1423e429fdddd3eL, 0xbc937193cd5e5e71L, 0x26a297a2b1131397L,
                0x5704f504a2a6a6f5L, 0x69b868b801b9b968L, 0x0000000000000000L, 0x99742c74b5c1c12cL, 0x80a060a0e0404060L, 0xdd211f21c2e3e31fL, 0xf243c8433a7979c8L, 0x772ced2c9ab6b6edL,
                0xb3d9bed90dd4d4beL, 0x01ca46ca478d8d46L, 0xce70d970176767d9L, 0xe4dd4bddaf72724bL, 0x3379de79ed9494deL, 0x2b67d467ff9898d4L, 0x7b23e82393b0b0e8L, 0x11de4ade5b85854aL,
                0x6dbd6bbd06bbbb6bL, 0x917e2a7ebbc5c52aL, 0x9e34e5347b4f4fe5L, 0xc13a163ad7eded16L, 0x1754c554d28686c5L, 0x2f62d762f89a9ad7L, 0xccff55ff99666655L, 0x22a794a7b6111194L,
                0x0f4acf4ac08a8acfL, 0xc9301030d9e9e910L, 0x080a060a0e040406L, 0xe798819866fefe81L, 0x5b0bf00baba0a0f0L, 0xf0cc44ccb4787844L, 0x4ad5bad5f02525baL, 0x963ee33e754b4be3L,
                0x5f0ef30eaca2a2f3L, 0xba19fe19445d5dfeL, 0x1b5bc05bdb8080c0L, 0x0a858a858005058aL, 0x7eecadecd33f3fadL, 0x42dfbcdffe2121bcL, 0xe0d848d8a8707048L, 0xf90c040cfdf1f104L,
                0xc67adf7a196363dfL, 0xee58c1582f7777c1L, 0x459f759f30afaf75L, 0x84a563a5e7424263L, 0x4050305070202030L, 0xd12e1a2ecbe5e51aL, 0xe1120e12effdfd0eL, 0x65b76db708bfbf6dL,
                0x19d44cd45581814cL, 0x303c143c24181814L, 0x4c5f355f79262635L, 0x9d712f71b2c3c32fL, 0x6738e13886bebee1L, 0x6afda2fdc83535a2L, 0x0b4fcc4fc78888ccL, 0x5c4b394b652e2e39L,
                0x3df957f96a939357L, 0xaa0df20d585555f2L, 0xe39d829d61fcfc82L, 0xf4c947c9b37a7a47L, 0x8befacef27c8c8acL, 0x6f32e73288babae7L, 0x647d2b7d4f32322bL, 0xd7a495a442e6e695L,
                0x9bfba0fb3bc0c0a0L, 0x32b398b3aa191998L, 0x2768d168f69e9ed1L, 0x5d817f8122a3a37fL, 0x88aa66aaee444466L, 0xa8827e82d654547eL, 0x76e6abe6dd3b3babL, 0x169e839e950b0b83L,
                0x0345ca45c98c8ccaL, 0x957b297bbcc7c729L, 0xd66ed36e056b6bd3L, 0x50443c446c28283cL, 0x558b798b2ca7a779L, 0x633de23d81bcbce2L, 0x2c271d273116161dL, 0x419a769a37adad76L,
                0xad4d3b4d96dbdb3bL, 0xc8fa56fa9e646456L, 0xe8d24ed2a674744eL, 0x28221e223614141eL, 0x3f76db76e49292dbL, 0x181e0a1e120c0c0aL, 0x90b46cb4fc48486cL, 0x6b37e4378fb8b8e4L,
                0x25e75de7789f9f5dL, 0x61b26eb20fbdbd6eL, 0x862aef2a694343efL, 0x93f1a6f135c4c4a6L, 0x72e3a8e3da3939a8L, 0x62f7a4f7c63131a4L, 0xbd5937598ad3d337L, 0xff868b8674f2f28bL,
                0xb156325683d5d532L, 0x0dc543c54e8b8b43L, 0xdceb59eb856e6e59L, 0xafc2b7c218dadab7L, 0x028f8c8f8e01018cL, 0x79ac64ac1db1b164L, 0x236dd26df19c9cd2L, 0x923be03b724949e0L,
                0xabc7b4c71fd8d8b4L, 0x4315fa15b9acacfaL, 0xfd090709faf3f307L, 0x856f256fa0cfcf25L, 0x8feaafea20cacaafL, 0xf3898e897df4f48eL, 0x8e20e920674747e9L, 0x2028182838101018L,
                0xde64d5640b6f6fd5L, 0xfb83888373f0f088L, 0x94b16fb1fb4a4a6fL, 0xb8967296ca5c5c72L, 0x706c246c54383824L, 0xae08f1085f5757f1L, 0xe652c752217373c7L, 0x35f351f364979751L,
                0x8d652365aecbcb23L, 0x59847c8425a1a17cL, 0xcbbf9cbf57e8e89cL, 0x7c6321635d3e3e21L, 0x377cdd7cea9696ddL, 0xc27fdc7f1e6161dcL, 0x1a9186919c0d0d86L, 0x1e9485949b0f0f85L,
                0xdbab90ab4be0e090L, 0xf8c642c6ba7c7c42L, 0xe257c457267171c4L, 0x83e5aae529ccccaaL, 0x3b73d873e39090d8L, 0x0c0f050f09060605L, 0xf5030103f4f7f701L, 0x383612362a1c1c12L,
                0x9ffea3fe3cc2c2a3L, 0xd4e15fe18b6a6a5fL, 0x4710f910beaeaef9L, 0xd26bd06b026969d0L, 0x2ea891a8bf171791L, 0x29e858e871999958L, 0x74692769533a3a27L, 0x4ed0b9d0f72727b9L,
                0xa948384891d9d938L, 0xcd351335deebeb13L, 0x56ceb3cee52b2bb3L, 0x4455335577222233L, 0xbfd6bbd604d2d2bbL, 0x4990709039a9a970L, 0x0e80898087070789L, 0x66f2a7f2c13333a7L,
                0x5ac1b6c1ec2d2db6L, 0x786622665a3c3c22L, 0x2aad92adb8151592L, 0x89602060a9c9c920L, 0x15db49db5c878749L, 0x4f1aff1ab0aaaaffL, 0xa0887888d8505078L, 0x518e7a8e2ba5a57aL,
                0x068a8f8a8903038fL, 0xb213f8134a5959f8L, 0x129b809b92090980L, 0x34391739231a1a17L, 0xca75da75106565daL, 0xb553315384d7d731L, 0x1351c651d58484c6L, 0xbbd3b8d303d0d0b8L,
                0x1f5ec35edc8282c3L, 0x52cbb0cbe22929b0L, 0xb4997799c35a5a77L, 0x3c3311332d1e1e11L, 0xf646cb463d7b7bcbL, 0x4b1ffc1fb7a8a8fcL, 0xda61d6610c6d6dd6L, 0x584e3a4e622c2c3aL,
                0xf4a5f432c6c6a597L, 0x9784976ff8f884ebL, 0xb099b05eeeee99c7L, 0x8c8d8c7af6f68df7L, 0x170d17e8ffff0de5L, 0xdcbddc0ad6d6bdb7L, 0xc8b1c816dedeb1a7L, 0xfc54fc6d91915439L,
                0xf050f090606050c0L, 0x0503050702020304L, 0xe0a9e02ececea987L, 0x877d87d156567dacL, 0x2b192bcce7e719d5L, 0xa662a613b5b56271L, 0x31e6317c4d4de69aL, 0xb59ab559ecec9ac3L,
                0xcf45cf408f8f4505L, 0xbc9dbca31f1f9d3eL, 0xc040c04989894009L, 0x92879268fafa87efL, 0x3f153fd0efef15c5L, 0x26eb2694b2b2eb7fL, 0x40c940ce8e8ec907L, 0x1d0b1de6fbfb0bedL,
                0x2fec2f6e4141ec82L, 0xa967a91ab3b3677dL, 0x1cfd1c435f5ffdbeL, 0x25ea25604545ea8aL, 0xdabfdaf92323bf46L, 0x02f702515353f7a6L, 0xa196a145e4e496d3L, 0xed5bed769b9b5b2dL,
                0x5dc25d287575c2eaL, 0x241c24c5e1e11cd9L, 0xe9aee9d43d3dae7aL, 0xbe6abef24c4c6a98L, 0xee5aee826c6c5ad8L, 0xc341c3bd7e7e41fcL, 0x060206f3f5f502f1L, 0xd14fd15283834f1dL,
                0xe45ce48c68685cd0L, 0x07f407565151f4a2L, 0x5c345c8dd1d134b9L, 0x180818e1f9f908e9L, 0xae93ae4ce2e293dfL, 0x9573953eabab734dL, 0xf553f597626253c4L, 0x413f416b2a2a3f54L,
                0x140c141c08080c10L, 0xf652f66395955231L, 0xaf65afe94646658cL, 0xe25ee27f9d9d5e21L, 0x7828784830302860L, 0xf8a1f8cf3737a16eL, 0x110f111b0a0a0f14L, 0xc4b5c4eb2f2fb55eL,
                0x1b091b150e0e091cL, 0x5a365a7e24243648L, 0xb69bb6ad1b1b9b36L, 0x473d4798dfdf3da5L, 0x6a266aa7cdcd2681L, 0xbb69bbf54e4e699cL, 0x4ccd4c337f7fcdfeL, 0xba9fba50eaea9fcfL,
                0x2d1b2d3f12121b24L, 0xb99eb9a41d1d9e3aL, 0x9c749cc4585874b0L, 0x722e724634342e68L, 0x772d774136362d6cL, 0xcdb2cd11dcdcb2a3L, 0x29ee299db4b4ee73L, 0x16fb164d5b5bfbb6L,
                0x01f601a5a4a4f653L, 0xd74dd7a176764decL, 0xa361a314b7b76175L, 0x49ce49347d7dcefaL, 0x8d7b8ddf52527ba4L, 0x423e429fdddd3ea1L, 0x937193cd5e5e71bcL, 0xa297a2b113139726L,
                0x04f504a2a6a6f557L, 0xb868b801b9b96869L, 0x0000000000000000L, 0x742c74b5c1c12c99L, 0xa060a0e040406080L, 0x211f21c2e3e31fddL, 0x43c8433a7979c8f2L, 0x2ced2c9ab6b6ed77L,
                0xd9bed90dd4d4beb3L, 0xca46ca478d8d4601L, 0x70d970176767d9ceL, 0xdd4bddaf72724be4L, 0x79de79ed9494de33L, 0x67d467ff9898d42bL, 0x23e82393b0b0e87bL, 0xde4ade5b85854a11L,
                0xbd6bbd06bbbb6b6dL, 0x7e2a7ebbc5c52a91L, 0x34e5347b4f4fe59eL, 0x3a163ad7eded16c1L, 0x54c554d28686c517L, 0x62d762f89a9ad72fL, 0xff55ff99666655ccL, 0xa794a7b611119422L,
                0x4acf4ac08a8acf0fL, 0x301030d9e9e910c9L, 0x0a060a0e04040608L, 0x98819866fefe81e7L, 0x0bf00baba0a0f05bL, 0xcc44ccb4787844f0L, 0xd5bad5f02525ba4aL, 0x3ee33e754b4be396L,
                0x0ef30eaca2a2f35fL, 0x19fe19445d5dfebaL, 0x5bc05bdb8080c01bL, 0x858a858005058a0aL, 0xecadecd33f3fad7eL, 0xdfbcdffe2121bc42L, 0xd848d8a8707048e0L, 0x0c040cfdf1f104f9L,
                0x7adf7a196363dfc6L, 0x58c1582f7777c1eeL, 0x9f759f30afaf7545L, 0xa563a5e742426384L, 0x5030507020203040L, 0x2e1a2ecbe5e51ad1L, 0x120e12effdfd0ee1L, 0xb76db708bfbf6d65L,
                0xd44cd45581814c19L, 0x3c143c2418181430L, 0x5f355f792626354cL, 0x712f71b2c3c32f9dL, 0x38e13886bebee167L, 0xfda2fdc83535a26aL, 0x4fcc4fc78888cc0bL, 0x4b394b652e2e395cL,
                0xf957f96a9393573dL, 0x0df20d585555f2aaL, 0x9d829d61fcfc82e3L, 0xc947c9b37a7a47f4L, 0xefacef27c8c8ac8bL, 0x32e73288babae76fL, 0x7d2b7d4f32322b64L, 0xa495a442e6e695d7L,
                0xfba0fb3bc0c0a09bL, 0xb398b3aa19199832L, 0x68d168f69e9ed127L, 0x817f8122a3a37f5dL, 0xaa66aaee44446688L, 0x827e82d654547ea8L, 0xe6abe6dd3b3bab76L, 0x9e839e950b0b8316L,
                0x45ca45c98c8cca03L, 0x7b297bbcc7c72995L, 0x6ed36e056b6bd3d6L, 0x443c446c28283c50L, 0x8b798b2ca7a77955L, 0x3de23d81bcbce263L, 0x271d273116161d2cL, 0x9a769a37adad7641L,
                0x4d3b4d96dbdb3badL, 0xfa56fa9e646456c8L, 0xd24ed2a674744ee8L, 0x221e223614141e28L, 0x76db76e49292db3fL, 0x1e0a1e120c0c0a18L, 0xb46cb4fc48486c90L, 0x37e4378fb8b8e46bL,
                0xe75de7789f9f5d25L, 0xb26eb20fbdbd6e61L, 0x2aef2a694343ef86L, 0xf1a6f135c4c4a693L, 0xe3a8e3da3939a872L, 0xf7a4f7c63131a462L, 0x5937598ad3d337bdL, 0x868b8674f2f28bffL,
                0x56325683d5d532b1L, 0xc543c54e8b8b430dL, 0xeb59eb856e6e59dcL, 0xc2b7c218dadab7afL, 0x8f8c8f8e01018c02L, 0xac64ac1db1b16479L, 0x6dd26df19c9cd223L, 0x3be03b724949e092L,
                0xc7b4c71fd8d8b4abL, 0x15fa15b9acacfa43L, 0x090709faf3f307fdL, 0x6f256fa0cfcf2585L, 0xeaafea20cacaaf8fL, 0x898e897df4f48ef3L, 0x20e920674747e98eL, 0x2818283810101820L,
                0x64d5640b6f6fd5deL, 0x83888373f0f088fbL, 0xb16fb1fb4a4a6f94L, 0x967296ca5c5c72b8L, 0x6c246c5438382470L, 0x08f1085f5757f1aeL, 0x52c752217373c7e6L, 0xf351f36497975135L,
                0x652365aecbcb238dL, 0x847c8425a1a17c59L, 0xbf9cbf57e8e89ccbL, 0x6321635d3e3e217cL, 0x7cdd7cea9696dd37L, 0x7fdc7f1e6161dcc2L, 0x9186919c0d0d861aL, 0x9485949b0f0f851eL,
                0xab90ab4be0e090dbL, 0xc642c6ba7c7c42f8L, 0x57c457267171c4e2L, 0xe5aae529ccccaa83L, 0x73d873e39090d83bL, 0x0f050f090606050cL, 0x030103f4f7f701f5L, 0x3612362a1c1c1238L,
                0xfea3fe3cc2c2a39fL, 0xe15fe18b6a6a5fd4L, 0x10f910beaeaef947L, 0x6bd06b026969d0d2L, 0xa891a8bf1717912eL, 0xe858e87199995829L, 0x692769533a3a2774L, 0xd0b9d0f72727b94eL,
                0x48384891d9d938a9L, 0x351335deebeb13cdL, 0xceb3cee52b2bb356L, 0x5533557722223344L, 0xd6bbd604d2d2bbbfL, 0x90709039a9a97049L, 0x808980870707890eL, 0xf2a7f2c13333a766L,
                0xc1b6c1ec2d2db65aL, 0x6622665a3c3c2278L, 0xad92adb81515922aL, 0x602060a9c9c92089L, 0xdb49db5c87874915L, 0x1aff1ab0aaaaff4fL, 0x887888d8505078a0L, 0x8e7a8e2ba5a57a51L,
                0x8a8f8a8903038f06L, 0x13f8134a5959f8b2L, 0x9b809b9209098012L, 0x391739231a1a1734L, 0x75da75106565dacaL, 0x53315384d7d731b5L, 0x51c651d58484c613L, 0xd3b8d303d0d0b8bbL,
                0x5ec35edc8282c31fL, 0xcbb0cbe22929b052L, 0x997799c35a5a77b4L, 0x3311332d1e1e113cL, 0x46cb463d7b7bcbf6L, 0x1ffc1fb7a8a8fc4bL, 0x61d6610c6d6dd6daL, 0x4e3a4e622c2c3a58L,
                0xa5f432c6c6a597f4L, 0x84976ff8f884eb97L, 0x99b05eeeee99c7b0L, 0x8d8c7af6f68df78cL, 0x0d17e8ffff0de517L, 0xbddc0ad6d6bdb7dcL, 0xb1c816dedeb1a7c8L, 0x54fc6d91915439fcL,
                0x50f090606050c0f0L, 0x0305070202030405L, 0xa9e02ececea987e0L, 0x7d87d156567dac87L, 0x192bcce7e719d52bL, 0x62a613b5b56271a6L, 0xe6317c4d4de69a31L, 0x9ab559ecec9ac3b5L,
                0x45cf408f8f4505cfL, 0x9dbca31f1f9d3ebcL, 0x40c04989894009c0L, 0x879268fafa87ef92L, 0x153fd0efef15c53fL, 0xeb2694b2b2eb7f26L, 0xc940ce8e8ec90740L, 0x0b1de6fbfb0bed1dL,
                0xec2f6e4141ec822fL, 0x67a91ab3b3677da9L, 0xfd1c435f5ffdbe1cL, 0xea25604545ea8a25L, 0xbfdaf92323bf46daL, 0xf702515353f7a602L, 0x96a145e4e496d3a1L, 0x5bed769b9b5b2dedL,
                0xc25d287575c2ea5dL, 0x1c24c5e1e11cd924L, 0xaee9d43d3dae7ae9L, 0x6abef24c4c6a98beL, 0x5aee826c6c5ad8eeL, 0x41c3bd7e7e41fcc3L, 0x0206f3f5f502f106L, 0x4fd15283834f1dd1L,
                0x5ce48c68685cd0e4L, 0xf407565151f4a207L, 0x345c8dd1d134b95cL, 0x0818e1f9f908e918L, 0x93ae4ce2e293dfaeL, 0x73953eabab734d95L, 0x53f597626253c4f5L, 0x3f416b2a2a3f5441L,
                0x0c141c08080c1014L, 0x52f66395955231f6L, 0x65afe94646658cafL, 0x5ee27f9d9d5e21e2L, 0x2878483030286078L, 0xa1f8cf3737a16ef8L, 0x0f111b0a0a0f1411L, 0xb5c4eb2f2fb55ec4L,
                0x091b150e0e091c1bL, 0x365a7e242436485aL, 0x9bb6ad1b1b9b36b6L, 0x3d4798dfdf3da547L, 0x266aa7cdcd26816aL, 0x69bbf54e4e699cbbL, 0xcd4c337f7fcdfe4cL, 0x9fba50eaea9fcfbaL,
                0x1b2d3f12121b242dL, 0x9eb9a41d1d9e3ab9L, 0x749cc4585874b09cL, 0x2e724634342e6872L, 0x2d774136362d6c77L, 0xb2cd11dcdcb2a3cdL, 0xee299db4b4ee7329L, 0xfb164d5b5bfbb616L,
                0xf601a5a4a4f65301L, 0x4dd7a176764decd7L, 0x61a314b7b76175a3L, 0xce49347d7dcefa49L, 0x7b8ddf52527ba48dL, 0x3e429fdddd3ea142L, 0x7193cd5e5e71bc93L, 0x97a2b113139726a2L,
                0xf504a2a6a6f55704L, 0x68b801b9b96869b8L, 0x0000000000000000L, 0x2c74b5c1c12c9974L, 0x60a0e040406080a0L, 0x1f21c2e3e31fdd21L, 0xc8433a7979c8f243L, 0xed2c9ab6b6ed772cL,
                0xbed90dd4d4beb3d9L, 0x46ca478d8d4601caL, 0xd970176767d9ce70L, 0x4bddaf72724be4ddL, 0xde79ed9494de3379L, 0xd467ff9898d42b67L, 0xe82393b0b0e87b23L, 0x4ade5b85854a11deL,
                0x6bbd06bbbb6b6dbdL, 0x2a7ebbc5c52a917eL, 0xe5347b4f4fe59e34L, 0x163ad7eded16c13aL, 0xc554d28686c51754L, 0xd762f89a9ad72f62L, 0x55ff99666655ccffL, 0x94a7b611119422a7L,
                0xcf4ac08a8acf0f4aL, 0x1030d9e9e910c930L, 0x060a0e040406080aL, 0x819866fefe81e798L, 0xf00baba0a0f05b0bL, 0x44ccb4787844f0ccL, 0xbad5f02525ba4ad5L, 0xe33e754b4be3963eL,
                0xf30eaca2a2f35f0eL, 0xfe19445d5dfeba19L, 0xc05bdb8080c01b5bL, 0x8a858005058a0a85L, 0xadecd33f3fad7eecL, 0xbcdffe2121bc42dfL, 0x48d8a8707048e0d8L, 0x040cfdf1f104f90cL,
                0xdf7a196363dfc67aL, 0xc1582f7777c1ee58L, 0x759f30afaf75459fL, 0x63a5e742426384a5L, 0x3050702020304050L, 0x1a2ecbe5e51ad12eL, 0x0e12effdfd0ee112L, 0x6db708bfbf6d65b7L,
                0x4cd45581814c19d4L, 0x143c24181814303cL, 0x355f792626354c5fL, 0x2f71b2c3c32f9d71L, 0xe13886bebee16738L, 0xa2fdc83535a26afdL, 0xcc4fc78888cc0b4fL, 0x394b652e2e395c4bL,
                0x57f96a9393573df9L, 0xf20d585555f2aa0dL, 0x829d61fcfc82e39dL, 0x47c9b37a7a47f4c9L, 0xacef27c8c8ac8befL, 0xe73288babae76f32L, 0x2b7d4f32322b647dL, 0x95a442e6e695d7a4L,
                0xa0fb3bc0c0a09bfbL, 0x98b3aa19199832b3L, 0xd168f69e9ed12768L, 0x7f8122a3a37f5d81L, 0x66aaee44446688aaL, 0x7e82d654547ea882L, 0xabe6dd3b3bab76e6L, 0x839e950b0b83169eL,
                0xca45c98c8cca0345L, 0x297bbcc7c729957bL, 0xd36e056b6bd3d66eL, 0x3c446c28283c5044L, 0x798b2ca7a779558bL, 0xe23d81bcbce2633dL, 0x1d273116161d2c27L, 0x769a37adad76419aL,
                0x3b4d96dbdb3bad4dL, 0x56fa9e646456c8faL, 0x4ed2a674744ee8d2L, 0x1e223614141e2822L, 0xdb76e49292db3f76L, 0x0a1e120c0c0a181eL, 0x6cb4fc48486c90b4L, 0xe4378fb8b8e46b37L,
                0x5de7789f9f5d25e7L, 0x6eb20fbdbd6e61b2L, 0xef2a694343ef862aL, 0xa6f135c4c4a693f1L, 0xa8e3da3939a872e3L, 0xa4f7c63131a462f7L, 0x37598ad3d337bd59L, 0x8b8674f2f28bff86L,
                0x325683d5d532b156L, 0x43c54e8b8b430dc5L, 0x59eb856e6e59dcebL, 0xb7c218dadab7afc2L, 0x8c8f8e01018c028fL, 0x64ac1db1b16479acL, 0xd26df19c9cd2236dL, 0xe03b724949e0923bL,
                0xb4c71fd8d8b4abc7L, 0xfa15b9acacfa4315L, 0x0709faf3f307fd09L, 0x256fa0cfcf25856fL, 0xafea20cacaaf8feaL, 0x8e897df4f48ef389L, 0xe920674747e98e20L, 0x1828381010182028L,
                0xd5640b6f6fd5de64L, 0x888373f0f088fb83L, 0x6fb1fb4a4a6f94b1L, 0x7296ca5c5c72b896L, 0x246c54383824706cL, 0xf1085f5757f1ae08L, 0xc752217373c7e652L, 0x51f36497975135f3L,
                0x2365aecbcb238d65L, 0x7c8425a1a17c5984L, 0x9cbf57e8e89ccbbfL, 0x21635d3e3e217c63L, 0xdd7cea9696dd377cL, 0xdc7f1e6161dcc27fL, 0x86919c0d0d861a91L, 0x85949b0f0f851e94L,
                0x90ab4be0e090dbabL, 0x42c6ba7c7c42f8c6L, 0xc457267171c4e257L, 0xaae529ccccaa83e5L, 0xd873e39090d83b73L, 0x050f090606050c0fL, 0x0103f4f7f701f503L, 0x12362a1c1c123836L,
                0xa3fe3cc2c2a39ffeL, 0x5fe18b6a6a5fd4e1L, 0xf910beaeaef94710L, 0xd06b026969d0d26bL, 0x91a8bf1717912ea8L, 0x58e87199995829e8L, 0x2769533a3a277469L, 0xb9d0f72727b94ed0L,
                0x384891d9d938a948L, 0x1335deebeb13cd35L, 0xb3cee52b2bb356ceL, 0x3355772222334455L, 0xbbd604d2d2bbbfd6L, 0x709039a9a9704990L, 0x8980870707890e80L, 0xa7f2c13333a766f2L,
                0xb6c1ec2d2db65ac1L, 0x22665a3c3c227866L, 0x92adb81515922aadL, 0x2060a9c9c9208960L, 0x49db5c87874915dbL, 0xff1ab0aaaaff4f1aL, 0x7888d8505078a088L, 0x7a8e2ba5a57a518eL,
                0x8f8a8903038f068aL, 0xf8134a5959f8b213L, 0x809b92090980129bL, 0x1739231a1a173439L, 0xda75106565daca75L, 0x315384d7d731b553L, 0xc651d58484c61351L, 0xb8d303d0d0b8bbd3L,
                0xc35edc8282c31f5eL, 0xb0cbe22929b052cbL, 0x7799c35a5a77b499L, 0x11332d1e1e113c33L, 0xcb463d7b7bcbf646L, 0xfc1fb7a8a8fc4b1fL, 0xd6610c6d6dd6da61L, 0x3a4e622c2c3a584eL,
                0xf432c6c6a597f4a5L, 0x976ff8f884eb9784L, 0xb05eeeee99c7b099L, 0x8c7af6f68df78c8dL, 0x17e8ffff0de5170dL, 0xdc0ad6d6bdb7dcbdL, 0xc816dedeb1a7c8b1L, 0xfc6d91915439fc54L,
                0xf090606050c0f050L, 0x0507020203040503L, 0xe02ececea987e0a9L, 0x87d156567dac877dL, 0x2bcce7e719d52b19L, 0xa613b5b56271a662L, 0x317c4d4de69a31e6L, 0xb559ecec9ac3b59aL,
                0xcf408f8f4505cf45L, 0xbca31f1f9d3ebc9dL, 0xc04989894009c040L, 0x9268fafa87ef9287L, 0x3fd0efef15c53f15L, 0x2694b2b2eb7f26ebL, 0x40ce8e8ec90740c9L, 0x1de6fbfb0bed1d0bL,
                0x2f6e4141ec822fecL, 0xa91ab3b3677da967L, 0x1c435f5ffdbe1cfdL, 0x25604545ea8a25eaL, 0xdaf92323bf46dabfL, 0x02515353f7a602f7L, 0xa145e4e496d3a196L, 0xed769b9b5b2ded5bL,
                0x5d287575c2ea5dc2L, 0x24c5e1e11cd9241cL, 0xe9d43d3dae7ae9aeL, 0xbef24c4c6a98be6aL, 0xee826c6c5ad8ee5aL, 0xc3bd7e7e41fcc341L, 0x06f3f5f502f10602L, 0xd15283834f1dd14fL,
                0xe48c68685cd0e45cL, 0x07565151f4a207f4L, 0x5c8dd1d134b95c34L, 0x18e1f9f908e91808L, 0xae4ce2e293dfae93L, 0x953eabab734d9573L, 0xf597626253c4f553L, 0x416b2a2a3f54413fL,
                0x141c08080c10140cL, 0xf66395955231f652L, 0xafe94646658caf65L, 0xe27f9d9d5e21e25eL, 0x7848303028607828L, 0xf8cf3737a16ef8a1L, 0x111b0a0a0f14110fL, 0xc4eb2f2fb55ec4b5L,
                0x1b150e0e091c1b09L, 0x5a7e242436485a36L, 0xb6ad1b1b9b36b69bL, 0x4798dfdf3da5473dL, 0x6aa7cdcd26816a26L, 0xbbf54e4e699cbb69L, 0x4c337f7fcdfe4ccdL, 0xba50eaea9fcfba9fL,
                0x2d3f12121b242d1bL, 0xb9a41d1d9e3ab99eL, 0x9cc4585874b09c74L, 0x724634342e68722eL, 0x774136362d6c772dL, 0xcd11dcdcb2a3cdb2L, 0x299db4b4ee7329eeL, 0x164d5b5bfbb616fbL,
                0x01a5a4a4f65301f6L, 0xd7a176764decd74dL, 0xa314b7b76175a361L, 0x49347d7dcefa49ceL, 0x8ddf52527ba48d7bL, 0x429fdddd3ea1423eL, 0x93cd5e5e71bc9371L, 0xa2b113139726a297L,
                0x04a2a6a6f55704f5L, 0xb801b9b96869b868L, 0x0000000000000000L, 0x74b5c1c12c99742cL, 0xa0e040406080a060L, 0x21c2e3e31fdd211fL, 0x433a7979c8f243c8L, 0x2c9ab6b6ed772cedL,
                0xd90dd4d4beb3d9beL, 0xca478d8d4601ca46L, 0x70176767d9ce70d9L, 0xddaf72724be4dd4bL, 0x79ed9494de3379deL, 0x67ff9898d42b67d4L, 0x2393b0b0e87b23e8L, 0xde5b85854a11de4aL,
                0xbd06bbbb6b6dbd6bL, 0x7ebbc5c52a917e2aL, 0x347b4f4fe59e34e5L, 0x3ad7eded16c13a16L, 0x54d28686c51754c5L, 0x62f89a9ad72f62d7L, 0xff99666655ccff55L, 0xa7b611119422a794L,
                0x4ac08a8acf0f4acfL, 0x30d9e9e910c93010L, 0x0a0e040406080a06L, 0x9866fefe81e79881L, 0x0baba0a0f05b0bf0L, 0xccb4787844f0cc44L, 0xd5f02525ba4ad5baL, 0x3e754b4be3963ee3L,
                0x0eaca2a2f35f0ef3L, 0x19445d5dfeba19feL, 0x5bdb8080c01b5bc0L, 0x858005058a0a858aL, 0xecd33f3fad7eecadL, 0xdffe2121bc42dfbcL, 0xd8a8707048e0d848L, 0x0cfdf1f104f90c04L,
                0x7a196363dfc67adfL, 0x582f7777c1ee58c1L, 0x9f30afaf75459f75L, 0xa5e742426384a563L, 0x5070202030405030L, 0x2ecbe5e51ad12e1aL, 0x12effdfd0ee1120eL, 0xb708bfbf6d65b76dL,
                0xd45581814c19d44cL, 0x3c24181814303c14L, 0x5f792626354c5f35L, 0x71b2c3c32f9d712fL, 0x3886bebee16738e1L, 0xfdc83535a26afda2L, 0x4fc78888cc0b4fccL, 0x4b652e2e395c4b39L,
                0xf96a9393573df957L, 0x0d585555f2aa0df2L, 0x9d61fcfc82e39d82L, 0xc9b37a7a47f4c947L, 0xef27c8c8ac8befacL, 0x3288babae76f32e7L, 0x7d4f32322b647d2bL, 0xa442e6e695d7a495L,
                0xfb3bc0c0a09bfba0L, 0xb3aa19199832b398L, 0x68f69e9ed12768d1L, 0x8122a3a37f5d817fL, 0xaaee44446688aa66L, 0x82d654547ea8827eL, 0xe6dd3b3bab76e6abL, 0x9e950b0b83169e83L,
                0x45c98c8cca0345caL, 0x7bbcc7c729957b29L, 0x6e056b6bd3d66ed3L, 0x446c28283c50443cL, 0x8b2ca7a779558b79L, 0x3d81bcbce2633de2L, 0x273116161d2c271dL, 0x9a37adad76419a76L,
                0x4d96dbdb3bad4d3bL, 0xfa9e646456c8fa56L, 0xd2a674744ee8d24eL, 0x223614141e28221eL, 0x76e49292db3f76dbL, 0x1e120c0c0a181e0aL, 0xb4fc48486c90b46cL, 0x378fb8b8e46b37e4L,
                0xe7789f9f5d25e75dL, 0xb20fbdbd6e61b26eL, 0x2a694343ef862aefL, 0xf135c4c4a693f1a6L, 0xe3da3939a872e3a8L, 0xf7c63131a462f7a4L, 0x598ad3d337bd5937L, 0x8674f2f28bff868bL,
                0x5683d5d532b15632L, 0xc54e8b8b430dc543L, 0xeb856e6e59dceb59L, 0xc218dadab7afc2b7L, 0x8f8e01018c028f8cL, 0xac1db1b16479ac64L, 0x6df19c9cd2236dd2L, 0x3b724949e0923be0L,
                0xc71fd8d8b4abc7b4L, 0x15b9acacfa4315faL, 0x09faf3f307fd0907L, 0x6fa0cfcf25856f25L, 0xea20cacaaf8feaafL, 0x897df4f48ef3898eL, 0x20674747e98e20e9L, 0x2838101018202818L,
                0x640b6f6fd5de64d5L, 0x8373f0f088fb8388L, 0xb1fb4a4a6f94b16fL, 0x96ca5c5c72b89672L, 0x6c54383824706c24L, 0x085f5757f1ae08f1L, 0x52217373c7e652c7L, 0xf36497975135f351L,
                0x65aecbcb238d6523L, 0x8425a1a17c59847cL, 0xbf57e8e89ccbbf9cL, 0x635d3e3e217c6321L, 0x7cea9696dd377cddL, 0x7f1e6161dcc27fdcL, 0x919c0d0d861a9186L, 0x949b0f0f851e9485L,
                0xab4be0e090dbab90L, 0xc6ba7c7c42f8c642L, 0x57267171c4e257c4L, 0xe529ccccaa83e5aaL, 0x73e39090d83b73d8L, 0x0f090606050c0f05L, 0x03f4f7f701f50301L, 0x362a1c1c12383612L,
                0xfe3cc2c2a39ffea3L, 0xe18b6a6a5fd4e15fL, 0x10beaeaef94710f9L, 0x6b026969d0d26bd0L, 0xa8bf1717912ea891L, 0xe87199995829e858L, 0x69533a3a27746927L, 0xd0f72727b94ed0b9L,
                0x4891d9d938a94838L, 0x35deebeb13cd3513L, 0xcee52b2bb356ceb3L, 0x5577222233445533L, 0xd604d2d2bbbfd6bbL, 0x9039a9a970499070L, 0x80870707890e8089L, 0xf2c13333a766f2a7L,
                0xc1ec2d2db65ac1b6L, 0x665a3c3c22786622L, 0xadb81515922aad92L, 0x60a9c9c920896020L, 0xdb5c87874915db49L, 0x1ab0aaaaff4f1affL, 0x88d8505078a08878L, 0x8e2ba5a57a518e7aL,
                0x8a8903038f068a8fL, 0x134a5959f8b213f8L, 0x9b92090980129b80L, 0x39231a1a17343917L, 0x75106565daca75daL, 0x5384d7d731b55331L, 0x51d58484c61351c6L, 0xd303d0d0b8bbd3b8L,
                0x5edc8282c31f5ec3L, 0xcbe22929b052cbb0L, 0x99c35a5a77b49977L, 0x332d1e1e113c3311L, 0x463d7b7bcbf646cbL, 0x1fb7a8a8fc4b1ffcL, 0x610c6d6dd6da61d6L, 0x4e622c2c3a584e3aL,
                0x32c6c6a597f4a5f4L, 0x6ff8f884eb978497L, 0x5eeeee99c7b099b0L, 0x7af6f68df78c8d8cL, 0xe8ffff0de5170d17L, 0x0ad6d6bdb7dcbddcL, 0x16dedeb1a7c8b1c8L, 0x6d91915439fc54fcL,
                0x90606050c0f050f0L, 0x0702020304050305L, 0x2ececea987e0a9e0L, 0xd156567dac877d87L, 0xcce7e719d52b192bL, 0x13b5b56271a662a6L, 0x7c4d4de69a31e631L, 0x59ecec9ac3b59ab5L,
                0x408f8f4505cf45cfL, 0xa31f1f9d3ebc9dbcL, 0x4989894009c040c0L, 0x68fafa87ef928792L, 0xd0efef15c53f153fL, 0x94b2b2eb7f26eb26L, 0xce8e8ec90740c940L, 0xe6fbfb0bed1d0b1dL,
                0x6e4141ec822fec2fL, 0x1ab3b3677da967a9L, 0x435f5ffdbe1cfd1cL, 0x604545ea8a25ea25L, 0xf92323bf46dabfdaL, 0x515353f7a602f702L, 0x45e4e496d3a196a1L, 0x769b9b5b2ded5bedL,
                0x287575c2ea5dc25dL, 0xc5e1e11cd9241c24L, 0xd43d3dae7ae9aee9L, 0xf24c4c6a98be6abeL, 0x826c6c5ad8ee5aeeL, 0xbd7e7e41fcc341c3L, 0xf3f5f502f1060206L, 0x5283834f1dd14fd1L,
                0x8c68685cd0e45ce4L, 0x565151f4a207f407L, 0x8dd1d134b95c345cL, 0xe1f9f908e9180818L, 0x4ce2e293dfae93aeL, 0x3eabab734d957395L, 0x97626253c4f553f5L, 0x6b2a2a3f54413f41L,
                0x1c08080c10140c14L, 0x6395955231f652f6L, 0xe94646658caf65afL, 0x7f9d9d5e21e25ee2L, 0x4830302860782878L, 0xcf3737a16ef8a1f8L, 0x1b0a0a0f14110f11L, 0xeb2f2fb55ec4b5c4L,
                0x150e0e091c1b091bL, 0x7e242436485a365aL, 0xad1b1b9b36b69bb6L, 0x98dfdf3da5473d47L, 0xa7cdcd26816a266aL, 0xf54e4e699cbb69bbL, 0x337f7fcdfe4ccd4cL, 0x50eaea9fcfba9fbaL,
                0x3f12121b242d1b2dL, 0xa41d1d9e3ab99eb9L, 0xc4585874b09c749cL, 0x4634342e68722e72L, 0x4136362d6c772d77L, 0x11dcdcb2a3cdb2cdL, 0x9db4b4ee7329ee29L, 0x4d5b5bfbb616fb16L,
                0xa5a4a4f65301f601L, 0xa176764decd74dd7L, 0x14b7b76175a361a3L, 0x347d7dcefa49ce49L, 0xdf52527ba48d7b8dL, 0x9fdddd3ea1423e42L, 0xcd5e5e71bc937193L, 0xb113139726a297a2L,
                0xa2a6a6f55704f504L, 0x01b9b96869b868b8L, 0x0000000000000000L, 0xb5c1c12c99742c74L, 0xe040406080a060a0L, 0xc2e3e31fdd211f21L, 0x3a7979c8f243c843L, 0x9ab6b6ed772ced2cL,
                0x0dd4d4beb3d9bed9L, 0x478d8d4601ca46caL, 0x176767d9ce70d970L, 0xaf72724be4dd4bddL, 0xed9494de3379de79L, 0xff9898d42b67d467L, 0x93b0b0e87b23e823L, 0x5b85854a11de4adeL,
                0x06bbbb6b6dbd6bbdL, 0xbbc5c52a917e2a7eL, 0x7b4f4fe59e34e534L, 0xd7eded16c13a163aL, 0xd28686c51754c554L, 0xf89a9ad72f62d762L, 0x99666655ccff55ffL, 0xb611119422a794a7L,
                0xc08a8acf0f4acf4aL, 0xd9e9e910c9301030L, 0x0e040406080a060aL, 0x66fefe81e7988198L, 0xaba0a0f05b0bf00bL, 0xb4787844f0cc44ccL, 0xf02525ba4ad5bad5L, 0x754b4be3963ee33eL,
                0xaca2a2f35f0ef30eL, 0x445d5dfeba19fe19L, 0xdb8080c01b5bc05bL, 0x8005058a0a858a85L, 0xd33f3fad7eecadecL, 0xfe2121bc42dfbcdfL, 0xa8707048e0d848d8L, 0xfdf1f104f90c040cL,
                0x196363dfc67adf7aL, 0x2f7777c1ee58c158L, 0x30afaf75459f759fL, 0xe742426384a563a5L, 0x7020203040503050L, 0xcbe5e51ad12e1a2eL, 0xeffdfd0ee1120e12L, 0x08bfbf6d65b76db7L,
                0x5581814c19d44cd4L, 0x24181814303c143cL, 0x792626354c5f355fL, 0xb2c3c32f9d712f71L, 0x86bebee16738e138L, 0xc83535a26afda2fdL, 0xc78888cc0b4fcc4fL, 0x652e2e395c4b394bL,
                0x6a9393573df957f9L, 0x585555f2aa0df20dL, 0x61fcfc82e39d829dL, 0xb37a7a47f4c947c9L, 0x27c8c8ac8befacefL, 0x88babae76f32e732L, 0x4f32322b647d2b7dL, 0x42e6e695d7a495a4L,
                0x3bc0c0a09bfba0fbL, 0xaa19199832b398b3L, 0xf69e9ed12768d168L, 0x22a3a37f5d817f81L, 0xee44446688aa66aaL, 0xd654547ea8827e82L, 0xdd3b3bab76e6abe6L, 0x950b0b83169e839eL,
                0xc98c8cca0345ca45L, 0xbcc7c729957b297bL, 0x056b6bd3d66ed36eL, 0x6c28283c50443c44L, 0x2ca7a779558b798bL, 0x81bcbce2633de23dL, 0x3116161d2c271d27L, 0x37adad76419a769aL,
                0x96dbdb3bad4d3b4dL, 0x9e646456c8fa56faL, 0xa674744ee8d24ed2L, 0x3614141e28221e22L, 0xe49292db3f76db76L, 0x120c0c0a181e0a1eL, 0xfc48486c90b46cb4L, 0x8fb8b8e46b37e437L,
                0x789f9f5d25e75de7L, 0x0fbdbd6e61b26eb2L, 0x694343ef862aef2aL, 0x35c4c4a693f1a6f1L, 0xda3939a872e3a8e3L, 0xc63131a462f7a4f7L, 0x8ad3d337bd593759L, 0x74f2f28bff868b86L,
                0x83d5d532b1563256L, 0x4e8b8b430dc543c5L, 0x856e6e59dceb59ebL, 0x18dadab7afc2b7c2L, 0x8e01018c028f8c8fL, 0x1db1b16479ac64acL, 0xf19c9cd2236dd26dL, 0x724949e0923be03bL,
                0x1fd8d8b4abc7b4c7L, 0xb9acacfa4315fa15L, 0xfaf3f307fd090709L, 0xa0cfcf25856f256fL, 0x20cacaaf8feaafeaL, 0x7df4f48ef3898e89L, 0x674747e98e20e920L, 0x3810101820281828L,
                0x0b6f6fd5de64d564L, 0x73f0f088fb838883L, 0xfb4a4a6f94b16fb1L, 0xca5c5c72b8967296L, 0x54383824706c246cL, 0x5f5757f1ae08f108L, 0x217373c7e652c752L, 0x6497975135f351f3L,
                0xaecbcb238d652365L, 0x25a1a17c59847c84L, 0x57e8e89ccbbf9cbfL, 0x5d3e3e217c632163L, 0xea9696dd377cdd7cL, 0x1e6161dcc27fdc7fL, 0x9c0d0d861a918691L, 0x9b0f0f851e948594L,
                0x4be0e090dbab90abL, 0xba7c7c42f8c642c6L, 0x267171c4e257c457L, 0x29ccccaa83e5aae5L, 0xe39090d83b73d873L, 0x090606050c0f050fL, 0xf4f7f701f5030103L, 0x2a1c1c1238361236L,
                0x3cc2c2a39ffea3feL, 0x8b6a6a5fd4e15fe1L, 0xbeaeaef94710f910L, 0x026969d0d26bd06bL, 0xbf1717912ea891a8L, 0x7199995829e858e8L, 0x533a3a2774692769L, 0xf72727b94ed0b9d0L,
                0x91d9d938a9483848L, 0xdeebeb13cd351335L, 0xe52b2bb356ceb3ceL, 0x7722223344553355L, 0x04d2d2bbbfd6bbd6L, 0x39a9a97049907090L, 0x870707890e808980L, 0xc13333a766f2a7f2L,
                0xec2d2db65ac1b6c1L, 0x5a3c3c2278662266L, 0xb81515922aad92adL, 0xa9c9c92089602060L, 0x5c87874915db49dbL, 0xb0aaaaff4f1aff1aL, 0xd8505078a0887888L, 0x2ba5a57a518e7a8eL,
                0x8903038f068a8f8aL, 0x4a5959f8b213f813L, 0x92090980129b809bL, 0x231a1a1734391739L, 0x106565daca75da75L, 0x84d7d731b5533153L, 0xd58484c61351c651L, 0x03d0d0b8bbd3b8d3L,
                0xdc8282c31f5ec35eL, 0xe22929b052cbb0cbL, 0xc35a5a77b4997799L, 0x2d1e1e113c331133L, 0x3d7b7bcbf646cb46L, 0xb7a8a8fc4b1ffc1fL, 0x0c6d6dd6da61d661L, 0x622c2c3a584e3a4eL,
                0xc6c6a597f4a5f432L, 0xf8f884eb9784976fL, 0xeeee99c7b099b05eL, 0xf6f68df78c8d8c7aL, 0xffff0de5170d17e8L, 0xd6d6bdb7dcbddc0aL, 0xdedeb1a7c8b1c816L, 0x91915439fc54fc6dL,
                0x606050c0f050f090L, 0x0202030405030507L, 0xcecea987e0a9e02eL, 0x56567dac877d87d1L, 0xe7e719d52b192bccL, 0xb5b56271a662a613L, 0x4d4de69a31e6317cL, 0xecec9ac3b59ab559L,
                0x8f8f4505cf45cf40L, 0x1f1f9d3ebc9dbca3L, 0x89894009c040c049L, 0xfafa87ef92879268L, 0xefef15c53f153fd0L, 0xb2b2eb7f26eb2694L, 0x8e8ec90740c940ceL, 0xfbfb0bed1d0b1de6L,
                0x4141ec822fec2f6eL, 0xb3b3677da967a91aL, 0x5f5ffdbe1cfd1c43L, 0x4545ea8a25ea2560L, 0x2323bf46dabfdaf9L, 0x5353f7a602f70251L, 0xe4e496d3a196a145L, 0x9b9b5b2ded5bed76L,
                0x7575c2ea5dc25d28L, 0xe1e11cd9241c24c5L, 0x3d3dae7ae9aee9d4L, 0x4c4c6a98be6abef2L, 0x6c6c5ad8ee5aee82L, 0x7e7e41fcc341c3bdL, 0xf5f502f1060206f3L, 0x83834f1dd14fd152L,
                0x68685cd0e45ce48cL, 0x5151f4a207f40756L, 0xd1d134b95c345c8dL, 0xf9f908e9180818e1L, 0xe2e293dfae93ae4cL, 0xabab734d9573953eL, 0x626253c4f553f597L, 0x2a2a3f54413f416bL,
                0x08080c10140c141cL, 0x95955231f652f663L, 0x4646658caf65afe9L, 0x9d9d5e21e25ee27fL, 0x3030286078287848L, 0x3737a16ef8a1f8cfL, 0x0a0a0f14110f111bL, 0x2f2fb55ec4b5c4ebL,
                0x0e0e091c1b091b15L, 0x242436485a365a7eL, 0x1b1b9b36b69bb6adL, 0xdfdf3da5473d4798L, 0xcdcd26816a266aa7L, 0x4e4e699cbb69bbf5L, 0x7f7fcdfe4ccd4c33L, 0xeaea9fcfba9fba50L,
                0x12121b242d1b2d3fL, 0x1d1d9e3ab99eb9a4L, 0x585874b09c749cc4L, 0x34342e68722e7246L, 0x36362d6c772d7741L, 0xdcdcb2a3cdb2cd11L, 0xb4b4ee7329ee299dL, 0x5b5bfbb616fb164dL,
                0xa4a4f65301f601a5L, 0x76764decd74dd7a1L, 0xb7b76175a361a314L, 0x7d7dcefa49ce4934L, 0x52527ba48d7b8ddfL, 0xdddd3ea1423e429fL, 0x5e5e71bc937193cdL, 0x13139726a297a2b1L,
                0xa6a6f55704f504a2L, 0xb9b96869b868b801L, 0x0000000000000000L, 0xc1c12c99742c74b5L, 0x40406080a060a0e0L, 0xe3e31fdd211f21c2L, 0x7979c8f243c8433aL, 0xb6b6ed772ced2c9aL,
                0xd4d4beb3d9bed90dL, 0x8d8d4601ca46ca47L, 0x6767d9ce70d97017L, 0x72724be4dd4bddafL, 0x9494de3379de79edL, 0x9898d42b67d467ffL, 0xb0b0e87b23e82393L, 0x85854a11de4ade5bL,
                0xbbbb6b6dbd6bbd06L, 0xc5c52a917e2a7ebbL, 0x4f4fe59e34e5347bL, 0xeded16c13a163ad7L, 0x8686c51754c554d2L, 0x9a9ad72f62d762f8L, 0x666655ccff55ff99L, 0x11119422a794a7b6L,
                0x8a8acf0f4acf4ac0L, 0xe9e910c9301030d9L, 0x040406080a060a0eL, 0xfefe81e798819866L, 0xa0a0f05b0bf00babL, 0x787844f0cc44ccb4L, 0x2525ba4ad5bad5f0L, 0x4b4be3963ee33e75L,
                0xa2a2f35f0ef30eacL, 0x5d5dfeba19fe1944L, 0x8080c01b5bc05bdbL, 0x05058a0a858a8580L, 0x3f3fad7eecadecd3L, 0x2121bc42dfbcdffeL, 0x707048e0d848d8a8L, 0xf1f104f90c040cfdL,
                0x6363dfc67adf7a19L, 0x7777c1ee58c1582fL, 0xafaf75459f759f30L, 0x42426384a563a5e7L, 0x2020304050305070L, 0xe5e51ad12e1a2ecbL, 0xfdfd0ee1120e12efL, 0xbfbf6d65b76db708L,
                0x81814c19d44cd455L, 0x181814303c143c24L, 0x2626354c5f355f79L, 0xc3c32f9d712f71b2L, 0xbebee16738e13886L, 0x3535a26afda2fdc8L, 0x8888cc0b4fcc4fc7L, 0x2e2e395c4b394b65L,
                0x9393573df957f96aL, 0x5555f2aa0df20d58L, 0xfcfc82e39d829d61L, 0x7a7a47f4c947c9b3L, 0xc8c8ac8befacef27L, 0xbabae76f32e73288L, 0x32322b647d2b7d4fL, 0xe6e695d7a495a442L,
                0xc0c0a09bfba0fb3bL, 0x19199832b398b3aaL, 0x9e9ed12768d168f6L, 0xa3a37f5d817f8122L, 0x44446688aa66aaeeL, 0x54547ea8827e82d6L, 0x3b3bab76e6abe6ddL, 0x0b0b83169e839e95L,
                0x8c8cca0345ca45c9L, 0xc7c729957b297bbcL, 0x6b6bd3d66ed36e05L, 0x28283c50443c446cL, 0xa7a779558b798b2cL, 0xbcbce2633de23d81L, 0x16161d2c271d2731L, 0xadad76419a769a37L,
                0xdbdb3bad4d3b4d96L, 0x646456c8fa56fa9eL, 0x74744ee8d24ed2a6L, 0x14141e28221e2236L, 0x9292db3f76db76e4L, 0x0c0c0a181e0a1e12L, 0x48486c90b46cb4fcL, 0xb8b8e46b37e4378fL,
                0x9f9f5d25e75de778L, 0xbdbd6e61b26eb20fL, 0x4343ef862aef2a69L, 0xc4c4a693f1a6f135L, 0x3939a872e3a8e3daL, 0x3131a462f7a4f7c6L, 0xd3d337bd5937598aL, 0xf2f28bff868b8674L,
                0xd5d532b156325683L, 0x8b8b430dc543c54eL, 0x6e6e59dceb59eb85L, 0xdadab7afc2b7c218L, 0x01018c028f8c8f8eL, 0xb1b16479ac64ac1dL, 0x9c9cd2236dd26df1L, 0x4949e0923be03b72L,
                0xd8d8b4abc7b4c71fL, 0xacacfa4315fa15b9L, 0xf3f307fd090709faL, 0xcfcf25856f256fa0L, 0xcacaaf8feaafea20L, 0xf4f48ef3898e897dL, 0x4747e98e20e92067L, 0x1010182028182838L,
                0x6f6fd5de64d5640bL, 0xf0f088fb83888373L, 0x4a4a6f94b16fb1fbL, 0x5c5c72b8967296caL, 0x383824706c246c54L, 0x5757f1ae08f1085fL, 0x7373c7e652c75221L, 0x97975135f351f364L,
                0xcbcb238d652365aeL, 0xa1a17c59847c8425L, 0xe8e89ccbbf9cbf57L, 0x3e3e217c6321635dL, 0x9696dd377cdd7ceaL, 0x6161dcc27fdc7f1eL, 0x0d0d861a9186919cL, 0x0f0f851e9485949bL,
                0xe0e090dbab90ab4bL, 0x7c7c42f8c642c6baL, 0x7171c4e257c45726L, 0xccccaa83e5aae529L, 0x9090d83b73d873e3L, 0x0606050c0f050f09L, 0xf7f701f5030103f4L, 0x1c1c12383612362aL,
                0xc2c2a39ffea3fe3cL, 0x6a6a5fd4e15fe18bL, 0xaeaef94710f910beL, 0x6969d0d26bd06b02L, 0x1717912ea891a8bfL, 0x99995829e858e871L, 0x3a3a277469276953L, 0x2727b94ed0b9d0f7L,
                0xd9d938a948384891L, 0xebeb13cd351335deL, 0x2b2bb356ceb3cee5L, 0x2222334455335577L, 0xd2d2bbbfd6bbd604L, 0xa9a9704990709039L, 0x0707890e80898087L, 0x3333a766f2a7f2c1L,
                0x2d2db65ac1b6c1ecL, 0x3c3c22786622665aL, 0x1515922aad92adb8L, 0xc9c92089602060a9L, 0x87874915db49db5cL, 0xaaaaff4f1aff1ab0L, 0x505078a0887888d8L, 0xa5a57a518e7a8e2bL,
                0x03038f068a8f8a89L, 0x5959f8b213f8134aL, 0x090980129b809b92L, 0x1a1a173439173923L, 0x6565daca75da7510L, 0xd7d731b553315384L, 0x8484c61351c651d5L, 0xd0d0b8bbd3b8d303L,
                0x8282c31f5ec35edcL, 0x2929b052cbb0cbe2L, 0x5a5a77b4997799c3L, 0x1e1e113c3311332dL, 0x7b7bcbf646cb463dL, 0xa8a8fc4b1ffc1fb7L, 0x6d6dd6da61d6610cL, 0x2c2c3a584e3a4e62L };

        /**
         * Constructor.
         * @param pHashBitLen the hash bit length
         */
        GroestlFastDigest(int pHashBitLen) {
            /* Check the hashBitLength */
            int numCols;
            switch (pHashBitLen) {
                case 224:
                case 256:
                    isShort = true;
                    size = SIZE512;
                    numCols = COLS512;
                    break;
                case 384:
                case 512:
                    isShort = false;
                    size = SIZE1024;
                    numCols = COLS1024;
                    break;
                default:
                    throw new IllegalArgumentException("JH digest restricted to one of [224, 256, 384, 512]");
            }

            /* Store value and initialise */
            hashbitlen = pHashBitLen;

            /* Allocate buffers */
            buffer = new byte[size];
            chaining = new long[numCols];
            tmpY = new long[numCols];
            tmpZ = new long[numCols];
            tmpOutQ = new long[numCols];
            tmpInP = new long[numCols];
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
            return size;
        }

        /**
         * Rotate a long nBits to the left retaining bits.
         * @param a the value to rotate
         * @param n the number of bits to rotate
         * @return the rotated long
         */
        private static long ROTL64(long a, int n) {
            return (a << n) | (a >>> (64 - n));
        }

        /**
         * Extract a numbered byte from a long.
         * @param var the long to extract from
         * @param n the byte number
         * @return the extracted byte
         */
        private static int EXT_BYTE(long var, int n) {
            return (int) ((var >>> (8 * n)) & 0xffL);
        }

        /**
         * Convert a long value to little-endian.
         * @param a the value to convert
         * @return the converted value
         */
        private static long U64BIG(long a) {
            return ((ROTL64(a, 8) & 0x000000FF000000FFL) |
                    (ROTL64(a, 24) & 0x0000FF000000FF00L) |
                    (ROTL64(a, 40) & 0x00FF000000FF0000L) |
                    (ROTL64(a, 56) & 0xFF000000FF000000L));
        }

        /**
         * Convert a series of eight bytes in littleEndian form to a long.
         * @param pBuffer the source buffer
         * @param pOffset the offset in the source buffer to extract from
         * @param pIndex the index of the long to extract with respect to the offset
         * @return the extracted long
         */
        private static long leBytesToLong(byte[] pBuffer, int pOffset, int pIndex) {
            /* Determine position to extract from */
            pIndex *= 8;
            pIndex += pOffset;

            /* Loop through the bytes to build the value */
            long value = 0;
            int i = 7;
            while (i > 0) {
                value += pBuffer[pIndex + i--] & 0xff;
                value <<= 8;
            }
            value += pBuffer[pIndex] & 0xff;

            /* Return the value */
            return value;
        }

        /**
         * Convert a long to littleEndian Bytes with truncation if required.
         * @param pValue the value to convert
         * @param pBuffer the buffer to place the result into
         * @param pOffset the offset of the buffer to place the result into
         * @param pLength the length of buffer available
         */
        private static void longToLeBytes(long pValue, byte[] pBuffer, int pOffset, int pLength) {
            /* Determine how many bytes to copy */
            int i = 8;
            while (i > pLength) {
                pValue >>= 8;
                i--;
            }

            /* Convert and copy bytes */
            int pos = pOffset + pLength - i;
            while (i-- > 0) {
                pBuffer[pos++] = (byte) (pValue & 0xff);
                pValue >>= 8;
            }
        }

        /* compute one new state column */
        private static long COLUMN(long[] x, int c0, int c1, int c2, int c3, int c4, int c5, int c6, int c7) {
            return T[0 * 256 + EXT_BYTE(x[c0], 0)]
                   ^ T[1 * 256 + EXT_BYTE(x[c1], 1)]
                   ^ T[2 * 256 + EXT_BYTE(x[c2], 2)]
                   ^ T[3 * 256 + EXT_BYTE(x[c3], 3)]
                   ^ T[4 * 256 + EXT_BYTE(x[c4], 4)]
                   ^ T[5 * 256 + EXT_BYTE(x[c5], 5)]
                   ^ T[6 * 256 + EXT_BYTE(x[c6], 6)]
                   ^ T[7 * 256 + EXT_BYTE(x[c7], 7)];
        }

        /* compute a round in P (short variants) */
        private static void RND512P(long[] x, long[] y, long r) {
            x[0] ^= 0x0000000000000000l ^ r;
            x[1] ^= 0x0000000000000010l ^ r;
            x[2] ^= 0x0000000000000020l ^ r;
            x[3] ^= 0x0000000000000030l ^ r;
            x[4] ^= 0x0000000000000040l ^ r;
            x[5] ^= 0x0000000000000050l ^ r;
            x[6] ^= 0x0000000000000060l ^ r;
            x[7] ^= 0x0000000000000070l ^ r;
            y[0] = COLUMN(x, 0, 1, 2, 3, 4, 5, 6, 7);
            y[1] = COLUMN(x, 1, 2, 3, 4, 5, 6, 7, 0);
            y[2] = COLUMN(x, 2, 3, 4, 5, 6, 7, 0, 1);
            y[3] = COLUMN(x, 3, 4, 5, 6, 7, 0, 1, 2);
            y[4] = COLUMN(x, 4, 5, 6, 7, 0, 1, 2, 3);
            y[5] = COLUMN(x, 5, 6, 7, 0, 1, 2, 3, 4);
            y[6] = COLUMN(x, 6, 7, 0, 1, 2, 3, 4, 5);
            y[7] = COLUMN(x, 7, 0, 1, 2, 3, 4, 5, 6);
        }

        /* compute a round in Q (short variants) */
        private static void RND512Q(long[] x, long[] y, long r) {
            x[0] ^= 0xffffffffffffffffl ^ r;
            x[1] ^= 0xefffffffffffffffl ^ r;
            x[2] ^= 0xdfffffffffffffffl ^ r;
            x[3] ^= 0xcfffffffffffffffl ^ r;
            x[4] ^= 0xbfffffffffffffffl ^ r;
            x[5] ^= 0xafffffffffffffffl ^ r;
            x[6] ^= 0x9fffffffffffffffl ^ r;
            x[7] ^= 0x8fffffffffffffffl ^ r;
            y[0] = COLUMN(x, 1, 3, 5, 7, 0, 2, 4, 6);
            y[1] = COLUMN(x, 2, 4, 6, 0, 1, 3, 5, 7);
            y[2] = COLUMN(x, 3, 5, 7, 1, 2, 4, 6, 0);
            y[3] = COLUMN(x, 4, 6, 0, 2, 3, 5, 7, 1);
            y[4] = COLUMN(x, 5, 7, 1, 3, 4, 6, 0, 2);
            y[5] = COLUMN(x, 6, 0, 2, 4, 5, 7, 1, 3);
            y[6] = COLUMN(x, 7, 1, 3, 5, 6, 0, 2, 4);
            y[7] = COLUMN(x, 0, 2, 4, 6, 7, 1, 3, 5);
        }

        /* compute a round in P (long variants) */
        private static void RND1024P(long[] x, long[] y, long r) {
            x[0] ^= 0x0000000000000000l ^ r;
            x[1] ^= 0x0000000000000010l ^ r;
            x[2] ^= 0x0000000000000020l ^ r;
            x[3] ^= 0x0000000000000030l ^ r;
            x[4] ^= 0x0000000000000040l ^ r;
            x[5] ^= 0x0000000000000050l ^ r;
            x[6] ^= 0x0000000000000060l ^ r;
            x[7] ^= 0x0000000000000070l ^ r;
            x[8] ^= 0x0000000000000080l ^ r;
            x[9] ^= 0x0000000000000090l ^ r;
            x[10] ^= 0x00000000000000a0l ^ r;
            x[11] ^= 0x00000000000000b0l ^ r;
            x[12] ^= 0x00000000000000c0l ^ r;
            x[13] ^= 0x00000000000000d0l ^ r;
            x[14] ^= 0x00000000000000e0l ^ r;
            x[15] ^= 0x00000000000000f0l ^ r;
            y[15] = COLUMN(x, 15, 0, 1, 2, 3, 4, 5, 10);
            y[14] = COLUMN(x, 14, 15, 0, 1, 2, 3, 4, 9);
            y[13] = COLUMN(x, 13, 14, 15, 0, 1, 2, 3, 8);
            y[12] = COLUMN(x, 12, 13, 14, 15, 0, 1, 2, 7);
            y[11] = COLUMN(x, 11, 12, 13, 14, 15, 0, 1, 6);
            y[10] = COLUMN(x, 10, 11, 12, 13, 14, 15, 0, 5);
            y[9] = COLUMN(x, 9, 10, 11, 12, 13, 14, 15, 4);
            y[8] = COLUMN(x, 8, 9, 10, 11, 12, 13, 14, 3);
            y[7] = COLUMN(x, 7, 8, 9, 10, 11, 12, 13, 2);
            y[6] = COLUMN(x, 6, 7, 8, 9, 10, 11, 12, 1);
            y[5] = COLUMN(x, 5, 6, 7, 8, 9, 10, 11, 0);
            y[4] = COLUMN(x, 4, 5, 6, 7, 8, 9, 10, 15);
            y[3] = COLUMN(x, 3, 4, 5, 6, 7, 8, 9, 14);
            y[2] = COLUMN(x, 2, 3, 4, 5, 6, 7, 8, 13);
            y[1] = COLUMN(x, 1, 2, 3, 4, 5, 6, 7, 12);
            y[0] = COLUMN(x, 0, 1, 2, 3, 4, 5, 6, 11);
        }

        /* compute a round in Q (long variants) */
        private static void RND1024Q(long[] x, long[] y, long r) {
            x[0] ^= 0xffffffffffffffffl ^ r;
            x[1] ^= 0xefffffffffffffffl ^ r;
            x[2] ^= 0xdfffffffffffffffl ^ r;
            x[3] ^= 0xcfffffffffffffffl ^ r;
            x[4] ^= 0xbfffffffffffffffl ^ r;
            x[5] ^= 0xafffffffffffffffl ^ r;
            x[6] ^= 0x9fffffffffffffffl ^ r;
            x[7] ^= 0x8fffffffffffffffl ^ r;
            x[8] ^= 0x7fffffffffffffffl ^ r;
            x[9] ^= 0x6fffffffffffffffl ^ r;
            x[10] ^= 0x5fffffffffffffffl ^ r;
            x[11] ^= 0x4fffffffffffffffl ^ r;
            x[12] ^= 0x3fffffffffffffffl ^ r;
            x[13] ^= 0x2fffffffffffffffl ^ r;
            x[14] ^= 0x1fffffffffffffffl ^ r;
            x[15] ^= 0x0fffffffffffffffl ^ r;
            y[15] = COLUMN(x, 0, 2, 4, 10, 15, 1, 3, 5);
            y[14] = COLUMN(x, 15, 1, 3, 9, 14, 0, 2, 4);
            y[13] = COLUMN(x, 14, 0, 2, 8, 13, 15, 1, 3);
            y[12] = COLUMN(x, 13, 15, 1, 7, 12, 14, 0, 2);
            y[11] = COLUMN(x, 12, 14, 0, 6, 11, 13, 15, 1);
            y[10] = COLUMN(x, 11, 13, 15, 5, 10, 12, 14, 0);
            y[9] = COLUMN(x, 10, 12, 14, 4, 9, 11, 13, 15);
            y[8] = COLUMN(x, 9, 11, 13, 3, 8, 10, 12, 14);
            y[7] = COLUMN(x, 8, 10, 12, 2, 7, 9, 11, 13);
            y[6] = COLUMN(x, 7, 9, 11, 1, 6, 8, 10, 12);
            y[5] = COLUMN(x, 6, 8, 10, 0, 5, 7, 9, 11);
            y[4] = COLUMN(x, 5, 7, 9, 15, 4, 6, 8, 10);
            y[3] = COLUMN(x, 4, 6, 8, 14, 3, 5, 7, 9);
            y[2] = COLUMN(x, 3, 5, 7, 13, 2, 4, 6, 8);
            y[1] = COLUMN(x, 2, 4, 6, 12, 1, 3, 5, 7);
            y[0] = COLUMN(x, 1, 3, 5, 11, 0, 2, 4, 6);
        }

        /* the compression function (short variants) */
        private void F512(long[] h, byte[] m, int pOffset) {
            int i;

            for (i = 0; i < COLS512; i++) {
                long inVal = leBytesToLong(m, pOffset, i);
                tmpZ[i] = inVal;
                tmpInP[i] = h[i] ^ inVal;
            }

            /* compute Q(m) */
            RND512Q(tmpZ, tmpY, 0x0000000000000000l);
            RND512Q(tmpY, tmpZ, 0x0100000000000000l);
            RND512Q(tmpZ, tmpY, 0x0200000000000000l);
            RND512Q(tmpY, tmpZ, 0x0300000000000000l);
            RND512Q(tmpZ, tmpY, 0x0400000000000000l);
            RND512Q(tmpY, tmpZ, 0x0500000000000000l);
            RND512Q(tmpZ, tmpY, 0x0600000000000000l);
            RND512Q(tmpY, tmpZ, 0x0700000000000000l);
            RND512Q(tmpZ, tmpY, 0x0800000000000000l);
            RND512Q(tmpY, tmpOutQ, 0x0900000000000000l);

            /* compute P(h+m) */
            RND512P(tmpInP, tmpZ, 0x0000000000000000l);
            RND512P(tmpZ, tmpY, 0x0000000000000001l);
            RND512P(tmpY, tmpZ, 0x0000000000000002l);
            RND512P(tmpZ, tmpY, 0x0000000000000003l);
            RND512P(tmpY, tmpZ, 0x0000000000000004l);
            RND512P(tmpZ, tmpY, 0x0000000000000005l);
            RND512P(tmpY, tmpZ, 0x0000000000000006l);
            RND512P(tmpZ, tmpY, 0x0000000000000007l);
            RND512P(tmpY, tmpZ, 0x0000000000000008l);
            RND512P(tmpZ, tmpY, 0x0000000000000009l);

            /* h' == h + Q(m) + P(h+m) */
            for (i = 0; i < COLS512; i++) {
                h[i] ^= tmpOutQ[i] ^ tmpY[i];
            }
        }

        /* the compression function (long variants) */
        private void F1024(long[] h, byte[] m, int pOffset) {
            int i;

            for (i = 0; i < COLS1024; i++) {
                long inVal = leBytesToLong(m, pOffset, i);
                tmpZ[i] = inVal;
                tmpInP[i] = h[i] ^ inVal;
            }

            /* compute Q(m) */
            RND1024Q(tmpZ, tmpY, 0);
            for (i = 1; i < ROUNDS1024 - 1; i += 2) {
                RND1024Q(tmpY, tmpZ, U64BIG((long) i));
                RND1024Q(tmpZ, tmpY, U64BIG((long) (i + 1)));
            }
            RND1024Q(tmpY, tmpOutQ, U64BIG(((long) (ROUNDS1024 - 1))));

            /* compute P(h+m) */
            RND1024P(tmpInP, tmpZ, 0);
            for (i = 1; i < ROUNDS1024 - 1; i += 2) {
                RND1024P(tmpZ, tmpY, U64BIG(((long) i) << 56));
                RND1024P(tmpY, tmpZ, U64BIG(((long) (i + 1)) << 56));
            }
            RND1024P(tmpZ, tmpY, U64BIG(((long) (ROUNDS1024 - 1)) << 56));

            /* h' == h + Q(m) + P(h+m) */
            for (i = 0; i < COLS1024; i++) {
                h[i] ^= tmpOutQ[i] ^ tmpY[i];
            }
        }

        /* digest up to msglen bytes of input (full blocks only) */
        private void Transform(byte[] input, int pOffset, int msglen) {
            /*
             * determine variant, SHORT or LONG, and select underlying compression function based on
             * the variant
             */
            if (isShort) {
                /* increment block counter */
                block_counter += msglen / SIZE512;
                while (msglen >= SIZE512) {
                    F512(chaining, input, pOffset);
                    msglen -= SIZE512;
                    pOffset += SIZE512;
                }
            } else {
                /* increment block counter */
                block_counter += msglen / SIZE1024;
                while (msglen >= SIZE1024) {
                    F1024(chaining, input, pOffset);
                    msglen -= SIZE1024;
                    pOffset += SIZE1024;
                }
            }
        }

        /* given state h, do h <- P(h)+h */
        private void OutputTransformation() {
            int j;

            /* determine variant */
            if (isShort) {
                for (j = 0; j < COLS512; j++) {
                    tmpInP[j] = chaining[j];
                }
                RND512P(tmpInP, tmpZ, 0x0000000000000000l);
                RND512P(tmpZ, tmpY, 0x0000000000000001l);
                RND512P(tmpY, tmpZ, 0x0000000000000002l);
                RND512P(tmpZ, tmpY, 0x0000000000000003l);
                RND512P(tmpY, tmpZ, 0x0000000000000004l);
                RND512P(tmpZ, tmpY, 0x0000000000000005l);
                RND512P(tmpY, tmpZ, 0x0000000000000006l);
                RND512P(tmpZ, tmpY, 0x0000000000000007l);
                RND512P(tmpY, tmpZ, 0x0000000000000008l);
                RND512P(tmpZ, tmpInP, 0x0000000000000009l);
                for (j = 0; j < COLS512; j++) {
                    chaining[j] ^= tmpInP[j];
                }

            } else {
                for (j = 0; j < COLS1024; j++) {
                    tmpInP[j] = chaining[j];
                }
                RND1024P(tmpInP, tmpY, 0);
                for (j = 1; j < ROUNDS1024 - 1; j += 2) {
                    RND1024P(tmpY, tmpZ, U64BIG(((long) j) << 56));
                    RND1024P(tmpZ, tmpY, U64BIG(((long) j + 1) << 56));
                }
                RND1024P(tmpY, tmpInP, U64BIG(((long) (ROUNDS1024 - 1)) << 56));
                for (j = 0; j < COLS1024; j++) {
                    chaining[j] ^= tmpInP[j];
                }
            }
        }

        /* initialise context */
        private void Init() {
            /*
             * set number of state columns and state size depending on variant
             */
            if (isShort) {
                /* set initial value */
                chaining[COLS512 - 1] = U64BIG((long) hashbitlen);

            } else {
                /* set initial value */
                chaining[COLS1024 - 1] = U64BIG((long) hashbitlen);
            }

            /* set other variables */
            buf_ptr = 0;
            block_counter = 0;
            bits_in_last_byte = 0;
        }

        /**
         * Reset the digest.
         */
        void reset() {
            if (initialised) {
                /* Clear Chaining and buffer */
                Arrays.fill(chaining, 0);
                Arrays.fill(buffer, (byte) 0);

                /* Clear the initialised flag */
                initialised = false;
            }
        }

        /**
         * CopyIn state from another digest.
         * @param pState the other digest
         */
        void copyIn(GroestlFastDigest pState) {
            /* Ensure that we are copying similar digest */
            if (this.hashbitlen != pState.hashbitlen)
                throw new IllegalArgumentException();

            /* Copy state */
            initialised = pState.initialised;
            block_counter = pState.block_counter;
            buf_ptr = pState.buf_ptr;
            bits_in_last_byte = pState.bits_in_last_byte;
            System.arraycopy(pState.buffer, 0, buffer, 0, buffer.length);
            System.arraycopy(pState.chaining, 0, chaining, 0, chaining.length);
        }

        /* update state with databitlen bits of input */
        void Update(byte[] input, int pOffset, long databitlen) {
            int index = 0;
            int msglen = (int) (databitlen / 8);
            int rem = (int) (databitlen % 8);

            /*
             * non-integral number of message bytes can only be supplied in the last call to this
             * function
             */
            if (bits_in_last_byte != 0)
                throw new IllegalStateException("FAIL");

            /* Ensure that we are initialised */
            ensureInitialised();

            /*
             * if the buffer contains data that has not yet been digested, first add data to buffer
             * until full
             */
            if (buf_ptr != 0) {
                while (buf_ptr < size && index < msglen) {
                    buffer[buf_ptr++] = input[pOffset + index++];
                }
                if (buf_ptr < size) {
                    /* buffer still not full, return */
                    if (rem != 0) {
                        bits_in_last_byte = rem;
                        buffer[buf_ptr++] = input[pOffset + index];
                    }
                    return;
                }

                /* digest buffer */
                buf_ptr = 0;
                Transform(buffer, 0, size);
            }

            /* digest bulk of message */
            Transform(input, pOffset + index, msglen - index);
            index += ((msglen - index) / size) * size;

            /* store remaining data in buffer */
            while (index < msglen) {
                buffer[buf_ptr++] = input[pOffset + index++];
            }

            /*
             * if non-integral number of bytes have been supplied, store remaining bits in last
             * byte, together with information about number of bits
             */
            if (rem != 0) {
                bits_in_last_byte = rem;
                buffer[buf_ptr++] = input[pOffset + index];
            }
        }

        /**
         * Build hash from state buffer.
         * @param pHashVal the buffer to build the hash into
         * @param pOffset the offset at which to place the hash
         * @param pLength the length of the hash
         */
        private void buildHashFromState(byte[] pHashVal, int pOffset, int pLength) {
            for (int i = chaining.length - 1; i >= 0 && pLength > 0; i--) {
                longToLeBytes(chaining[i], pHashVal, pOffset, pLength);
                pLength -= 8;
            }
        }

        /*
         * finalise: process remaining data (including padding), perform output transformation, and
         * write hash result to 'output'
         */
        void Final(byte[] hashval, int pOffset) {
            int hashbytelen = hashbitlen / 8;

            /* Ensure that we are initialised */
            ensureInitialised();

            /* pad with '1'-bit and first few '0'-bits */
            if (bits_in_last_byte != 0) {
                buffer[buf_ptr - 1] &= ((1 << bits_in_last_byte) - 1) << (8 - bits_in_last_byte);
                buffer[buf_ptr - 1] ^= 0x1 << (7 - bits_in_last_byte);
                bits_in_last_byte = 0;
            } else
                buffer[buf_ptr++] = (byte) 0x80;

            /* pad with '0'-bits */
            if (buf_ptr > size - LENGTHFIELDLEN) {
                /* padding requires two blocks */
                while (buf_ptr < size) {
                    buffer[buf_ptr++] = 0;
                }
                /* digest first padding block */
                Transform(buffer, 0, size);
                buf_ptr = 0;
            }
            while (buf_ptr < size - LENGTHFIELDLEN) {
                buffer[buf_ptr++] = 0;
            }

            /* length padding */
            block_counter++;
            buf_ptr = size;
            while (buf_ptr > size - LENGTHFIELDLEN) {
                buffer[--buf_ptr] = (byte) block_counter;
                block_counter >>>= 8;
            }

            /* digest final padding block */
            Transform(buffer, 0, size);

            /* perform output transformation */
            OutputTransformation();

            /* store hash result in output */
            buildHashFromState(hashval, pOffset, hashbytelen);

            /* Reset the digest */
            reset();
        }
    }
}
