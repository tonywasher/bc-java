package org.bouncycastle.crypto.signers.xmss;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FilterInputStream;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.XMSSMTKeyPairGenerator;
import org.bouncycastle.crypto.params.XMSSMTKeyGenerationParameters;
import org.bouncycastle.crypto.params.XMSSMTParameters;
import org.bouncycastle.crypto.params.XMSSMTPrivateKeyParameters;
import org.bouncycastle.crypto.signers.XMSSMTSigner;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/**
 * The BDS traversal state an XMSS^MT private key carries is written as the versioned binary form
 * BDSStateCodec defines, but state Java serialized by an earlier release is still read. State
 * written before it recorded a maximum index has to be resolved against the parameter set of the
 * key it belongs to, since a state map - unlike a BDS, which knows its own tree height - cannot
 * resolve it for itself. State that does carry a maximum index has to keep it, whatever the stream
 * it arrives on reports it has available: a state map silently taken for one written without a
 * maximum index would be widened to the whole key space, and a single use key shard widened that
 * way signs with one-time keys the key it was taken from will use again.
 */
public class BDSStateSerializationTests
    extends TestCase
{
    private static final int HEIGHT = 4;
    private static final int LAYERS = 2;

    private static final String STATE_MAP_CLASS = "org.bouncycastle.crypto.signers.xmss.BDSStateMap";

    public void testStateMapWithoutAMaximumIndexResolvedAgainstTheParameters()
        throws Exception
    {
        XMSSMTParameters params = new XMSSMTParameters(HEIGHT, LAYERS, new SHA256Digest());
        XMSSMTPrivateKeyParameters privKey = generateKey(params);

        byte[] legacyState = withoutMaximumIndex(javaSerialize(privKey.getBDSState()));
        BDSStateMap recovered = (BDSStateMap)XMSSUtil.deserialize(legacyState, BDSStateMap.class);

        assertEquals(-1L, recovered.getMaxIndex());

        // as PrivateKeyFactory does: the WOTS+ parameters are not part of what was serialized, so
        // they go back on before anything copies the states
        recovered = recovered.withWOTSDigest(params.getTreeDigestOID(), params.getTreeDigestSize());

        assertEquals(-1L, recovered.getMaxIndex());

        // through the builder, as PrivateKeyFactory imports one
        XMSSMTPrivateKeyParameters fromBuilder = new XMSSMTPrivateKeyParameters.Builder(params)
            .withSecretKeySeed(privKey.getSecretKeySeed()).withSecretKeyPRF(privKey.getSecretKeyPRF())
            .withPublicSeed(privKey.getPublicSeed()).withRoot(privKey.getRoot())
            .withIndex(privKey.getIndex())
            .withBDSState(recovered).build();

        assertEquals(1L << HEIGHT, fromBuilder.getUsagesRemaining());
        assertEquals((1L << HEIGHT) - 1, fromBuilder.getBDSState().getMaxIndex());
        signsOnce(fromBuilder);

        // and through the private key encoding, where the state is the tail of the encoding
        int stateOffset = ((HEIGHT + 7) / 8) + 4 * params.getTreeDigestSize();
        byte[] current = privKey.getEncoded();
        byte[] legacyEncoding = Arrays.concatenate(Arrays.copyOfRange(current, 0, stateOffset), legacyState);

        XMSSMTPrivateKeyParameters fromEncoding = new XMSSMTPrivateKeyParameters.Builder(params)
            .withPrivateKey(legacyEncoding).build();

        assertEquals(1L << HEIGHT, fromEncoding.getUsagesRemaining());
        signsOnce(fromEncoding);
    }

    public void testStateMapKeepsItsMaximumIndexOnAStreamReportingNothingAvailable()
        throws Exception
    {
        BDSStateMap stateMap = new BDSStateMap(5L);
        byte[] encoding = javaSerialize(stateMap);

        assertEquals(5L, javaDeserialize(new ByteArrayInputStream(encoding)).getMaxIndex());

        // ObjectInputStream.available() answers what can be read without blocking, which for a
        // stream that has to wait for its next block header is zero even though the maximum index
        // is there to be read
        assertEquals(5L, javaDeserialize(new NothingAvailable(new ByteArrayInputStream(encoding))).getMaxIndex());
    }

    private XMSSMTPrivateKeyParameters generateKey(XMSSMTParameters params)
    {
        XMSSMTKeyPairGenerator kpg = new XMSSMTKeyPairGenerator();

        kpg.init(new XMSSMTKeyGenerationParameters(params, new SecureRandom()));

        return (XMSSMTPrivateKeyParameters)kpg.generateKeyPair().getPrivate();
    }

    private void signsOnce(XMSSMTPrivateKeyParameters privKey)
    {
        XMSSMTSigner signer = new XMSSMTSigner();
        byte[] message = new byte[]{ 1, 2, 3 };

        signer.init(true, privKey);
        signer.update(message, 0, message.length);

        assertNotNull(signer.generateSignature());
    }

    private static byte[] javaSerialize(Object o)
        throws Exception
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);

        oOut.writeObject(o);
        oOut.close();

        return bOut.toByteArray();
    }

    private static BDSStateMap javaDeserialize(InputStream in)
        throws Exception
    {
        return (BDSStateMap)new ObjectInputStream(in).readObject();
    }

    /**
     * Rewrite a Java serialized state map as one written before BDSStateMap recorded a maximum
     * index: clear SC_WRITE_METHOD in the class descriptor flags, which say the writer had a
     * writeObject() method, and drop the block holding the long it wrote and its end marker.
     */
    private static byte[] withoutMaximumIndex(byte[] encoding)
    {
        byte[] name = Strings.toByteArray(STATE_MAP_CLASS);
        int at = -1;

        for (int i = 0; i <= encoding.length - name.length; i++)
        {
            if (Arrays.areEqual(name, Arrays.copyOfRange(encoding, i, i + name.length)))
            {
                at = i;
                break;
            }
        }

        assertTrue("class descriptor for " + STATE_MAP_CLASS + " not found", at >= 0);

        // TC_BLOCKDATA, a length of 8, the long itself, then TC_ENDBLOCKDATA
        byte[] out = Arrays.copyOfRange(encoding, 0, encoding.length - 11);
        int flagsAt = at + name.length + 8;      // the name is followed by the serialVersionUID

        assertEquals(0x03, out[flagsAt] & 0xff); // SC_WRITE_METHOD | SC_SERIALIZABLE
        out[flagsAt] &= 0xfe;

        return out;
    }

    private static class NothingAvailable
        extends FilterInputStream
    {
        NothingAvailable(InputStream in)
        {
            super(in);
        }

        public int available()
        {
            return 0;
        }
    }
}
