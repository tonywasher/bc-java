package org.bouncycastle.crypto.signers.xmss;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.XMSSKeyPairGenerator;
import org.bouncycastle.crypto.generators.XMSSMTKeyPairGenerator;
import org.bouncycastle.crypto.params.XMSSKeyGenerationParameters;
import org.bouncycastle.crypto.params.XMSSMTKeyGenerationParameters;
import org.bouncycastle.crypto.params.XMSSMTParameters;
import org.bouncycastle.crypto.params.XMSSParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.pqc.asn1.XMSSMTPrivateKey;
import org.bouncycastle.pqc.asn1.XMSSPrivateKey;

/**
 * A private key written before the versioned BDSStateCodec form carries its BDS traversal state as
 * a bare Java serialized object, and that path is still read. Java deserialization does not run
 * field initializers, so a crafted stream that simply declares no fields leaves every field of the
 * recovered state at its default - the collections the state is made of come back null.
 * <p>
 * The import path then calls withWOTSDigest() on the recovered state to rebuild it around the
 * digest the key names, and that walks those collections before any validation runs: the null
 * checks BDS.validate() and BDSStateMap.validate() carry are real, but they are reached too late
 * to be the thing that rejects this. So the checks belong at the point of deserialization, where
 * the crafted stream actually enters, and they report as an IOException - the failure a caller of
 * PrivateKeyFactory.createKey is already handling - rather than as a NullPointerException out of
 * the middle of the rebuild.
 * </p>
 */
public class CraftedLegacyStateTests
    extends TestCase
{
    private static final byte TC_ENDBLOCKDATA = 0x78;
    private static final byte TC_NULL = 0x70;
    private static final byte TC_CLASSDESC = 0x72;
    private static final byte TC_OBJECT = 0x73;
    private static final byte TC_BLOCKDATA = 0x77;

    private static final byte SC_WRITE_METHOD = 0x01;
    private static final byte SC_SERIALIZABLE = 0x02;

    /**
     * A Java serialized object naming {@code className} and declaring no fields at all, so every
     * field of the class it names is left at its default on the way back in. {@code trailer} is
     * the class's own writeObject() data, which its readObject() still expects to find.
     */
    private static byte[] fieldlessObject(String className, long serialVersionUID, byte[] trailer)
        throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        DataOutputStream dOut = new DataOutputStream(bOut);

        dOut.writeShort(0xaced);                          // STREAM_MAGIC
        dOut.writeShort(0x0005);                          // STREAM_VERSION

        dOut.writeByte(TC_OBJECT);
        dOut.writeByte(TC_CLASSDESC);
        dOut.writeUTF(className);
        dOut.writeLong(serialVersionUID);
        dOut.writeByte(SC_WRITE_METHOD | SC_SERIALIZABLE);
        dOut.writeShort(0);                               // no fields
        dOut.writeByte(TC_ENDBLOCKDATA);                  // end of class annotation
        dOut.writeByte(TC_NULL);                          // no superclass

        // no field values follow, the descriptor declared none

        dOut.writeByte(TC_BLOCKDATA);
        dOut.writeByte(trailer.length);
        dOut.write(trailer);
        dOut.writeByte(TC_ENDBLOCKDATA);

        dOut.close();

        return bOut.toByteArray();
    }

    /**
     * A BDS whose authenticationPath, retain, stack, treeHashInstances and keep are all null. Its
     * readObject() reads a four byte maximum index, and treeHeight came back as 0, so 0 is the
     * only maximum index it will accept.
     */
    private static byte[] craftedBDS()
        throws IOException
    {
        return fieldlessObject("org.bouncycastle.crypto.signers.xmss.BDS", 1L,
            new byte[]{0, 0, 0, 0});
    }

    /**
     * A BDSStateMap whose map of per-layer states is null. Its readObject() reads an eight byte
     * maximum index.
     */
    private static byte[] craftedBDSStateMap()
        throws IOException
    {
        return fieldlessObject("org.bouncycastle.crypto.signers.xmss.BDSStateMap",
            -3464451825208522308L, new byte[]{0, 0, 0, 0, 0, 0, 0, 0});
    }

    public void testCraftedXMSSStateReported()
        throws Exception
    {
        XMSSParameters params = new XMSSParameters(4, NISTObjectIdentifiers.id_sha256);
        XMSSKeyPairGenerator kpg = new XMSSKeyPairGenerator();

        kpg.init(new XMSSKeyGenerationParameters(params, new SecureRandom()));

        AsymmetricCipherKeyPair kp = kpg.generateKeyPair();
        PrivateKeyInfo info = PrivateKeyInfoFactory.createPrivateKeyInfo(kp.getPrivate());
        XMSSPrivateKey asn1 = XMSSPrivateKey.getInstance(info.parsePrivateKey());

        PrivateKeyInfo crafted = new PrivateKeyInfo(info.getPrivateKeyAlgorithm(),
            new XMSSPrivateKey(asn1.getIndex(), asn1.getSecretKeySeed(), asn1.getSecretKeyPRF(),
                asn1.getPublicSeed(), asn1.getRoot(), craftedBDS()));

        try
        {
            PrivateKeyFactory.createKey(crafted);
            fail("crafted BDS state accepted");
        }
        catch (IOException e)
        {
            assertEquals("incomplete BDS state", e.getMessage());
        }
    }

    public void testCraftedXMSSMTStateReported()
        throws Exception
    {
        // height 4 over 2 layers is not one of the RFC 8391 sec. 5.4 registered sets, so the key
        // is written in the legacy form that carries a serialized state rather than the RFC 9802
        // raw form, which carries none
        XMSSMTParameters params = new XMSSMTParameters(4, 2, NISTObjectIdentifiers.id_sha256);
        XMSSMTKeyPairGenerator kpg = new XMSSMTKeyPairGenerator();

        kpg.init(new XMSSMTKeyGenerationParameters(params, new SecureRandom()));

        AsymmetricCipherKeyPair kp = kpg.generateKeyPair();
        PrivateKeyInfo info = PrivateKeyInfoFactory.createPrivateKeyInfo(kp.getPrivate());
        XMSSMTPrivateKey asn1 = XMSSMTPrivateKey.getInstance(info.parsePrivateKey());

        PrivateKeyInfo crafted = new PrivateKeyInfo(info.getPrivateKeyAlgorithm(),
            new XMSSMTPrivateKey(asn1.getIndex(), asn1.getSecretKeySeed(), asn1.getSecretKeyPRF(),
                asn1.getPublicSeed(), asn1.getRoot(), craftedBDSStateMap()));

        try
        {
            PrivateKeyFactory.createKey(crafted);
            fail("crafted BDS state map accepted");
        }
        catch (IOException e)
        {
            assertEquals("no state in BDS state map", e.getMessage());
        }
    }
}
