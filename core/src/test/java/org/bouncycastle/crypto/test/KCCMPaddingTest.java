package org.bouncycastle.crypto.test;

import java.security.SecureRandom;
import java.util.Arrays;

import org.bouncycastle.crypto.CipherKeyGenerator;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.engines.DSTU7624Engine;
import org.bouncycastle.crypto.macs.KGMac;
import org.bouncycastle.crypto.modes.KCCMBlockCipher;
import org.bouncycastle.crypto.modes.KGCMBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

/**
 * Test for DSTU7624 Padding problems in modes.
 */
public class KCCMPaddingTest {
    /* Create standard 64-byte input for encryption */
    private static final byte[] BYTES_64 = "A123456789B123456789C123456789D123456789E123456789F123456789G123".getBytes();

    /* Create longer 65-byte input for encryption */
    private static final byte[] BYTES_67 = "A123456789B123456789C123456789D123456789E123456789F123456789G123456".getBytes();

    /**
     * Run Tests.
     * @param pArgs arguments
     */
    public static void main(final String[] pArgs) {
        TestDSTU7624CCM(128, BYTES_64, true, false);
        TestDSTU7624CCM(128, BYTES_64, false, true);
        TestDSTU7624CCM(128, BYTES_64, true, true);
        TestDSTU7624CCM(128, BYTES_67, true, false);
        TestDSTU7624CCM(128, BYTES_67, false, true);
        TestDSTU7624CCM(128, BYTES_67, true, true);
    }

    /**
     * Test lightweight Kalyna KCCM Mode.
     * @param pBlockSize the blockSize
     * @param pData the data to encrypt
     * @param useAAD pass data as AAD to cipher
     * @param useData pass data as data to cipher
     */
    private static void TestDSTU7624CCM(final int pBlockSize,
                                        final byte[] pData,
                                        final boolean useAAD,
                                        final boolean useData) {
        /* Create the generator and generate a key */
        CipherKeyGenerator myGenerator = new CipherKeyGenerator();
        SecureRandom myRandom = new SecureRandom();
        KeyGenerationParameters myParams = new KeyGenerationParameters(myRandom, pBlockSize);
        myGenerator.init(myParams);
        byte[] myKey = myGenerator.generateKey();

        /* Create an base engine */
        DSTU7624Engine myEngine = new DSTU7624Engine(pBlockSize);

        /* Create IV */
        byte[] myIV = new byte[myEngine.getBlockSize()];
        myRandom.nextBytes(myIV);

        /* Create a parameterSpec */
        KeyParameter myParms = new KeyParameter(myKey);
        ParametersWithIV myIVParms = new ParametersWithIV(myParms, myIV);

        /* Create cipher */
        KCCMBlockCipher myCipher = new KCCMBlockCipher(myEngine);

        /* Catch Exceptions */
        try {
            /* Try with standard data only */
            myCipher.init(true, myIVParms);
            if (useAAD) {
                myCipher.processAADBytes(pData, 0, pData.length);
            }
            byte[] myEncrypted = new byte[myCipher.getUpdateOutputSize(useData
                                                                               ? pData.length
                                                                               : 0)];
            int myLen = useData
                                ? myCipher.processBytes(pData, 0, pData.length, myEncrypted, 0)
                                : 0;
            int myXtra = myCipher.getOutputSize(0);
            myEncrypted = Arrays.copyOf(myEncrypted, myLen + myXtra);
            myLen += myCipher.doFinal(myEncrypted, myLen);
            if (myLen != myEncrypted.length) {
                myEncrypted = Arrays.copyOf(myEncrypted, myLen);
            }

            myCipher.init(false, myIVParms);
            if (useAAD) {
                myCipher.processAADBytes(pData, 0, pData.length);
            }
            byte[] myClearText = new byte[myCipher.getUpdateOutputSize(myEncrypted.length)];
            myLen = myCipher.processBytes(myEncrypted, 0, myEncrypted.length, myClearText, 0);
            myXtra = myCipher.getOutputSize(0);
            myClearText = Arrays.copyOf(myClearText, myLen + myXtra);
            myLen += myCipher.doFinal(myClearText, myLen);
            if (myLen != myClearText.length) {
                myClearText = Arrays.copyOf(myClearText, myLen);
            }

            boolean bSuccess = useData
                                       ? Arrays.equals(pData, myClearText)
                                       : myLen == 0;
            if (bSuccess) {
                System.out.println("DSTU7624-" + pBlockSize + " Bug fixed");
            } else {
                System.out.println("DSTU7624-" + pBlockSize + " Bug still exists");
            }

            /* Catch general exceptions */
        } catch (IllegalArgumentException | IllegalStateException | InvalidCipherTextException e) {
            System.out.println("DSTU7624-" + pBlockSize + " Bug still exists");
        }
    }
}
