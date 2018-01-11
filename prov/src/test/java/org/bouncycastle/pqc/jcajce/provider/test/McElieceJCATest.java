package org.bouncycastle.pqc.jcajce.provider.test;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.McElieceCCA2KeyGenParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.McElieceKeyGenParameterSpec;

/**
 * Test for McEliece JCE bugs.
 */
public class McElieceJCATest {
    /**
     * McEliece algorithm.
     */
    private static final String MCELIECE_ALGO = "McEliece";

    /**
     * McEliece-CCA2 algorithm.
     */
    private static final String MCELIECECCA2_ALGO = "McEliece-CCA2";

    /**
     * Note the post quantum provider.
     */
    private static final Provider BCPQPROV = new BouncyCastlePQCProvider();

    /**
     * Run Tests.
     * @param pArgs arguments
     */
    public static void main(final String[] pArgs) {
        TestMcElieceInit();
        TestMcElieceCCA2Init();
        TestMcElieceKeySpec();
        TestMcElieceCCA2KeySpec();
    }

    /**
     * Test McEliece Init.
     */
    private static void TestMcElieceInit() {
        /* Catch Exceptions */
        try {
            /* Create and initialise the generator */
            KeyPairGenerator myGenerator = KeyPairGenerator.getInstance(MCELIECE_ALGO, BCPQPROV);
            McElieceKeyGenParameterSpec mySpec = new McElieceKeyGenParameterSpec(McElieceKeyGenParameterSpec.DEFAULT_M,
                    McElieceKeyGenParameterSpec.DEFAULT_T);
            myGenerator.initialize(mySpec, new SecureRandom());

            /*
             * Generate the keyPair. This will generate a NullPointerException since the version of
             * initialise used is a NoOp
             */
            myGenerator.generateKeyPair();
            System.out.println("McElieceCCA2 init Bug fixed");

            /* Catch Null Pointer Exception */
        } catch (NullPointerException e) {
            System.out.println("McEliece init Bug still exists");
            // e.printStackTrace();

            /* Catch general exceptions */
        } catch (NoSuchAlgorithmException
                | InvalidAlgorithmParameterException e) {
            System.out.println("Failed to create generator");
            e.printStackTrace();
        }
    }

    /**
     * Test McElieceCCA2 Init.
     */
    private static void TestMcElieceCCA2Init() {
        /* Catch Exceptions */
        try {
            /* Create and initialise the generator */
            KeyPairGenerator myGenerator = KeyPairGenerator.getInstance(MCELIECECCA2_ALGO, BCPQPROV);
            McElieceCCA2KeyGenParameterSpec mySpec = new McElieceCCA2KeyGenParameterSpec(McElieceCCA2KeyGenParameterSpec.DEFAULT_M,
                    McElieceCCA2KeyGenParameterSpec.DEFAULT_T, McElieceCCA2KeyGenParameterSpec.SHA512);
            myGenerator.initialize(mySpec, new SecureRandom());

            /*
             * Generate the keyPair. This will generate a NullPointerException since the version of
             * initialise used is a NoOp
             */
            myGenerator.generateKeyPair();
            System.out.println("McElieceCCA2 init Bug fixed");

            /* Catch Null Pointer Exception */
        } catch (NullPointerException e) {
            System.out.println("McElieceCCA2 init Bug still exists");
            // e.printStackTrace();

            /* Catch general exceptions */
        } catch (NoSuchAlgorithmException
                | InvalidAlgorithmParameterException e) {
            System.out.println("Failed to create generator");
            e.printStackTrace();
        }
    }

    /**
     * Test McEliece KeySpec.
     */
    private static void TestMcElieceKeySpec() {
        /* Catch Exceptions */
        try {
            /* Create and initialise the generator */
            KeyPairGenerator myGenerator = KeyPairGenerator.getInstance(MCELIECE_ALGO, BCPQPROV);
            myGenerator.initialize(McElieceKeyGenParameterSpec.DEFAULT_M, new SecureRandom());

            /* Generate the keyPair. */
            KeyPair myPair = myGenerator.generateKeyPair();

            /* Create the Factory */
            KeyFactory myFactory = KeyFactory.getInstance(MCELIECE_ALGO, BCPQPROV);

            /* Access KeySpecs. This will return NULL keys since the call has not been coded */
            PKCS8EncodedKeySpec myPrivateSpec = myFactory.getKeySpec(myPair.getPrivate(), PKCS8EncodedKeySpec.class);
            X509EncodedKeySpec myPublicSpec = myFactory.getKeySpec(myPair.getPublic(), X509EncodedKeySpec.class);
            if ((myPrivateSpec != null) && (myPublicSpec != null)) {
                System.out.println("McEliece keySpec Bug fixed");
            } else {
                System.out.println("McEliece keySpec Bug still exists");
            }

            /* Translate Keys. This will return NULL keys since the call has not been coded */
            Key myPrivate = myFactory.translateKey(myPair.getPrivate());
            Key myPublic = myFactory.translateKey(myPair.getPublic());
            if ((myPrivate != null) && (myPublic != null)) {
                System.out.println("McEliece translate Bug fixed");
            } else {
                System.out.println("McEliece translate Bug still exists");
            }

            /* Catch general exceptions */
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Failed to create generator");
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            System.out.println("Failed to obtain keySpec");
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            System.out.println("Failed to translate key");
            e.printStackTrace();
        }
    }

    /**
     * Test McElieceCCA2 KeySpec.
     */
    private static void TestMcElieceCCA2KeySpec() {
        /* Catch Exceptions */
        try {
            /* Create and initialise the generator */
            KeyPairGenerator myGenerator = KeyPairGenerator.getInstance(MCELIECECCA2_ALGO, BCPQPROV);
            myGenerator.initialize(McElieceCCA2KeyGenParameterSpec.DEFAULT_M, new SecureRandom());

            /* Generate the keyPair. */
            KeyPair myPair = myGenerator.generateKeyPair();

            /* Create the Factory */
            KeyFactory myFactory = KeyFactory.getInstance(MCELIECECCA2_ALGO, BCPQPROV);

            /* Access KeySpecs. This will return NULL keys since the call has not been coded */
            PKCS8EncodedKeySpec myPrivateSpec = myFactory.getKeySpec(myPair.getPrivate(), PKCS8EncodedKeySpec.class);
            X509EncodedKeySpec myPublicSpec = myFactory.getKeySpec(myPair.getPublic(), X509EncodedKeySpec.class);
            if ((myPrivateSpec != null) && (myPublicSpec != null)) {
                System.out.println("McElieceCCA2 keySpec Bug fixed");
            } else {
                System.out.println("McElieceCCA2 keySpec Bug still exists");
            }

            /* Translate Keys. This will return NULL keys since the call has not been coded */
            Key myPrivate = myFactory.translateKey(myPair.getPrivate());
            Key myPublic = myFactory.translateKey(myPair.getPublic());
            if ((myPrivate != null) && (myPublic != null)) {
                System.out.println("McElieceCCA2 translate Bug fixed");
            } else {
                System.out.println("McElieceCCA2 translate Bug still exists");
            }

            /* Catch general exceptions */
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Failed to create generator");
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            System.out.println("Failed to obtain keySpec");
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            System.out.println("Failed to translate key");
            e.printStackTrace();
        }
    }
}
