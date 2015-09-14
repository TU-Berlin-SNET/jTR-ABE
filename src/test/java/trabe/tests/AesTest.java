package trabe.tests;

import static org.junit.Assert.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Arrays;

import org.junit.BeforeClass;
import org.junit.Test;

import trabe.*;
import trabe.aes.AesEncryption;

public class AesTest {

    private static SecureRandom random;

    @BeforeClass
    public static void testSetup() {
        random = new SecureRandom();
    }
    
    @Test
    public void testStreamingAES() throws AbeEncryptionException, IOException, DecryptionException {
        for (int i = 0; i < 100; i++) {
            int plainTextLength = random.nextInt(100) + 1;
            byte[] plaintext = new byte[plainTextLength];
            byte[] cpabeKey = new byte[1000];
            byte[] iv = new byte[16];

            random.nextBytes(plaintext);
            random.nextBytes(cpabeKey);
            random.nextBytes(iv);
            
            ByteArrayInputStream encInput = new ByteArrayInputStream(plaintext);
            ByteArrayOutputStream encOutput = new ByteArrayOutputStream();
            
            AesEncryption.encrypt(cpabeKey, null, iv, encInput, encOutput);
            byte[] ciphertext = encOutput.toByteArray();
            
            ByteArrayInputStream decInput = new ByteArrayInputStream(ciphertext);
            ByteArrayOutputStream decOutput = new ByteArrayOutputStream();
            AesEncryption.decrypt(cpabeKey, null, iv, decInput, decOutput);
            
            byte[] decryptedtext = decOutput.toByteArray();
            assertTrue(Arrays.equals(plaintext, decryptedtext));

        }
    }

    @Test
    public void testByteArrayAES() throws AbeEncryptionException, IOException, DecryptionException {
        for (int i = 0; i < 100; i++) {
            int plainTextLength = random.nextInt(100) + 1;
            byte[] plaintext = new byte[plainTextLength];
            byte[] cpabeKey = new byte[1000];
            byte[] iv = new byte[16];

            random.nextBytes(plaintext);
            random.nextBytes(cpabeKey);
            random.nextBytes(iv);

            byte[] ciphertext = AesEncryption.encrypt(cpabeKey, null, iv, plaintext);
            byte[] decryptedPlaintext = AesEncryption.decrypt(cpabeKey, null, iv, ciphertext);

            assertTrue(Arrays.equals(plaintext, decryptedPlaintext));
        }
    }
    
    //@Test
    public void readAfterABEFileTest() throws Exception {
    	// currently not working, difficult to do
        AbeSecretMasterKey smKey = Cpabe.setup();
        AbePublicKey pubKey = smKey.getPublicKey();

        int plainTextLength = random.nextInt(100) + 1;
        byte[] plaintext = new byte[plainTextLength];
        random.nextBytes(plaintext);
        
        String policy = "someAttribute1 and someAttribute2";

        AbeEncrypted encrypted = Cpabe.encrypt(pubKey, policy, plaintext);
        AbePrivateKey key = Cpabe.keygenSingle(smKey, "someAttribute1 someAttribute2");
        
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        encrypted.writeEncryptedFile(baos, pubKey);
        
        byte[] encryptedData = baos.toByteArray();
        byte[] encryptedDataPlusBytes = Arrays.copyOf(encryptedData, encryptedData.length + 3);
        encryptedDataPlusBytes[encryptedDataPlusBytes.length - 1] = 15;
        encryptedDataPlusBytes[encryptedDataPlusBytes.length - 2] = 10;
        encryptedDataPlusBytes[encryptedDataPlusBytes.length - 3] = 5;
        
        ByteArrayInputStream bais = new ByteArrayInputStream(encryptedDataPlusBytes);
        ByteArrayOutputStream decryptedStream = new ByteArrayOutputStream();
        Cpabe.decrypt(key, bais, decryptedStream);
        
        
        byte[] decryptedData = decryptedStream.toByteArray();
        assertTrue(Arrays.equals(plaintext, decryptedData));
        assertTrue(bais.read() == 5);
        assertTrue(bais.read() == 10);
        assertTrue(bais.read() == 15);
    }
}
