package trabe.tests;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.security.SecureRandom;
import java.util.Arrays;

import org.junit.BeforeClass;

import trabe.AbeEncrypted;
import trabe.AbePrivateKey;
import trabe.AbePublicKey;
import trabe.AbeSecretMasterKey;
import trabe.Cpabe;
import trabe.CpabeWeber;

public class WeberTest {
    private static SecureRandom random;
	
    @BeforeClass
    public static void testSetup() {
        random = new SecureRandom();
    }

    public byte[] getRandomData() {
        byte[] data = new byte[random.nextInt(100) + 20];
        random.nextBytes(data);
        return data;
    }

    // so we dont need to check for exceptions every time we want to decrypt
    private byte[] decrypt(AbePrivateKey privateKey, AbeEncrypted encryptedData, byte[] lbeKey) {
        try {
            return CpabeWeber.decrypt(privateKey, encryptedData, lbeKey);
        } catch (Exception e) {
            return null;
        }
    }
    
    //@Test
    public void numberTest() throws Exception {
        AbeSecretMasterKey smKey = CpabeWeber.setup();
        AbePublicKey pubKey = smKey.getPublicKey();

        byte[] data = getRandomData();
        String policy = "trivial and to and decrypt";
        
        byte[] lbeKey1 = new byte[16];
        random.nextBytes(lbeKey1);
        
        byte[] lbeKey2 = new byte[16];
        random.nextBytes(lbeKey2);

        // each AbeEncrypted can only be decrypted once, since we advance the stream to after the AES data.
        AbeEncrypted withFirstLbeKey1 = CpabeWeber.encrypt(pubKey, policy, data, lbeKey1);
        AbeEncrypted withFirstLbeKey2 = CpabeWeber.encrypt(pubKey, policy, data, lbeKey1);
        AbeEncrypted withSecondLbeKey1 = CpabeWeber.encrypt(pubKey, policy, data, lbeKey2);
        AbeEncrypted withSecondLbeKey2 = CpabeWeber.encrypt(pubKey, policy, data, lbeKey2);
        
        String allAttributes = "trivial to decrypt";
        AbePrivateKey allKey = Cpabe.keygenSingle(smKey, allAttributes);

        assertTrue(Arrays.equals(data, decrypt(allKey, withFirstLbeKey1, lbeKey1)));
        assertFalse(Arrays.equals(data, decrypt(allKey, withFirstLbeKey2, lbeKey2)));
        assertFalse(Arrays.equals(data, decrypt(allKey, withSecondLbeKey1, lbeKey1)));
        assertTrue(Arrays.equals(data, decrypt(allKey, withSecondLbeKey2, lbeKey2)));
    }
}
