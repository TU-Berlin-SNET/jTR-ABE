package trabe.tests;

import static org.junit.Assert.*;

import org.junit.BeforeClass;
import org.junit.Test;
import trabe.*;
import trabe.policyparser.ParseException;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Arrays;

public class BlackBoxTest {

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

    @Test
    public void decryptionTest() throws IOException, AbeEncryptionException, ParseException, AbeDecryptionException {
        AbeSecretMasterKey smKey = Cpabe.setup(15);
        AbePublicKey pubKey = smKey.getPublicKey();

        byte[] data = getRandomData();

        String policy1 = "(att1 and att2) or att3";

        AbeEncrypted ct1 = Cpabe.encrypt(pubKey, policy1, data);
        AbeEncrypted ct2 = Cpabe.encrypt(pubKey, policy1, data);
        AbeEncrypted ct3 = Cpabe.encrypt(pubKey, policy1, data);

        String att1att2Attribute = "att1 att2";
        String att1Attribute = "att1";

        AbePrivateKey att1att2Key = Cpabe.keygenSingle(smKey, att1att2Attribute);
        AbePrivateKey att1Key = Cpabe.keygenSingle(smKey, att1Attribute);

        DecryptionBlackBox bb1 = new MockBlackBox(new AbePrivateKey[]{ att1att2Key, att1Key }, pubKey);
        DecryptionBlackBox bb2 = new MockBlackBox(new AbePrivateKey[]{ att1att2Key }, pubKey);
        DecryptionBlackBox bb3 = new MockBlackBox(new AbePrivateKey[]{ att1Key }, pubKey);

        assertTrue(Arrays.equals(data, bb1.decrypt(ct1)));

        assertTrue(Arrays.equals(data, bb2.decrypt(ct2)));

        assertNull(bb3.decrypt(ct3));
    }
}
