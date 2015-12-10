package trabe.tests;

import static org.junit.Assert.*;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.*;

import it.unisa.dia.gas.jpbc.Element;
import org.bouncycastle.util.encoders.Base64;
import org.junit.BeforeClass;
import org.junit.Test;

import trabe.*;
import trabe.lw14.*;

public class Lw14Test {

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
    private byte[] decrypt(AbePrivateKey privateKey, AbeEncrypted encryptedData) {
        try {
            return Cpabe.decrypt(privateKey, encryptedData);
        } catch (Exception e) {
            return null;
        }
    }

    @Test
    public void addAttributesTest() throws Exception {
        AbeSecretMasterKey smKey = Cpabe.setup();
        AbePublicKey pubKey = smKey.getPublicKey();

        byte[] data = getRandomData();

        String policy1 = "(att1 and att2) or att3";
        String policy2 = "att3 or att4 >= 5";

        AbeEncrypted policy1EncryptedTest1 = Cpabe.encrypt(pubKey, policy1, data);
        AbeEncrypted policy2EncryptedTest1 = Cpabe.encrypt(pubKey, policy2, data);
        
        AbeEncrypted policy1EncryptedTest2 = Cpabe.encrypt(pubKey, policy1, data);
        AbeEncrypted policy2EncryptedTest2 = Cpabe.encrypt(pubKey, policy2, data);
        
        AbeEncrypted policy1EncryptedTest3 = Cpabe.encrypt(pubKey, policy1, data);
        AbeEncrypted policy2EncryptedTest3 = Cpabe.encrypt(pubKey, policy2, data);
        
        AbeEncrypted policy1EncryptedTest4 = Cpabe.encrypt(pubKey, policy1, data);
        AbeEncrypted policy2EncryptedTest4 = Cpabe.encrypt(pubKey, policy2, data);
        
        AbeEncrypted policy1EncryptedTest5 = Cpabe.encrypt(pubKey, policy1, data);
        AbeEncrypted policy2EncryptedTest5 = Cpabe.encrypt(pubKey, policy2, data);

        String att1att2Attribute = "att1 att2";
        String att1Attribute = "att1";

        Pair<Element, Integer> preKey1 = Cpabe.preKeygen(smKey);
        Pair<Element, Integer> preKey2 = Cpabe.preKeygen(smKey);

        AbePrivateKey att1att2Key = Cpabe.keygen(smKey, att1att2Attribute, preKey1);
        AbePrivateKey att1Key = Cpabe.keygen(smKey, att1Attribute, preKey2);

        byte[] dec1 = Cpabe.decrypt(att1att2Key, policy1EncryptedTest1);
        assertTrue(Arrays.equals(data, dec1));
        assertFalse(Arrays.equals(data, decrypt(att1att2Key, policy2EncryptedTest1)));
        
        assertFalse(Arrays.equals(data, decrypt(att1Key, policy1EncryptedTest2)));
        assertFalse(Arrays.equals(data, decrypt(att1Key, policy2EncryptedTest2)));


        AbePrivateKey att1att2att3Key = att1att2Key.merge(Cpabe.keygen(smKey, "att3", preKey1));
        AbePrivateKey att1att3Key = att1Key.merge(Cpabe.keygen(smKey, "att3", preKey2));
        AbePrivateKey att1att4Key = att1Key.merge(Cpabe.keygen(smKey, "att4=42", preKey2));

        assertTrue(Arrays.equals(data, decrypt(att1att2att3Key, policy1EncryptedTest3)));
        assertTrue(Arrays.equals(data, decrypt(att1att2att3Key, policy2EncryptedTest3)));

        assertTrue(Arrays.equals(data, decrypt(att1att3Key, policy1EncryptedTest4)));
        assertTrue(Arrays.equals(data, decrypt(att1att3Key, policy2EncryptedTest4)));

        assertFalse(Arrays.equals(data, decrypt(att1att4Key, policy1EncryptedTest5)));
        assertTrue(Arrays.equals(data, decrypt(att1att4Key, policy2EncryptedTest5)));
    }

    @Test
    public void cipherTextSerializationTest() throws Exception {
        File folder = TestUtil.prepareTestFolder();

        AbeSecretMasterKey msk = Cpabe.setup(2);
        AbePublicKey pub = msk.getPublicKey();

        AbeSecretMasterKey mskClone = AbeSecretMasterKey.readFromByteArray(msk.getAsByteArray());
        AbePublicKey pubClone = AbePublicKey.readFromByteArray(pub.getAsByteArray());

        assertEquals(msk, mskClone);
        assertEquals(pub, pubClone);

        String policy1 = "(att1 and att2) or att3";

        AbeEncrypted enc = Cpabe.encrypt(pub, policy1, getRandomData());
        CipherText cto = enc.getCipher();

        CipherText ctc = CipherText.readFromByteArray(cto.getAsByteArray(pub), pub);

        assertEquals(cto, ctc);

        File ctFile = new File(folder, "ct.dat");

        AbeOutputStream out = new AbeOutputStream(new FileOutputStream(ctFile), pub);
        cto.writeToStream(out);
        out.flush();
        out.close();

        AbeInputStream in = new AbeInputStream(new FileInputStream(ctFile), pub);
        CipherText ctr = CipherText.readFromStream(in);
        in.close();

        assertEquals(cto, ctr);
    }

    @Test
    public void encryptDecryptTestWithFiles() throws Exception {
        File folder = TestUtil.prepareTestFolder();
        File mskFile = new File(folder, "msk.dat");
        File pubFile = new File(folder, "pub.dat");

        Cpabe.setup(pubFile, mskFile);

        AbePublicKey pub = AbePublicKey.readFromFile(pubFile);
        assertNotNull(pub);

        String policy1 = "(att1 and att2) or att3";

        File data1File = TestUtil.randomData();
        File enc1File = new File(folder, "enc1.dat");
        Cpabe.encrypt(pubFile, policy1, data1File, enc1File);

        AbeEncrypted ct = AbeEncrypted.readFromFile(pub, enc1File);
        assertNotNull(ct);

        String att1att2Attribute = "att1 att2";
        String att1Attribute = "att1";

        File private1File = new File(folder, "private1.dat");
        Cpabe.keygenSingle(private1File, mskFile, att1att2Attribute);

        File decrypted1File = new File(folder, "dec1.dat");
        Cpabe.decrypt(private1File, enc1File, decrypted1File);

        assertTrue(Arrays.equals(TestUtil.read(data1File), TestUtil.read(decrypted1File)));

        File secretComponentFile = new File(folder, "usk1.dat");
        Cpabe.preKeygen(mskFile, secretComponentFile);

        File private2File = new File(folder, "private2.dat");
        Cpabe.keygen(private2File, mskFile, att1att2Attribute, secretComponentFile);

        File decrypted2File = new File(folder, "dec2.dat");
        Cpabe.decrypt(private1File, enc1File, decrypted2File);

        assertTrue(Arrays.equals(TestUtil.read(data1File), TestUtil.read(decrypted2File)));
    }

    @Test
    public void setupAndObjectTestWithFiles() throws Exception {
        File folder = TestUtil.prepareTestFolder();
        File mskFile = new File(folder, "msk.dat");
        File pubFile = new File(folder, "pub.dat");

        Cpabe.setup(7, pubFile, mskFile);

        AbeSecretMasterKey msk = AbeSecretMasterKey.readFromFile(mskFile);
        AbeSecretMasterKey msk2 = Cpabe.setup(7);

        assertEquals(msk, msk);
        assertNotEquals(msk, 1);
        assertNotEquals(msk, null);
        assertNotEquals(msk, msk2);

        assertEquals(msk.getPublicKey(), msk.getPublicKey());
        assertNotEquals(msk.getPublicKey(), 1);
        assertNotEquals(msk.getPublicKey(), null);
        assertNotEquals(msk.getPublicKey(), msk2.getPublicKey());
    }

    @Test
    public void encryptDecryptTest() throws Exception {
        LinkedHashMap<String, LinkedHashMap<String, Boolean>> testVectors = new LinkedHashMap<String, LinkedHashMap<String, Boolean>>();

        LinkedHashMap<String, Boolean> vector;

        vector = new LinkedHashMap<String, Boolean>();
        vector.put("att1=5", false);
        vector.put("att1=6", true);
        vector.put("att1=623234", true);
        testVectors.put("att1>5", vector);

        vector = new LinkedHashMap<String, Boolean>();
        vector.put("att1=0", true);
        vector.put("att1=1", true);
        vector.put("att1=65336", true);
        vector.put("att1=65337", false);
        vector.put("att1=65338", false);
        vector.put("att1=65339", false);
        testVectors.put("att1<=65336", vector);

        vector = new LinkedHashMap<String, Boolean>();
        vector.put("att1=4", false);
        vector.put("att1=5", false);
        vector.put("att1=6", true);
        vector.put("att1=7", true);
        vector.put("att1=8", false);
        vector.put("att1=9", false);
        vector.put("att1=623234", false);
        testVectors.put("att1>5 and att1<8", vector);

        vector = new LinkedHashMap<String, Boolean>();
        vector.put("att1=5 att2=70", false);
        vector.put("att1=5 att2=70 att3", true);
        vector.put("att1=6 att3", true);
        vector.put("att1=6 att2=70", true);
        vector.put("att1=4 att2=80 att3", false);
        testVectors.put("2 of (att1>5, att2<75, att3)", vector);

        vector = new LinkedHashMap<String, Boolean>();
        vector.put("att1", true);
        vector.put("att2", false);
        testVectors.put("att1", vector);

        vector = new LinkedHashMap<String, Boolean>();
        vector.put("att1 att2", true);
        vector.put("att1", false);
        vector.put("att2", false);
        testVectors.put("att1 and att2", vector);

        vector = new LinkedHashMap<String, Boolean>();
        vector.put("att1 att2", true);
        vector.put("att1 att3", true);
        vector.put("att2 att3", true);
        vector.put("att1", false);
        vector.put("att2", false);
        vector.put("att3", true);
        vector.put("att1 att2 att3", true);
        testVectors.put("(att1 and att2) or att3", vector);

        vector = new LinkedHashMap<String, Boolean>();
        vector.put("att1 att2", true);
        vector.put("att1 att3", true);
        vector.put("att2 att3", true);
        vector.put("att1", false);
        vector.put("att2", false);
        vector.put("att1 att4", false);
        vector.put("att1 att5", false);
        vector.put("att1 att4 att5", true);
        vector.put("att3", true);
        vector.put("att1 att2 att3", true);
        vector.put("att1 att2 att3 att4 att5", true);
        testVectors.put("(att1 and (att2 or (att4 and att5))) or att3", vector);

        vector = new LinkedHashMap<String, Boolean>();
        vector.put("att1 att2", true);
        vector.put("att1 att3", true);
        vector.put("att2 att3", true);
        vector.put("att1", false);
        vector.put("att2", false);
        vector.put("att3", false);
        vector.put("att1 att2 att3", true);
        testVectors.put("2 of (att1, att2, att3)", vector);

        vector = new LinkedHashMap<String, Boolean>();
        vector.put("att1 att2", false);
        vector.put("att1 att3", false);
        vector.put("att2 att3", false);
        vector.put("att1 att2 att3", true);
        vector.put("att1 att4", true);
        vector.put("att1 att3 att4", true);
        vector.put("att1 att2 att3 att4", true);
        testVectors.put("2 of (att1, (att2 and att3), att4)", vector);

        AbeSecretMasterKey msk = Cpabe.setup(100);
        // System.out.println("PK: " + Base64.toBase64String(msk.getPublicKey().getAsByteArray()));

        for(Map.Entry<String, LinkedHashMap<String, Boolean>> policy : testVectors.entrySet()) {
            System.out.println("Policy: " + policy.getKey());

            byte[] data = getRandomData();
            AbeEncrypted enc = Cpabe.encrypt(msk.getPublicKey(), policy.getKey(), data);
            assertNotNull(enc);

            byte[] encData = enc.writeEncryptedData(msk.getPublicKey());

            for(Map.Entry<String, Boolean> privateKey : policy.getValue().entrySet()) {
                System.out.println("Private key attributes: " + privateKey.getKey());

                AbePrivateKey pk = Cpabe.keygenSingle(msk, privateKey.getKey());
                assertNotNull(pk);

                AbeEncrypted encCopy = AbeEncrypted.read(encData, msk.getPublicKey());
                assertNotNull(encCopy);

                boolean success = false;
                boolean failed = false;
                try {
                    byte[] decData = encCopy.writeDecryptedData(pk);
                    success = Arrays.equals(data, decData);
                } catch (AbeDecryptionException e) {
                    //e.printStackTrace();
                    failed = true;
                }
                System.out.println("should success: " + privateKey.getValue() + " is success: " + success + " has failed: " + failed);
                if (privateKey.getValue()) {
                    assertTrue(success && !failed);
                } else {
                    assertFalse(success && failed);
                }
            }
        }
    }

    @Test
    public void userCeilingTest() {
        HashMap<Integer, Integer> testCases = new HashMap<Integer, Integer>();
        testCases.put(2, 4);
        testCases.put(3, 4);
        testCases.put(4, 9);
        testCases.put(8, 9);
        testCases.put(9, 16);
        testCases.put(15, 16);
        testCases.put(16, 25);
        testCases.put(24, 25);
        testCases.put(25, 36);

        for (Map.Entry<Integer, Integer> testCase : testCases.entrySet()) {
            int usersSqrt = (int)(Math.ceil(Math.sqrt(testCase.getKey()+1)));
            int users = usersSqrt * usersSqrt;
            // System.out.println("in: " + testCase.getKey() + ", out: " + users + ", expected out: " + testCase.getValue());
            assertEquals((Integer)users, testCase.getValue());
        }
    }

    @Test
    public void encryptDecryptRevokedTest() throws Exception {
        LinkedHashMap<String, LinkedHashMap<String, Boolean>> testVectors = new LinkedHashMap<String, LinkedHashMap<String, Boolean>>();

        LinkedHashMap<String, Boolean> vector;

        vector = new LinkedHashMap<String, Boolean>();
        vector.put("att1 att2", true);
        testVectors.put("att1 and att2", vector);

        vector = new LinkedHashMap<String, Boolean>();
        vector.put("att1 att2", true);
        vector.put("att1 att3", true);
        vector.put("att2 att3", true);
        vector.put("att3", true);
        vector.put("att1 att2 att3", true);
        testVectors.put("(att1 and att2) or att3", vector);

        vector = new LinkedHashMap<String, Boolean>();
        vector.put("att1 att2", true);
        vector.put("att1 att3", true);
        vector.put("att2 att3", true);
        vector.put("att1 att4 att5", true);
        vector.put("att3", true);
        vector.put("att1 att2 att3", true);
        vector.put("att1 att2 att3 att4 att5", true);
        testVectors.put("(att1 and (att2 or (att4 and att5))) or att3", vector);

        AbeSecretMasterKey msk = Cpabe.setup(100);

        byte[] data = getRandomData();

        for(Map.Entry<String, LinkedHashMap<String, Boolean>> policy : testVectors.entrySet()) {
            System.out.println("Policy: " + policy.getKey());

            for(Map.Entry<String, Boolean> privateKey : policy.getValue().entrySet()) {
                System.out.println("Private key attributes: " + privateKey.getKey());

                AbePrivateKey privateKeyNonRevoked1 = Cpabe.keygenSingle(msk, privateKey.getKey());
                AbePrivateKey privateKeyRevoked = Cpabe.keygenSingle(msk, privateKey.getKey());
                AbePrivateKey privateKeyNonRevoked2 = Cpabe.keygenSingle(msk, privateKey.getKey());

                AbeEncrypted enc = Cpabe.encrypt(msk.getPublicKey(), policy.getKey(), data,
                        new int[]{ privateKeyRevoked.position.counter });
                assertNotNull(enc);

                byte[] ciphertextCopy = enc.writeEncryptedData(msk.getPublicKey());

                byte[] plaintext = Cpabe.decrypt(privateKeyNonRevoked1, AbeEncrypted.read(ciphertextCopy, msk.getPublicKey()));
                assertNotNull(plaintext);
                assertTrue(Arrays.equals(data, plaintext));

                boolean exceptionThrown = false;
                plaintext = new byte[0];
                try {
                    plaintext = Cpabe.decrypt(privateKeyRevoked, AbeEncrypted.read(ciphertextCopy, msk.getPublicKey()));
                } catch (DecryptionException e) {
                    exceptionThrown = true;
                }
                assertFalse(Arrays.equals(data, plaintext));
                assertTrue(exceptionThrown);

                plaintext = Cpabe.decrypt(privateKeyNonRevoked2, AbeEncrypted.read(ciphertextCopy, msk.getPublicKey()));
                assertNotNull(plaintext);
                assertTrue(Arrays.equals(data, plaintext));
            }
        }
    }

    @Test
    public void encryptDecryptAttributeReuseTest() throws Exception {
        AbeSecretMasterKey msk = Cpabe.setup(2);

        String policy1 = "(att1 and att2) or (att1 and att3)";

        byte[] data = getRandomData();
        AbeEncrypted enc = Cpabe.encrypt(msk.getPublicKey(), policy1, data);
        assertNotNull(enc);

        byte[] encData = enc.writeEncryptedData(msk.getPublicKey());

        String att1att2Attribute = "att1 att2";
        String att1att3Attribute = "att1 att3";
        String att3att2Attribute = "att3 att2";

        AbePrivateKey priv1 = Cpabe.keygenSingle(msk, att1att2Attribute);
        AbePrivateKey priv2 = Cpabe.keygenSingle(msk, att1att3Attribute);
        AbePrivateKey priv3 = Cpabe.keygenSingle(msk, att3att2Attribute);

        AbeEncrypted encCopy = AbeEncrypted.read(encData, msk.getPublicKey());
        byte[] decData = encCopy.writeDecryptedData(priv1);
        assertTrue(Arrays.equals(data, decData));

        encCopy = AbeEncrypted.read(encData, msk.getPublicKey());
        decData = encCopy.writeDecryptedData(priv2);
        assertTrue(Arrays.equals(data, decData));

        boolean exceptionThrown = false;
        try {
            encCopy = AbeEncrypted.read(encData, msk.getPublicKey());
            decData = encCopy.writeDecryptedData(priv3);
        } catch (AbeDecryptionException e) {
            exceptionThrown = true;
        }

        assertTrue(exceptionThrown);
    }

    @Test
    public void privateKeyMergeTest() throws Exception {
        AbeSecretMasterKey msk = Cpabe.setup(2);

        String policy1 = "(att1 and att2) or att3";

        byte[] data = getRandomData();
        AbeEncrypted enc1 = Cpabe.encrypt(msk.getPublicKey(), policy1, data);
        assertNotNull(enc1);

        byte[] encData = enc1.writeEncryptedData(msk.getPublicKey());

        AbeEncrypted enc2 = AbeEncrypted.read(encData, msk.getPublicKey());

        assertNotNull(enc2);

        String att1att2Attribute = "att1 att2";
        String att4Attribute = "att4";

        Pair<Element, Integer> secret = Cpabe.preKeygen(msk);

        AbePrivateKey priv1 = Cpabe.keygen(msk, att1att2Attribute, secret);
        AbePrivateKey priv2 = Cpabe.keygen(msk, att4Attribute, secret);

        assertEquals(2, priv1.getComponents().size());
        assertEquals(1, priv2.getComponents().size());

        AbePrivateKey privMerge = priv1.merge(priv2);

        assertNotNull(privMerge);
        assertEquals(3, privMerge.getComponents().size());

        byte[] dec2Data = enc2.writeDecryptedData(privMerge);

        assertTrue(Arrays.equals(data, dec2Data));

        assertTrue(privMerge.equals(AbePrivateKey.readFromByteArray(privMerge.getAsByteArray())));
    }

    @Test
    public void userIndexTest() {
        AbeUserIndex i1 = new AbeUserIndex(4, 0);
        assertEquals(0, i1.i);
        assertEquals(0, i1.j);
        assertEquals(4, i1.m);

        assertEquals(i1, i1);

        AbeUserIndex i2 = new AbeUserIndex(i1.i, i1.j, i1.m);

        assertEquals(i1, i2);
        assertEquals(0, i2.counter);

        i1 = new AbeUserIndex(4, 9);
        assertEquals(2, i1.i);
        assertEquals(1, i1.j);
        assertEquals(4, i1.m);

        i2 = new AbeUserIndex(i1.i, i1.j, i1.m);

        assertEquals(i1, i2);
        assertEquals(9, i2.counter);

        // negative tests...
        i1 = new AbeUserIndex(4, 0);
        i2 = new AbeUserIndex(5, 0);

        assertNotEquals(i1, i2);
        assertNotEquals(i1, 4);
        assertNotEquals(i1, null);

        i1 = new AbeUserIndex(4, 0);
        i2 = new AbeUserIndex(4, 1);

        assertNotEquals(i1, i2);
    }

    @Test
    public void treeSatisfaction() throws Exception {
        AbePublicKey publicKey = Cpabe.setup(100).getPublicKey();

        LinkedHashMap<String, LinkedHashMap<String, Boolean>> testVectors = new LinkedHashMap<String, LinkedHashMap<String, Boolean>>();

        LinkedHashMap<String, Boolean> vector;
        vector = new LinkedHashMap<String, Boolean>();
        vector.put("att1 att2", true);
        vector.put("att1 att3", true);
        vector.put("att2 att3", true);
        vector.put("att1", false);
        vector.put("att2", false);
        vector.put("att3", true);
        vector.put("att1 att2 att3", true);
        testVectors.put("(att1 and att2) or att3", vector);

        vector = new LinkedHashMap<String, Boolean>();
        vector.put("att1 att2", true);
        vector.put("att1 att3", true);
        vector.put("att2 att3", true);
        vector.put("att1", false);
        vector.put("att2", false);
        vector.put("att1 att4", false);
        vector.put("att1 att5", false);
        vector.put("att1 att4 att5", true);
        vector.put("att3", true);
        vector.put("att1 att2 att3", true);
        vector.put("att1 att2 att3 att4 att5", true);
        testVectors.put("(att1 and (att2 or (att4 and att5))) or att3", vector);

        vector = new LinkedHashMap<String, Boolean>();
        vector.put("att1 att2", true);
        vector.put("att1 att3", true);
        vector.put("att2 att3", true);
        vector.put("att1", false);
        vector.put("att2", false);
        vector.put("att3", false);
        vector.put("att1 att2 att3", true);
        testVectors.put("2 of (att1, att2, att3)", vector);

        vector = new LinkedHashMap<String, Boolean>();
        vector.put("att1 att2", false);
        vector.put("att1 att3", false);
        vector.put("att2 att3", false);
        vector.put("att1 att2 att3", true);
        vector.put("att1 att4", true);
        vector.put("att1 att3 att4", true);
        vector.put("att1 att2 att3 att4", true);
        testVectors.put("2 of (att1, (att2 and att3), att4)", vector);

        for(Map.Entry<String, LinkedHashMap<String, Boolean>> policy : testVectors.entrySet()) {
            System.out.println("Policy: " + policy.getKey());

            for(Map.Entry<String, Boolean> privateKey : policy.getValue().entrySet()) {
                System.out.println("Private key attributes: " + privateKey.getKey());

                Set<String> attributes = new HashSet<String>();
                for(String attr : privateKey.getKey().split(" ")) {
                    attributes.add(attr);
                }

                assertEquals(privateKey.getValue(), Lw14Util.satisfies(policy.getKey(), attributes, publicKey));
            }
        }
    }

    @Test
    public void pascalRowTest() throws Exception {
        long[][] a = new long[][]{
                new long[]{ 1 },
                new long[]{ 1, 1 },
                new long[]{ 1, 2, 1 },
                new long[]{ 1, 3, 3, 1 },
                new long[]{ 1, 4, 6, 4, 1 },
        };
        for(int i = 0; i < a.length; i++) {
            assertTrue(Arrays.equals(a[i], Lw14Util.getPascalRow(i+1)));
        }
    }

    @Test
    public void nextLongPermutationTest() throws Exception {
        long value = 3;
        Long[] expectedResults = new Long[]{
                5L,
                6L,
                9L,
                10L,
                12L,
                17L
        };
        for (Long expectedResult : expectedResults) {
            long result = Lw14Util.getNextLexicographicalPermutation(value);
            assertTrue(expectedResult.equals(result));
            value = result;
        }

        BigInteger bigValue = BigInteger.valueOf(3);
        for (Long expectedResult : expectedResults) {
            BigInteger result = Lw14Util.getNextLexicographicalPermutation(bigValue);
            assertTrue(BigInteger.valueOf(expectedResult).equals(result));
            bigValue = result;
        }
    }

    @Test
    public void powerSetIteratorTest() throws Exception {
        Set<Integer> set = new HashSet<Integer>();
        set.add(2);
        set.add(4);
        set.add(5);

        SortedPowerSetIterator<Integer> iterator = new SortedPowerSetIterator<Integer>(set);
        assertTrue(iterator.hasNext());
        assertTrue(iterator.next().size() == 0);
        assertTrue(iterator.hasNext());
        assertTrue(iterator.next().size() == 1);
        assertTrue(iterator.hasNext());
        assertTrue(iterator.next().size() == 1);
        assertTrue(iterator.hasNext());
        assertTrue(iterator.next().size() == 1);
        assertTrue(iterator.hasNext());
        assertTrue(iterator.next().size() == 2);
        assertTrue(iterator.hasNext());
        assertTrue(iterator.next().size() == 2);
        assertTrue(iterator.hasNext());
        assertTrue(iterator.next().size() == 2);
        assertTrue(iterator.hasNext());
        assertTrue(iterator.next().size() == 3);
        assertFalse(iterator.hasNext());
    }

    @Test
    public void numberTest() throws Exception {
        AbeSecretMasterKey smKey = Cpabe.setup();
        AbePublicKey pubKey = smKey.getPublicKey();

        byte[] data = getRandomData();
        int number = random.nextInt(100) + 20; // 20-119
        String greaterPolicy = "someNumber > " + number;
        String greaterEqPolicy = "someNumber >= " + number;
        String smallerPolicy = "someNumber < " + number;
        String smallerEqPolicy = "someNumber <= " + number;

        // each AbeEncrypted can only be decrypted once, since we advance the stream to after the AES data.
        AbeEncrypted greaterEncryptedTest1 = Cpabe.encrypt(pubKey, greaterPolicy, data);
        AbeEncrypted greaterEqEncryptedTest1 = Cpabe.encrypt(pubKey, greaterEqPolicy, data);
        AbeEncrypted smallerEncryptedTest1 = Cpabe.encrypt(pubKey, smallerPolicy, data);
        AbeEncrypted smallerEqEncryptedTest1 = Cpabe.encrypt(pubKey, smallerEqPolicy, data);
        
        AbeEncrypted greaterEncryptedTest2 = Cpabe.encrypt(pubKey, greaterPolicy, data);
        AbeEncrypted greaterEqEncryptedTest2 = Cpabe.encrypt(pubKey, greaterEqPolicy, data);
        AbeEncrypted smallerEncryptedTest2 = Cpabe.encrypt(pubKey, smallerPolicy, data);
        AbeEncrypted smallerEqEncryptedTest2 = Cpabe.encrypt(pubKey, smallerEqPolicy, data);
        
        AbeEncrypted greaterEncryptedTest3 = Cpabe.encrypt(pubKey, greaterPolicy, data);
        AbeEncrypted greaterEqEncryptedTest3 = Cpabe.encrypt(pubKey, greaterEqPolicy, data);
        AbeEncrypted smallerEncryptedTest3 = Cpabe.encrypt(pubKey, smallerPolicy, data);
        AbeEncrypted smallerEqEncryptedTest3 = Cpabe.encrypt(pubKey, smallerEqPolicy, data);

        String greaterAttribute = "someNumber = " + Integer.toString(number + 1);
        String smallerAttribute = "someNumber = " + Integer.toString(number - 1);
        String equalAttribute = "someNumber = " + Integer.toString(number);

        AbePrivateKey greaterKey = Cpabe.keygenSingle(smKey, greaterAttribute);
        AbePrivateKey smallerKey = Cpabe.keygenSingle(smKey, smallerAttribute);
        AbePrivateKey equalKey = Cpabe.keygenSingle(smKey, equalAttribute);

        // greaterKey
        assertTrue(Arrays.equals(data, decrypt(greaterKey, greaterEncryptedTest1)));
        assertTrue(Arrays.equals(data, decrypt(greaterKey, greaterEqEncryptedTest1)));
        assertFalse(Arrays.equals(data, decrypt(greaterKey, smallerEncryptedTest1)));
        assertFalse(Arrays.equals(data, decrypt(greaterKey, smallerEqEncryptedTest1)));

        // smallerKey
        assertFalse(Arrays.equals(data, decrypt(smallerKey, greaterEncryptedTest2)));
        assertFalse(Arrays.equals(data, decrypt(smallerKey, greaterEqEncryptedTest2)));
        assertTrue(Arrays.equals(data, decrypt(smallerKey, smallerEncryptedTest2)));
        assertTrue(Arrays.equals(data, decrypt(smallerKey, smallerEqEncryptedTest2)));

        // equalKey
        assertFalse(Arrays.equals(data, decrypt(equalKey, greaterEncryptedTest3)));
        assertTrue(Arrays.equals(data, decrypt(equalKey, greaterEqEncryptedTest3)));
        assertFalse(Arrays.equals(data, decrypt(equalKey, smallerEncryptedTest3)));
        assertTrue(Arrays.equals(data, decrypt(equalKey, smallerEqEncryptedTest3)));
    }

    @Test
    public void coordinateTest() throws Exception {
        AbeSecretMasterKey smKey = Cpabe.setup();
        AbePublicKey pubKey = smKey.getPublicKey();
        byte[] data = getRandomData();

        double latitudeBerlin = 52.51217;
        double longitudeBerlin = 13.42106;

        double latitudeHamburg = 53.55108;
        double longitudeHamburg = 9.99368;

        double latitudeSchwerin = 53.63550;
        double longitudeSchwerin = 11.40125;

        String policyBerlin = String.format("a:%f:%f:22:1", latitudeBerlin, longitudeBerlin);
        String policyHamburg = String.format("a:%f:%f:24:1", latitudeHamburg, longitudeHamburg);

        AbeEncrypted berlinEncryptedTest1 = Cpabe.encrypt(pubKey, policyBerlin, data);
        AbeEncrypted hamburgEncryptedTest1 = Cpabe.encrypt(pubKey, policyHamburg, data);
        
        AbeEncrypted berlinEncryptedTest2 = Cpabe.encrypt(pubKey, policyBerlin, data);
        AbeEncrypted hamburgEncryptedTest2 = Cpabe.encrypt(pubKey, policyHamburg, data);
        
        AbeEncrypted berlinEncryptedTest3 = Cpabe.encrypt(pubKey, policyBerlin, data);
        AbeEncrypted hamburgEncryptedTest3 = Cpabe.encrypt(pubKey, policyHamburg, data);

        String berlinAttribute = String.format("a:%f:%f", latitudeBerlin, longitudeBerlin);
        String hamburgAttribute = String.format("a:%f:%f", latitudeHamburg, longitudeHamburg);
        String schwerinAttribute = String.format("a:%f:%f", latitudeSchwerin, longitudeSchwerin);

        AbePrivateKey berlinKey = Cpabe.keygenSingle(smKey, berlinAttribute);
        AbePrivateKey hamburgKey = Cpabe.keygenSingle(smKey, hamburgAttribute);
        AbePrivateKey schwerinKey = Cpabe.keygenSingle(smKey, schwerinAttribute);

        // berlinKey
        assertTrue(Arrays.equals(data, decrypt(berlinKey, berlinEncryptedTest1)));
        assertFalse(Arrays.equals(data, decrypt(berlinKey, hamburgEncryptedTest1)));

        // hamburgKey
        assertFalse(Arrays.equals(data, decrypt(hamburgKey, berlinEncryptedTest2)));
        assertTrue(Arrays.equals(data, decrypt(hamburgKey, hamburgEncryptedTest2)));
        

        // schwerinKey
        assertFalse(Arrays.equals(data, decrypt(schwerinKey, berlinEncryptedTest3)));
        assertFalse(Arrays.equals(data, decrypt(schwerinKey, hamburgEncryptedTest3)));
    }

    @Test
    public void testAdditionalDataInPrivateKey() throws Exception {
        AbeSecretMasterKey smKey = Cpabe.setup(3);
        AbePublicKey pubKey = smKey.getPublicKey();

        AbePrivateKey sk = Cpabe.keygenSingle(smKey, "a");
        assertNull(sk.getAdditionalData("a"));

        byte[] data = new byte[]{ 1, 2, 3, 7, 8};
        sk.setAdditionalData("data", data);

        assertArrayEquals(sk.getAdditionalData("data"), data);

        AbePrivateKey serializedDeserialized = AbePrivateKey.readFromByteArray(sk.getAsByteArray());

        assertEquals(sk, serializedDeserialized);
        assertArrayEquals(serializedDeserialized.getAdditionalData("data"), data);

        AbePrivateKey cloned = sk.duplicate();

        assertEquals(sk, cloned);
        assertArrayEquals(cloned.getAdditionalData("data"), data);
    }
}
