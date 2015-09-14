package trabe.demo;

import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import trabe.*;

import java.util.Arrays;
import java.util.List;

public class BlackBoxDemo {

    public static void main(String[] args) throws Exception {
        AbeSecretMasterKey smKey = Cpabe.setup(2);
        AbePublicKey pubKey = smKey.getPublicKey();

        String policy1 = "(att1 and att2) or att3";

        String att1att2att3Attribute = "att1 att2 att3";
        String att1att2Attribute = "att1 att2";
        String att1att3Attribute = "att1 att3";
        String att2att3Attribute = "att2 att3";
        String att1Attribute = "att1";
        String att2Attribute = "att2";
        String att3Attribute = "att3";

//        AbePrivateKey att1att2att3Key = Cpabe.keygenSingle(smKey, att1att2att3Attribute);
        AbePrivateKey att1att2Key = Cpabe.keygenSingle(smKey, att1att2Attribute);
//        AbePrivateKey att1att3Key = Cpabe.keygenSingle(smKey, att1att3Attribute);
//        AbePrivateKey att2att3Key = Cpabe.keygenSingle(smKey, att2att3Attribute);
        AbePrivateKey att1Key = Cpabe.keygenSingle(smKey, att1Attribute);
//        AbePrivateKey att2Key = Cpabe.keygenSingle(smKey, att2Attribute);
//        AbePrivateKey att3Key = Cpabe.keygenSingle(smKey, att3Attribute);

        DecryptionBlackBox bb1 = new MockBlackBox(new AbePrivateKey[]{ att1att2Key, att1Key }, pubKey);
//        DecryptionBlackBox bb2 = new MockBlackBox(new AbePrivateKey[]{ att1att2Key }, pubKey);
//        DecryptionBlackBox bb3 = new MockBlackBox(new AbePrivateKey[]{ att1Key }, pubKey);


        long timeStart = System.currentTimeMillis();
        List<Integer> userIndexes;
        userIndexes = Cpabe.trace(pubKey, policy1, bb1, 0.9);
        assert userIndexes != null;
        long timeEnd = System.currentTimeMillis();
        System.out.println(String.format("this trace took %d ms.", timeEnd - timeStart));

        System.out.println("Success: " + (userIndexes.size() == 1));
        System.out.println("Offending user ids: " + Arrays.toString(userIndexes.toArray()));

        System.out.println("wasPbcAvailable? "+PairingFactory.getInstance().isPBCAvailable());
    }
}
