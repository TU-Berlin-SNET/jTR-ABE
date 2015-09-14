package trabe.demo;

import java.security.SecureRandom;
import java.util.Arrays;

import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import trabe.*;

public class DemoForCpabe {

    public static void main(String[] args) throws Exception {
        long timeStart = System.currentTimeMillis();
        AbeSecretMasterKey smKey = Cpabe.setup(4);

        AbePublicKey pubKey = smKey.getPublicKey();

        SecureRandom r = new SecureRandom();
        byte[] data = new byte[100];
        r.nextBytes(data);

        String policy1 = "(att1 and att2) or att3";
        AbeEncrypted ct1 = Cpabe.encrypt(pubKey, policy1, data);

        String att1att2Attribute = "att1 att2";
        AbePrivateKey att1att2Key = Cpabe.keygenSingle(smKey, att1att2Attribute);

        System.out.println("Success: " + Arrays.equals(data, Cpabe.decrypt(att1att2Key, ct1)));
        long timeEnd = System.currentTimeMillis();

        System.out.println(String.format("this operation took %d ms.", timeEnd - timeStart));
        System.out.println("wasPbcAvailable? "+PairingFactory.getInstance().isPBCAvailable());
    }
}
