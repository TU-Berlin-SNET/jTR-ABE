package trabe;

import trabe.lw14.*;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class MockBlackBox extends DecryptionBlackBox {

    private List<AbePrivateKey> userKeys = new ArrayList<AbePrivateKey>();
    private AbePublicKey publicKey;

    public MockBlackBox(List<AbePrivateKey> userKeys, AbePublicKey publicKey) {
        this.userKeys = userKeys;
        this.publicKey = publicKey;
    }

    public MockBlackBox(AbePrivateKey[] userKeys, AbePublicKey publicKey) {
        this.userKeys = new ArrayList<AbePrivateKey>(userKeys.length);
        Collections.addAll(this.userKeys, userKeys);
        this.publicKey = publicKey;
    }

    /**
     * Determine if the given cipher text can be decrypted using this black box.
     *
     * @param ct Cipher text
     * @return plaintext
     */
    @Override
    public byte[] decrypt(AbeEncrypted ct) {
        for(AbePrivateKey key : userKeys) {
            try {
                String privKeyAttrs = "";
                for (String privKeyAttr : key.getAttributeSet()) {
                    privKeyAttrs += privKeyAttr + " ";
                }
                if (Lw14.canDecrypt(key, ct.getCipher())) {
                    System.out.println(privKeyAttrs + " [" + key.position.counter + "] [" + key.position.i + " , "+ key.position.j + "] can decrypt policy: " + ct.getCipher().policy);
                    return Cpabe.decrypt(key, ct);
                }
            } catch (Exception ignored) {
            }
        }
        return null;
    }
}
