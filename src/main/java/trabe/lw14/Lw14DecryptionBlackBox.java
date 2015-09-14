package trabe.lw14;

import it.unisa.dia.gas.jpbc.Element;

/**
 * The decryption black box may consist of multiple keys from different users
 * which makes up a whole. It may act probabilistically and decrypt ciphertexts
 * which use some but not all attributes of the users that the black box was
 * built from.
 */
public abstract class Lw14DecryptionBlackBox {

    /**
     * Determine if the given cipher text can be decrypted using this black box.
     * @param ct    Cipher text
     * @return is decryptable
     */
    public boolean canDecrypt(CipherText ct) {
        Element pt = decrypt(ct);
        return pt != null;
    }

    /**
     * Determine if the given cipher text can be decrypted using this black box.
     * @param ct    Cipher text
     * @return is decryptable
     */
    public abstract Element decrypt(CipherText ct);

}
