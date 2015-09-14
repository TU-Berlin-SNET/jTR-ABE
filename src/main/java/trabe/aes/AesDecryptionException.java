package trabe.aes;

import trabe.DecryptionException;

public class AesDecryptionException extends DecryptionException {
    public AesDecryptionException(Throwable throwable) {
        super(throwable);
    }
}
