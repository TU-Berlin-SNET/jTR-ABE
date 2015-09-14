package trabe;

import java.security.GeneralSecurityException;

public class AbeEncryptionException extends GeneralSecurityException {

    private static final long serialVersionUID = 1043863535572140323L;

    public AbeEncryptionException(String msg) {
        super(msg);
    }
    
    public AbeEncryptionException(String msg, Throwable t) {
        super(msg, t);
    }

}
