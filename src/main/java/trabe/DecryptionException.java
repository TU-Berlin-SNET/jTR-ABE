package trabe;

import java.security.GeneralSecurityException;

public class DecryptionException extends GeneralSecurityException {

    private static final long serialVersionUID = 2848983353356953397L;

    public DecryptionException() {
        super();
    }

    public DecryptionException(String msg) {
        super(msg);
    }

    public DecryptionException(Throwable t) {
        super(t);
    }

    public DecryptionException(String msg, Throwable t) {
        super(msg, t);
    }
}
