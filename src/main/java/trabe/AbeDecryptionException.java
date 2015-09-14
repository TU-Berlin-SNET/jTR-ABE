package trabe;

public class AbeDecryptionException extends DecryptionException {

	private static final long serialVersionUID = 2848983353356933397L;

	public AbeDecryptionException(String msg) {
		super(msg);
	}

	public AbeDecryptionException(String msg, Throwable t) {
		super(msg, t);
	}
}
