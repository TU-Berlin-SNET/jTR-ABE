package trabe.aes;

import java.io.IOException;
import java.io.InputStream;

/**
 * Returns EOF after the specified number of bytes has been read. Underlying stream may still have more data.
 * Not thread-safe
 *
 */
public class InputStreamStopper extends InputStream {
	private static final int EOF = -1;
	private long maxLength;
	private long curPos;
	private InputStream in;
	private static long MAX_READ_PER_CALL = 8192;
	
	public InputStreamStopper(InputStream in, long maxLength) {
		this.curPos = 0;
		this.maxLength = maxLength;
        this.in = in;
	}
	
	@Override
	public int read(byte[] b, int off, int len) throws IOException {
		if (curPos >= maxLength) return EOF;
		int maxRead = (int) Math.min(Math.min(len, maxLength - curPos), MAX_READ_PER_CALL);
		int actualRead = in.read(b, off, maxRead);
		if (actualRead != EOF) {
			curPos += actualRead;
		}
		return actualRead;
	}

	@Override
	public int read() throws IOException {
		if (curPos >= maxLength) return EOF;
		int val = in.read();
		if (val != EOF) {
			curPos++;
		}
		return val;
	}

}
