package trabe;

import it.unisa.dia.gas.jpbc.Element;

import java.io.*;

import trabe.aes.AesDecryptionException;
import trabe.aes.AesEncryption;
import trabe.lw14.CipherText;
import trabe.lw14.Lw14;

/**
 * The AbeEncrypted object can only be used once per method, because it is based
 * on streams and the streams cannot be read anew.
 */
public class AbeEncrypted {
    private final CipherText cipher;
	private final byte[] iv;
	private final InputStream dataStream; // the encrypted data

	AbeEncrypted(byte[] iv, CipherText cipher, InputStream dataStream) {
		this.iv = iv;
		this.cipher = cipher;
		this.dataStream = dataStream;
	}

	public CipherText getCipher() {
		return cipher;
	}

	public void writeEncryptedFile(OutputStream out, AbePublicKey publicKey) throws IOException {
		AbeOutputStream abeOut = new AbeOutputStream(out, publicKey);
		cipher.writeToStream(abeOut);
		abeOut.writeInt(iv.length);
		abeOut.write(iv);
		byte[] buffer = new byte[1024];
		int len;
		while ((len = dataStream.read(buffer)) != -1) {
			abeOut.write(buffer, 0, len);
		}
	}

	public static AbeEncrypted readFromFile(AbePublicKey publicKey, File file) throws IOException {
		return AbeEncrypted.readFromStream(publicKey, new BufferedInputStream(new FileInputStream(file)));
	}

	public static AbeEncrypted readFromStream(AbePublicKey publicKey, InputStream input) throws IOException {
		AbeInputStream stream = new AbeInputStream(input, publicKey);
		CipherText cipher = CipherText.readFromStream(stream);
		int ivLength = stream.readInt();
		byte[] iv = new byte[ivLength];
		stream.readFully(iv);
		return new AbeEncrypted(iv, cipher, input);
	}

	/**
	 * Writes the plaintext (decrypts) from the internal ciphertext stream.
	 * 
	 * @param privateKey    Private key
	 * @param output        Output stream
	 * @throws AbeDecryptionException See {@link #writeDecryptedData(AbePrivateKey, byte[], OutputStream)}
	 * @throws IOException See {@link #writeDecryptedData(AbePrivateKey, byte[], OutputStream)}
	 */
	public void writeDecryptedData(AbePrivateKey privateKey, OutputStream output) throws AbeDecryptionException, IOException {
        writeDecryptedData(privateKey, null, output);
    }

    /**
     * Writes the plaintext (decrypts) from the internal ciphertext stream.
     *
     * @param privateKey    Private key
     * @param lbeKey        Location-based key
     * @param output        Output stream
     * @throws AbeDecryptionException Decryption failed
     * @throws IOException Problem with reading the ciphertext or writing the plaintext
     */
	public void writeDecryptedData(AbePrivateKey privateKey, byte[] lbeKey, OutputStream output)
			throws AbeDecryptionException, IOException {
		Element secret = Lw14.decrypt(privateKey, cipher);
        if (secret == null) {
            throw new AbeDecryptionException("Couldn't recover the secret");
        }
		byte[] cpabeKey = secret.toBytes();
        try {
            AesEncryption.decrypt(cpabeKey, lbeKey, iv, dataStream, output);
        } catch (AesDecryptionException e) {
            throw new AbeDecryptionException("AES ciphertext couldn't be decrypted", e);
        }
        dataStream.close();
    }

    public byte[] writeDecryptedData(AbePrivateKey privateKey) throws IOException, AbeDecryptionException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        AbeOutputStream stream = new AbeOutputStream(baos, privateKey.getPublicKey());
        writeDecryptedData(privateKey, stream);
        return baos.toByteArray();
    }

    public byte[] writeEncryptedData(AbePublicKey pub) throws IOException, AbeDecryptionException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        AbeOutputStream stream = new AbeOutputStream(baos, pub);
        writeEncryptedFile(stream, pub);
        return baos.toByteArray();
    }

    public static AbeEncrypted read(byte[] data, AbePublicKey pub) throws IOException {
        AbeInputStream stream = new AbeInputStream(new ByteArrayInputStream(data), pub);
        return readFromStream(pub, stream);
    }

	public static AbeEncrypted createDuringEncryption(byte[] iv, CipherText cipher, InputStream input, Element plainSecret) throws AbeEncryptionException, IOException {
		return new AbeEncrypted(iv, cipher, AesEncryption.encrypt(plainSecret.toBytes(), null, iv, input));
	}
	
	public static AbeEncrypted createDuringEncryption(byte[] iv, byte[] lbeKey, CipherText cipher, InputStream input, Element plainSecret) throws AbeEncryptionException, IOException {
		return new AbeEncrypted(iv, cipher, AesEncryption.encrypt(plainSecret.toBytes(), lbeKey, iv, input));
	}
	
}
