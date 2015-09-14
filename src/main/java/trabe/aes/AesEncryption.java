package trabe.aes;

import java.io.*;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import trabe.AbeDecryptionException;
import trabe.AbeEncryptionException;

public class AesEncryption {
    private final static String KEY_ALGORITHM     = "AES";
    private final static String CIPHER_ALGORITHM  = "AES/CBC/PKCS5Padding"; //"AES/GCM/NoPadding" not working on android
    private final static String HASHING_ALGORITHM = "SHA-256";
    private static final int BUFFERSIZE = 1024;
    // We use AES128 per schneier, so we need to reduce the keysize
    private static final int AES_KEY_LENGTH = 16;
    
    static {
    	//Security.addProvider(new BouncyCastleProvider());
    }

    private static byte[] hash(byte[] cpabeData) {
        try {
            MessageDigest sha256 = MessageDigest.getInstance(HASHING_ALGORITHM);
            return Arrays.copyOf(sha256.digest(cpabeData), AES_KEY_LENGTH);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            System.err.println(HASHING_ALGORITHM + " not provided by runtime environment. Exiting...");
            System.exit(1);
        }
        return null;
    }
    
    private static byte[] combine(byte[] cpabeData, byte[] lbeKey) {
    	byte[] hashedCpabeSecret = hash(cpabeData);
    	if (lbeKey != null) {
    		if (hashedCpabeSecret.length != lbeKey.length) {
    			throw new RuntimeException("wrong key size for lbeKey, " + hashedCpabeSecret.length + " bytes required");
    		}
    		for (int i = 0; i < lbeKey.length; i++) {
    			hashedCpabeSecret[i] = (byte) (hashedCpabeSecret[i] ^ lbeKey[i]);
    		}
    	}
    	return hashedCpabeSecret;
    }
	
	public static void encrypt(byte[] cpabeKey, byte[] lbeKey, byte[] iv, InputStream input, OutputStream output) throws IOException, AbeEncryptionException {
        try {
            CipherInputStream cis = encrypt(cpabeKey, lbeKey, iv, input);
            int read;
            byte[] buffer = new byte[BUFFERSIZE];
            while ((read = cis.read(buffer)) >= 0) {
            	output.write(buffer, 0, read);
            }
            output.close();
            cis.close();
        } catch (GeneralSecurityException e) {
            throw new AbeEncryptionException(e.getMessage(), e);
        }
	}

    public static byte[] encrypt(byte[] cpabeKey, byte[] lbeKey, byte[] iv, byte[] data) throws IOException, AbeEncryptionException {
        ByteArrayInputStream bais = new ByteArrayInputStream(data);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        encrypt(cpabeKey, lbeKey, iv, bais, baos);
        return baos.toByteArray();
    }
	
	public static CipherInputStream encrypt(byte[] cpabeKey, byte[] lbeKey, byte[] iv, InputStream input) throws IOException, AbeEncryptionException {
        try {
            SecretKeySpec skeySpec = new SecretKeySpec(combine(cpabeKey, lbeKey), KEY_ALGORITHM);
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, new IvParameterSpec(iv));
            CipherInputStream cis = new CipherInputStream(input, cipher);
            return cis;
        } catch (GeneralSecurityException e) {
            throw new AbeEncryptionException(e.getMessage(), e);
        }
	}
	
	public static CipherInputStream decrypt(byte[] cpabeKey, byte[] lbeKey, byte[] iv, InputStream input) throws IOException, AbeDecryptionException {
        try {
            SecretKeySpec skeySpec = new SecretKeySpec(combine(cpabeKey, lbeKey), KEY_ALGORITHM);
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, new IvParameterSpec(iv));
            return new CipherInputStream(input, cipher);
        } catch (GeneralSecurityException e) {
            throw new AbeDecryptionException(e.getMessage(), e);
        }
	}

    public static Cipher decrypt(byte[] cpabeKey, byte[] lbeKey, byte[] iv) throws IOException {
        try {
            SecretKeySpec skeySpec = new SecretKeySpec(combine(cpabeKey, lbeKey), KEY_ALGORITHM);
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, new IvParameterSpec(iv));
            return cipher;
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }
	
	public static void decrypt(byte[] cpabeKey, byte[] lbeKey, byte[] iv, InputStream input, OutputStream output) throws IOException, AesDecryptionException {
        Cipher cipher = decrypt(cpabeKey, lbeKey, iv);
        int read;
        byte[] buffer = new byte[BUFFERSIZE];
        while ((read = input.read(buffer)) >= 0) {
            byte[] dec = cipher.update(buffer, 0, read);
            output.write(dec);
        }
        try {
            byte[] dec = cipher.doFinal();
            output.write(dec);
        } catch (Exception e) {
            throw new AesDecryptionException(e);
        }
	}

    public static byte[] decrypt(byte[] cpabeKey, byte[] lbeKey, byte[] iv, byte[] data) throws IOException, AesDecryptionException {
        ByteArrayInputStream bais = new ByteArrayInputStream(data);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        decrypt(cpabeKey, lbeKey, iv, bais, baos);
        return baos.toByteArray();
    }
}