package trabe;

import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import trabe.lw14.Lw14;
import trabe.policyparser.ParseException;

public class CpabeWeber {
	static {
        try {
            System.loadLibrary("jpbc-pbc");
        } catch (UnsatisfiedLinkError e) {
        	// cant fix this error, jcpabe still runs (slowly)
        }
        PairingFactory.getInstance().setUsePBCWhenPossible(true);
	}

    public static AbeSecretMasterKey setup() {
        return Lw14.setup(16);
    }

    public static void setup(File publicMasterFile, File secretMasterFile) throws IOException {
        AbeSecretMasterKey masterKey = setup();
        masterKey.writeToFile(secretMasterFile);
        masterKey.getPublicKey().writeToFile(publicMasterFile);
    }

    public static AbePrivateKey keygen(AbeSecretMasterKey secretMaster, String attributes) throws ParseException {
        return null;
//        String parsedAttributes = AttributeParser.parseAttributes(attributes);
//        String[] splitAttributes = parsedAttributes.split(" ");
//        return Lw14.keygen(secretMaster, splitAttributes);
    }

    public static void keygen(File privateFile, File secretMasterFile, String attributes) throws IOException, ParseException {
        AbeSecretMasterKey secretKey = AbeSecretMasterKey.readFromFile(secretMasterFile);
        AbePrivateKey prv = keygen(secretKey, attributes);
        prv.writeToFile(privateFile);
    }

    public static AbePrivateKey delegate(AbePrivateKey oldPrivateKey, String attributeSubset) throws ParseException {
        return null;
//        String parsedAttributeSubset = AttributeParser.parseAttributes(attributeSubset);
//        String[] splitAttributeSubset = parsedAttributeSubset.split(" ");
//        return Lw14.delegate(oldPrivateKey, splitAttributeSubset);
    }

    public static void delegate(File oldPrivateKeyFile, String attributeSubset, File newPrivateKeyFile) throws IOException, ParseException {
        AbePrivateKey oldPrivateKey = AbePrivateKey.readFromFile(oldPrivateKeyFile);
        AbePrivateKey newPrivateKey = delegate(oldPrivateKey, attributeSubset);
        newPrivateKey.writeToFile(newPrivateKeyFile);
    }
    
    public static void decrypt(AbePrivateKey privateKey, InputStream input, OutputStream output, byte[] lbeKey) throws IOException, AbeDecryptionException {
    	AbeEncrypted encrypted = AbeEncrypted.readFromStream(privateKey.getPublicKey(), input);
        encrypted.writeDecryptedData(privateKey, lbeKey, output);
    }
    
	public static byte[] decrypt(AbePrivateKey privateKey, AbeEncrypted encryptedData, byte[] lbeKey) throws AbeDecryptionException, IOException {
	  	ByteArrayOutputStream out = new ByteArrayOutputStream();
	  	encryptedData.writeDecryptedData(privateKey, lbeKey, out);
	  	return out.toByteArray();
	}

    public static void decrypt(File privateKeyFile, File encryptedFile, File decryptedFile, byte[] lbeKey) throws IOException, AbeDecryptionException {
        AbePrivateKey privateKey = AbePrivateKey.readFromFile(privateKeyFile);
        BufferedInputStream in = null;
        BufferedOutputStream out = null;
        try {
	        in = new BufferedInputStream(new FileInputStream(encryptedFile));
	        out = new BufferedOutputStream(new FileOutputStream(decryptedFile));
	        decrypt(privateKey, in, out, lbeKey);
        } finally {
        	if (out != null) 
        		out.close();
        	if (in != null)
        		in.close();
        }
    }
    
    public static void encrypt(AbePublicKey publicKey, String policy, InputStream input, OutputStream output, byte[] lbeKey) throws AbeEncryptionException, IOException {
        AbeEncrypted encrypted = encrypt(publicKey, policy, input, lbeKey);
        encrypted.writeEncryptedFile(output, publicKey);
    }
    
    public static AbeEncrypted encrypt(AbePublicKey publicKey, String policy, InputStream input, byte[] lbeKey) throws AbeEncryptionException, IOException {
    	/*try {
	        String parsedPolicy = PolicyParsing.parsePolicy(policy);
	        Bsw07CipherAndKey cipherAndKey = Lw14.encrypt(publicKey, parsedPolicy);
	        Bsw07Cipher abeEncryptedSecret = cipherAndKey.getCipher();
	        Element plainSecret = cipherAndKey.getKey();
	
	        if (abeEncryptedSecret == null) {
	            throw new AbeEncryptionException("ABE Encryption failed");
	        }
	
	        byte[] iv = new byte[16];
	        SecureRandom random = new SecureRandom();
	        random.nextBytes(iv);
	        return AbeEncrypted.createDuringEncryption(iv, lbeKey, abeEncryptedSecret, input, plainSecret);
    	} catch (ParseException e) {
    		throw new AbeEncryptionException("error while parsing policy", e);
    	}*/
        return null;
    }
    
    public static AbeEncrypted encrypt(AbePublicKey publicKey, String policy, byte[] data, byte[] lbeKey) throws AbeEncryptionException, IOException {
    	ByteArrayInputStream byteIn = new ByteArrayInputStream(data);
    	return encrypt(publicKey, policy, byteIn, lbeKey);
    }

    public static void encrypt(File publicKeyFile, String policy, File inputFile, File outputFile, byte[] lbeKey) throws IOException, AbeEncryptionException {
        AbePublicKey publicKey = AbePublicKey.readFromFile(publicKeyFile);
        BufferedInputStream in = null;
        BufferedOutputStream out = null;
        try {
	        in = new BufferedInputStream(new FileInputStream(inputFile));
	        out = new BufferedOutputStream(new FileOutputStream(outputFile));
	        encrypt(publicKey, policy, in, out, lbeKey);
        } finally {
        	if (out != null) 
        		out.close();
        	if (in != null)
        		in.close();
        }
    }
}
