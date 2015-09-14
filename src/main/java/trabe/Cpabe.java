package trabe;

import it.unisa.dia.gas.jpbc.Element;
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
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;

import trabe.lw14.CipherText;
import trabe.lw14.Lw14;
import trabe.policy.AttributeParser;
import trabe.policyparser.ParseException;

public class Cpabe {
	static {
        try {
            System.loadLibrary("jpbc-pbc");
        } catch (UnsatisfiedLinkError e) {
        	// cant fix this error, jcpabe still runs (slowly)
            System.err.println("Running without pbc native extension");
            //e.printStackTrace();
        }
        PairingFactory.getInstance().setUsePBCWhenPossible(true);
	}

    /**
     * Sets up the ABE system with a maximum of 100 users.
     * @return  Generated secret master key
     */
    public static AbeSecretMasterKey setup() {
        return Lw14.setup(100);
    }

    public static AbeSecretMasterKey setup(int users) {
        return Lw14.setup(users);
    }

    public static void setup(File publicKeyFile, File secretMasterKeyFile) throws IOException {
        AbeSecretMasterKey masterKey = setup();
        masterKey.writeToFile(secretMasterKeyFile);
        masterKey.getPublicKey().writeToFile(publicKeyFile);
    }

    public static void setup(int users, File publicKeyFile, File secretMasterKeyFile) throws IOException {
        AbeSecretMasterKey masterKey = setup(users);
        masterKey.writeToFile(secretMasterKeyFile);
        masterKey.getPublicKey().writeToFile(publicKeyFile);
    }

    /**
     * Generates a user secret component
     * @param secretMaster    master key
     * @return secret element
     */
    public static Pair<Element, Integer> preKeygen(AbeSecretMasterKey secretMaster) {
        return Lw14.generateUserSecretComponent(secretMaster);
    }

    public static void preKeygen(AbeSecretMasterKey secretMaster, OutputStream stream) throws IOException {
        AbeOutputStream out = new AbeOutputStream(stream, secretMaster.getPublicKey());
        Pair<Element, Integer> p = preKeygen(secretMaster);
        out.writeElement(p.getFirst());
        out.writeInt(p.getSecond());
        out.close();
    }

    public static void preKeygen(File secretMaster, File secretComponent) throws IOException {
        preKeygen(AbeSecretMasterKey.readFromFile(secretMaster), new FileOutputStream(secretComponent));
    }

    public static AbePrivateKey keygen(AbeSecretMasterKey secretMaster, Pair<Element, Integer> secretComponent) throws ParseException {
        return keygen(secretMaster, "", secretComponent);
    }

    public static AbePrivateKey keygen(AbeSecretMasterKey secretMaster, String attributes, Pair<Element, Integer> secretComponent) throws ParseException {
        String parsedAttributes = AttributeParser.parseAttributes(attributes);
        String[] splitAttributes = parsedAttributes.split(" ");
        return Lw14.keygen(secretMaster, secretComponent, splitAttributes);
    }

    public static void keygen(File privateKeyFile, File secretMasterFile, File secretComponentFile) throws ParseException, IOException {
        keygen(privateKeyFile, secretMasterFile, "", secretComponentFile);
    }

    public static void keygen(File privateKeyFile, File secretMasterFile, String attributes, File secretComponentFile) throws ParseException, IOException {
        AbeSecretMasterKey secretKey = AbeSecretMasterKey.readFromFile(secretMasterFile);
        AbeInputStream in = new AbeInputStream(new FileInputStream(secretComponentFile), secretKey.getPublicKey());
        Element secretComponent = in.readElement();
        int position = in.readInt();
        in.close();

        AbePrivateKey privateKey = keygen(secretKey, attributes, new Pair<Element, Integer>(secretComponent, position));

        privateKey.writeToFile(privateKeyFile);
    }

    public static AbePrivateKey keygenSingle(AbeSecretMasterKey secretMaster, String attributes) throws ParseException {
        String parsedAttributes = AttributeParser.parseAttributes(attributes);
        String[] splitAttributes = parsedAttributes.split(" ");
        Pair<Element, Integer> sigmaAndPosition = Lw14.generateUserSecretComponent(secretMaster);
        return Lw14.keygen(secretMaster, sigmaAndPosition, splitAttributes);
    }

    public static void keygenSingle(File privateFile, File secretMasterFile, String attributes) throws IOException, ParseException {
        AbeSecretMasterKey secretKey = AbeSecretMasterKey.readFromFile(secretMasterFile);
        AbePrivateKey prv = keygenSingle(secretKey, attributes);
        prv.writeToFile(privateFile);
    }
    
    public static void decrypt(AbePrivateKey privateKey, InputStream input, OutputStream output) throws IOException, AbeDecryptionException {
    	AbeEncrypted encrypted = AbeEncrypted.readFromStream(privateKey.getPublicKey(), input);
        encrypted.writeDecryptedData(privateKey, output);
    }
    
	public static byte[] decrypt(AbePrivateKey privateKey, AbeEncrypted encryptedData) throws AbeDecryptionException, IOException {
	  	ByteArrayOutputStream out = new ByteArrayOutputStream();
	  	encryptedData.writeDecryptedData(privateKey, out);
	  	return out.toByteArray();
	}

    public static void decrypt(File privateKeyFile, File encryptedFile, File decryptedFile) throws IOException, AbeDecryptionException {
        AbePrivateKey privateKey = AbePrivateKey.readFromFile(privateKeyFile);
        BufferedInputStream in = null;
        BufferedOutputStream out = null;
        try {
	        in = new BufferedInputStream(new FileInputStream(encryptedFile));
	        out = new BufferedOutputStream(new FileOutputStream(decryptedFile));
	        decrypt(privateKey, in, out);
        } finally {
        	if (out != null) 
        		out.close();
        	if (in != null)
        		in.close();
        }
    }

    public static void encrypt(AbePublicKey publicKey, String policy, InputStream input, OutputStream output) throws AbeEncryptionException, IOException {
        encrypt(publicKey, policy, input, output, 0);
    }

    public static void encrypt(AbePublicKey publicKey, String policy, InputStream input, OutputStream output, int userIndex) throws AbeEncryptionException, IOException {
        AbeEncrypted encrypted = encrypt(publicKey, policy, input, userIndex);
        encrypted.writeEncryptedFile(output, publicKey);
    }

    public static void encrypt(AbePublicKey publicKey, String policy, InputStream input, OutputStream output, int[] revokedUserIndexes) throws AbeEncryptionException, IOException {
        AbeEncrypted encrypted = encrypt(publicKey, policy, input, revokedUserIndexes);
        encrypted.writeEncryptedFile(output, publicKey);
    }

    public static void encrypt(AbePublicKey publicKey, String policy, InputStream input, OutputStream output, int[] revokedUserIndexes, int userIndex) throws AbeEncryptionException, IOException {
        AbeEncrypted encrypted = encrypt(publicKey, policy, input, revokedUserIndexes, userIndex);
        encrypted.writeEncryptedFile(output, publicKey);
    }

    public static AbeEncrypted encrypt(AbePublicKey publicKey, String policy, InputStream input) throws AbeEncryptionException, IOException {
        return encrypt(publicKey, policy, input, 0);
    }

    public static AbeEncrypted encrypt(AbePublicKey publicKey, String policy, InputStream input, int[] revokedUserIndexes) throws AbeEncryptionException, IOException {
        return encrypt(publicKey, policy, input, revokedUserIndexes, 0);
    }

    public static AbeEncrypted encrypt(AbePublicKey publicKey, String policy, InputStream input, int userIndex) throws AbeEncryptionException, IOException {
        return encrypt(publicKey, policy, input, new int[0], userIndex);
    }

    public static AbeEncrypted encrypt(AbePublicKey publicKey, String policy, InputStream input, int[] revokedUserIndexes, int userIndex) throws AbeEncryptionException, IOException {
        Pair<CipherText, Element> ctak = Lw14.encrypt(publicKey, policy, revokedUserIndexes, userIndex);
        CipherText cipherText = ctak.getFirst();
        Element key = ctak.getSecond();

        if (cipherText == null || key == null) {
            throw new AbeEncryptionException("ABE Encryption failed");
        }

        byte[] iv = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        return AbeEncrypted.createDuringEncryption(iv, cipherText, input, key);
    }

    public static AbeEncrypted encrypt(AbePublicKey publicKey, String policy, byte[] data) throws AbeEncryptionException, IOException {
        return encrypt(publicKey, policy, data, 0);
    }

    public static AbeEncrypted encrypt(AbePublicKey publicKey, String policy, byte[] data, int userIndex) throws AbeEncryptionException, IOException {
    	ByteArrayInputStream byteIn = new ByteArrayInputStream(data);
    	return encrypt(publicKey, policy, byteIn, userIndex);
    }

    public static AbeEncrypted encrypt(AbePublicKey publicKey, String policy, byte[] data, int[] revokedUserIndexes) throws AbeEncryptionException, IOException {
        ByteArrayInputStream byteIn = new ByteArrayInputStream(data);
        return encrypt(publicKey, policy, byteIn, revokedUserIndexes);
    }

    public static AbeEncrypted encrypt(AbePublicKey publicKey, String policy, byte[] data, int[] revokedUserIndexes, int userIndex) throws AbeEncryptionException, IOException {
        ByteArrayInputStream byteIn = new ByteArrayInputStream(data);
        return encrypt(publicKey, policy, byteIn, revokedUserIndexes, userIndex);
    }

    public static void encrypt(File publicKeyFile, String policy, File inputFile, File outputFile) throws IOException, AbeEncryptionException {
        encrypt(publicKeyFile, policy, inputFile, outputFile, 0);
    }

    public static void encrypt(File publicKeyFile, String policy, File inputFile, File outputFile, int userIndex) throws IOException, AbeEncryptionException {
        AbePublicKey publicKey = AbePublicKey.readFromFile(publicKeyFile);
        BufferedInputStream in = null;
        BufferedOutputStream out = null;
        try {
	        in = new BufferedInputStream(new FileInputStream(inputFile));
	        out = new BufferedOutputStream(new FileOutputStream(outputFile));
	        encrypt(publicKey, policy, in, out, userIndex);
        } finally {
        	if (out != null) 
        		out.close();
        	if (in != null)
        		in.close();
        }
    }

    /**
     * Returns true if the given privateKey is able to decrypt the cipher of the given File, false otherwise.
     * 
     * @param privateKey    Private key
     * @param file          the input stream of the file
     * @return true if the privatekey is able to decrypt the cipher
     * @throws IOException Ciphertext file couldn't be read
     * @throws ParseException Policy couldn't be parsed
     */
    public static boolean canDecrypt(AbePrivateKey privateKey, File file)
            throws ParseException, IOException {
    	FileInputStream fis = new FileInputStream(file);
    	AbeEncrypted encrypted = AbeEncrypted.readFromStream(privateKey.getPublicKey(), fis);
    	return Lw14.canDecrypt(privateKey, encrypted.getCipher());
    }

    /**
     * Calculates the indexes of users that lended their keys to the decryption blackbox.
     * @param pub            Public key
     * @param policy         policy to try
     * @param blackBox       Decryption black box (wrapper to contact the blackbox machine)
     * @param probability    probability??
     * @return  Indexes of all traced users (traitors)
     * @throws IOException See {@link #encrypt(AbePublicKey, String, byte[], int)}
     * @throws AbeEncryptionException See {@link #encrypt(AbePublicKey, String, byte[], int)}
     */
    public static ArrayList<Integer> trace(AbePublicKey pub, String policy,
                                           DecryptionBlackBox blackBox, double probability)
            throws IOException, AbeEncryptionException {
        // TODO: add revocation
        SecureRandom random = new SecureRandom();
        byte[] message = new byte[50]; // not a multiple of the block size
        int N = pub.getMaxUsers();
        int[] p_k = new int[N+1];
        double lambda = 0.1; // TODO
        int repeat = (int)Math.ceil(8 * lambda * Math.pow(N / probability, 2));
        System.out.println("Users: " + N + " repeated: " + repeat);
        for(int k = 0; k < N + 1; k++) {
            System.out.println("began with " + k);
            int counter = 0;
            for(int i = 0; i < repeat; i++) {
                random.nextBytes(message);
                AbeEncrypted ct = encrypt(pub, policy, message, k);
                byte[] decrypted = blackBox.decrypt(ct);
                if (Arrays.equals(message, decrypted)) {
                    counter++;
                }
            }
            p_k[k] = counter;
        }

        ArrayList<Integer> result = new ArrayList<Integer>();
        double threshold = probability/(4*N);

        for(int k = 0; k < N; k++) {
            if (p_k[k] - p_k[k+1] >= threshold) {
                result.add(k);
            }
        }

        return result;
    }
}
