package trabe;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Arrays;

import it.unisa.dia.gas.jpbc.Element;
import trabe.lw14.Lw14Util;

/**
 * A master secret key
 */
public class AbeSecretMasterKey {
    private static final int SERIALIZE_VERSION = 1;

    private final AbePublicKey pubKey;
    /** [Zr] **/
    public final Element[] alpha_i;
    /** [Zr] **/
    public final Element[] r_i;
    /** [Zr] **/
    public final Element[] c_j;

    public int counter;

    public AbePublicKey getPublicKey() {
        return pubKey;
    }

    public int getMaxUsers() {
        return getSqrtUsers() * getSqrtUsers() - 1;
    }

    public AbeSecretMasterKey(AbePublicKey pubKey, Element[] alpha_i, Element[] r_i, Element[] c_j) {
        this(pubKey, alpha_i, r_i, c_j, 0);
    }

    public AbeSecretMasterKey(AbePublicKey pubKey, Element[] alpha_i, Element[] r_i, Element[] c_j, int counter) {
        this.pubKey = pubKey;
        this.alpha_i = alpha_i;
        this.r_i = r_i;
        this.c_j = c_j;
        this.counter = counter;
    }
    
    private static AbeSecretMasterKey readFromStream(AbeInputStream stream) throws IOException {
        int version = stream.readInt();

        AbePublicKey pubKey = AbePublicKey.readFromStream(stream);
        //stream.setPublicKey(pubKey);

        int usersSqrt = stream.readInt();
        int counter = stream.readInt();

        Element[] alpha_i = Lw14Util.readElementArray(usersSqrt, stream);
        Element[] r_i = Lw14Util.readElementArray(usersSqrt, stream);
        Element[] c_j = Lw14Util.readElementArray(usersSqrt, stream);

        return new AbeSecretMasterKey(pubKey, alpha_i, r_i, c_j, counter);
    }

    public static AbeSecretMasterKey readFromFile(File file) throws IOException {
        AbeInputStream stream = new AbeInputStream(new FileInputStream(file));
        try {
        	return readFromStream(stream);
        } finally {
        	stream.close();
        }
    }
    
    public static AbeSecretMasterKey readFromByteArray(byte[] data) throws IOException {
        AbeInputStream stream = new AbeInputStream(new ByteArrayInputStream(data));
        try {
        	return readFromStream(stream);
        } finally {
        	stream.close();
        }
    }

    public void writeToFile(File file) throws IOException {
        AbeOutputStream fileStream = new AbeOutputStream(new FileOutputStream(file), pubKey);
        writeToStream(fileStream);
        fileStream.flush();
        fileStream.close();
    }
    
    public void writeToStream(OutputStream stream) throws IOException {
    	writeToStream(new AbeOutputStream(stream, pubKey));
    }
    
    public void writeToStream(AbeOutputStream stream) throws IOException {
        stream.writeInt(SERIALIZE_VERSION);

        pubKey.writeToStream(stream);

        stream.writeInt(getSqrtUsers());
        stream.writeInt(counter);

        Lw14Util.writeArray(alpha_i, stream, false);
        Lw14Util.writeArray(r_i, stream, false);
        Lw14Util.writeArray(c_j, stream, false);
    }
    
    public byte[] getAsByteArray() throws IOException {
    	ByteArrayOutputStream baos = new ByteArrayOutputStream();
    	this.writeToStream(baos);
    	return baos.toByteArray();
    }

    public int getSqrtUsers(){
        return this.c_j.length;
    }

    public AbeUserIndex getCurrentPosition(){
        return new AbeUserIndex(getSqrtUsers(), counter);
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null || !(obj instanceof AbeSecretMasterKey)) {
            return false;
        } else if(this == obj) {
            return true;
        }
        AbeSecretMasterKey msk = (AbeSecretMasterKey)obj;

        boolean result = pubKey.equals(msk.pubKey);
        result = result && Arrays.equals(alpha_i, msk.alpha_i);
        result = result && Arrays.equals(r_i, msk.r_i);
        result = result && Arrays.equals(c_j, msk.c_j);
        result = result && counter == msk.counter;

        return result;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");

        sb.append("    \"alpha_i\":");
        sb.append(Lw14Util.toString(alpha_i, 4, 4));
        sb.append(",\n");

        sb.append("    \"r_i\":");
        sb.append(Lw14Util.toString(r_i, 4, 4));
        sb.append(",\n");

        sb.append("    \"c_j\":");
        sb.append(Lw14Util.toString(c_j, 4, 4));
        sb.append(",\n");

        sb.append("    \"counter\":");
        sb.append(counter);

        sb.append("\n}");
        return sb.toString();
    }
}
