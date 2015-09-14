package trabe;

import java.io.*;
import java.util.Arrays;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.parameters.PropertiesParameters;
import trabe.lw14.Lw14Util;

public class AbePublicKey {
    /*
     * A public key
     */
    private final String pairingDesc;
    private transient Pairing p;
    /** G_1 **/
    public Element g;
    /** G_1 **/
    public Element  h;
    /** G_1 **/
    public Element  f;
    /** [G_1] **/
    public Element[] f_j;
    /** G_1 **/
    public Element G;
    /** G_1 **/
    public Element H;
    /** [G_T] **/
    public Element[] E_i;
    /** [G_1] **/
    public Element[] G_i;
    /** [G_1] **/
    public Element[] Z_i;
    /** [G_1] **/
    public Element[] H_j;

    /**
     * Creates a new AbePublicKey. This key should only be used after the elements have been set (setElements).
     * 
     * @param pairingDescription    Description of the pairing (parameters)
     */
    public AbePublicKey(String pairingDescription) {
        this.pairingDesc = pairingDescription;
    }
    
    public String getPairingDescription() {
        return pairingDesc;
    }

    public int getMaxUsers() {
        return getSqrtUsers() * getSqrtUsers() - 1;
    }

    public Pairing getPairing() {
        if (p == null) {
            PairingParameters params = new PropertiesParameters().load(new ByteArrayInputStream(pairingDesc.getBytes()));
            p = PairingFactory.getPairing(params);
        }
        return p;
    }

    public void setElements(Element g, Element h, Element f, Element[] f_j,
                            Element G, Element H, Element[] E_i, Element[] G_i,
                            Element[] Z_i, Element[] H_j) {
        this.g = g;
        this.h = h;
        this.f = f;
        this.f_j = f_j;
        this.G = G;
        this.H = H;
        this.E_i = E_i;
        this.G_i = G_i;
        this.Z_i = Z_i;
        this.H_j = H_j;
    }

    public static AbePublicKey readFromFile(File file) throws IOException {
        AbeInputStream stream = new AbeInputStream(new FileInputStream(file));
        try {
            return readFromStream(stream);
        } finally {
            stream.close();
        }
    }

    public static AbePublicKey readFromStream(AbeInputStream stream) throws IOException {
        String pairingDescription = stream.readString();
        AbePublicKey publicKey = new AbePublicKey(pairingDescription);
        stream.setPublicKey(publicKey);

        int usersSqrt = stream.readInt();

        publicKey.g = stream.readElement();
        publicKey.h = stream.readElement();
        publicKey.f = stream.readElement();
        publicKey.G = stream.readElement();
        publicKey.H = stream.readElement();

        publicKey.f_j = Lw14Util.readElementArray(usersSqrt, stream);
        publicKey.E_i = Lw14Util.readElementArray(usersSqrt, stream);
        publicKey.G_i = Lw14Util.readElementArray(usersSqrt, stream);
        publicKey.Z_i = Lw14Util.readElementArray(usersSqrt, stream);
        publicKey.H_j = Lw14Util.readElementArray(usersSqrt, stream);

        return publicKey;
    }

    public void writeToStream(OutputStream stream) throws IOException {
        writeToStream(new AbeOutputStream(stream, this));
    }

    public void writeToStream(AbeOutputStream stream) throws IOException {
        stream.writeString(pairingDesc);

        stream.writeInt(f_j.length);

        stream.writeElement(g);
        stream.writeElement(h);
        stream.writeElement(f);
        stream.writeElement(G);
        stream.writeElement(H);

        Lw14Util.writeArray(f_j, stream, false);
        Lw14Util.writeArray(E_i, stream, false);
        Lw14Util.writeArray(G_i, stream, false);
        Lw14Util.writeArray(Z_i, stream, false);
        Lw14Util.writeArray(H_j, stream, false);
    }

    public void writeToFile(File file) throws IOException {
        AbeOutputStream fos = new AbeOutputStream(new FileOutputStream(file), this);
        writeToStream(fos);
        fos.close();
    }

    public byte[] getAsByteArray() throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        this.writeToStream(baos);
        return baos.toByteArray();
    }

    public static AbePublicKey readFromByteArray(byte[] data) throws IOException {
        AbeInputStream stream = new AbeInputStream(new ByteArrayInputStream(data));
        try {
            return readFromStream(stream);
        } finally {
            stream.close();
        }
    }

    public int getSqrtUsers(){
        return this.f_j.length;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null || !(obj instanceof AbePublicKey)) {
            return false;
        } else if(this == obj) {
            return true;
        }
        AbePublicKey p = (AbePublicKey)obj;

        boolean result = pairingDesc.equals(p.pairingDesc);
        result = result && g.equals(p.g);
        result = result && h.equals(p.h);
        result = result && f.equals(p.f);
        result = result && Arrays.equals(f_j, p.f_j);
        result = result && G.equals(p.G);
        result = result && H.equals(p.H);
        result = result && Arrays.equals(E_i, p.E_i);
        result = result && Arrays.equals(G_i, p.G_i);
        result = result && Arrays.equals(Z_i, p.Z_i);
        result = result && Arrays.equals(H_j, p.H_j);

        return result;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");

        sb.append("    \"pairingDesc\":");
        sb.append('"');
        sb.append(pairingDesc);
        sb.append('"');
        sb.append(",\n");

        sb.append("    \"g\":");
        sb.append('"');
        sb.append(g);
        sb.append('"');
        sb.append(",\n");

        sb.append("    \"f\":");
        sb.append('"');
        sb.append(f);
        sb.append('"');
        sb.append(",\n");

        sb.append("    \"h\":");
        sb.append('"');
        sb.append(h);
        sb.append('"');
        sb.append(",\n");

        sb.append("    \"G\":");
        sb.append('"');
        sb.append(G);
        sb.append('"');
        sb.append(",\n");

        sb.append("    \"H\":");
        sb.append('"');
        sb.append(H);
        sb.append('"');
        sb.append(",\n");

        sb.append("    \"f_j\":");
        sb.append(Lw14Util.toString(f_j, 4, 4));
        sb.append(",\n");

        sb.append("    \"E_i\":");
        sb.append(Lw14Util.toString(E_i, 4, 4));
        sb.append(",\n");

        sb.append("    \"G_i\":");
        sb.append(Lw14Util.toString(G_i, 4, 4));
        sb.append(",\n");

        sb.append("    \"Z_i\":");
        sb.append(Lw14Util.toString(Z_i, 4, 4));
        sb.append(",\n");

        sb.append("    \"H_j\":");
        sb.append(Lw14Util.toString(H_j, 4, 4));

        sb.append("\n}");
        return sb.toString();
    }
}
