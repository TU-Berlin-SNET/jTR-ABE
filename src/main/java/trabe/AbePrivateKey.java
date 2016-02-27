package trabe;

import java.io.*;
import java.security.SecureRandom;
import java.util.*;

import trabe.lw14.Lw14PrivateKeyComponent;
import it.unisa.dia.gas.jpbc.Element;
import trabe.lw14.Lw14Util;

public class AbePrivateKey {
    private static final int SERIALIZE_VERSION = 3;

    public final AbeUserIndex position;

    /** G1 **/
    public final Element k1_ij;
    /** G1 **/
    public final Element k2_ij;
    /** G1 **/
    public final Element k3_ij;
    /** [G1] **/
    public final Element[] k_ijj;
    private final ArrayList<Lw14PrivateKeyComponent> components;
    private final AbePublicKey pubKey;

    /**
     * Can be used to store additional information such as a secret seed or a
     * authority public key. The seed on the client that can be used
     * to seed a PRNG for generating common parameters on client and authority
     * without further communication. The public key can be used to verify
     * received data that it is indeed from the authority.
     */
    private final Map<String, byte[]> additionalData = new HashMap<String, byte[]>();

    public AbePrivateKey(AbeUserIndex position,
                         Element k1_ij, Element k2_ij, Element k3_ij,
                         Element[] k_ijj, ArrayList<Lw14PrivateKeyComponent> components,
                         AbePublicKey pubKey) {
        this.position = position;
        this.k1_ij = k1_ij;
        this.k2_ij = k2_ij;
        this.k3_ij = k3_ij;
        this.k_ijj = k_ijj;
        this.components = components;
        this.pubKey = pubKey;
    }

    public AbePublicKey getPublicKey() {
        return pubKey;
    }

    /**
     * @return a new privatekey, where d and the component list has been duplicated. The list elements have NOT been duplicated.
     */
    public AbePrivateKey duplicate() {
        ArrayList<Lw14PrivateKeyComponent> duplicatedComponents = new ArrayList<Lw14PrivateKeyComponent>(components.size());
        for (Lw14PrivateKeyComponent cur : components) {
            // should each component also be duplicated? only necessary if components are altered somewhere, which they are not
            duplicatedComponents.add(cur);
        }
        Element[] duplicatedK_ijj = new Element[k_ijj.length];
        for(int i = 0; i < k_ijj.length; i++) {
            if (k_ijj[i] == null) {
                duplicatedK_ijj[i] = null;
            } else {
                duplicatedK_ijj[i] = k_ijj[i].duplicate();
            }
        }
        AbePrivateKey sk = new AbePrivateKey(position, k1_ij.duplicate(), k2_ij.duplicate(),
                k3_ij.duplicate(), duplicatedK_ijj, duplicatedComponents, pubKey);

        sk.additionalData.putAll(this.additionalData);

        return sk;
    }

    /**
     * Return the attributes of the matrix (LSSS approach).
     * @return  Attributes in the matrix
     */
    public Set<String> getAttributeSet() {
        int attributes = getComponents().size();
        Set<String> set = new HashSet<String>(attributes);
        for(int i = 0; i < attributes; i++) {
            set.add(components.get(i).attribute);
        }
        return set;
    }

    public List<Lw14PrivateKeyComponent> getComponents() {
    	return components;
    }

    /**
     * Finds the key component by attribute. This is of the LSSS approach which
     * needs access to the attribute string directly.
     * @param attribute    Attribute string
     * @return  Attribute component
     */
    public Lw14PrivateKeyComponent getComponent(String attribute) {
        for(Lw14PrivateKeyComponent c : components){
            if (attribute.equals(c.attribute)) {
                return c;
            }
        }
        return null;
    }

    public Lw14PrivateKeyComponent getSatisfyingComponent(Element hashedAttribute) {
        for (int i = 0; i < components.size(); i++) {
            Lw14PrivateKeyComponent component = components.get(i);
            if (component.hashedAttributeZr.isEqual(hashedAttribute)) {
                return component;
            }
        }
        return null;
    }

    /**
     * @see java.util.Map#get(Object)
     * @param name    Additional data identifier
     * @return  Additional data
     */
    public byte[] getAdditionalData(String name) {
        return additionalData.get(name);
    }

    /**
     * @see java.util.Map#put(Object, Object)
     * @param name    Additional data identifier
     * @param data    Additional data
     * @return  previously stored/replaced additional data or <code>null</code>
     */
    public byte[] setAdditionalData(String name, byte[] data) {
        return additionalData.put(name, data);
    }
    
    public AbePrivateKey newKeyWithAddedAttributes(List<Lw14PrivateKeyComponent> newComponents) {
        AbePrivateKey newKey = this.duplicate();
        newKey.components.addAll(newComponents);
        return newKey;
    }

    /**
     * Produces a new private key object which contains all the other attribute
     * components. It returns null if the positions or the other elements don't match.
     * The additional data values will be replaced.
     * @param otherKey    Private to merge with (attributes are taken from this one)
     * @return  Entirely new private key
     */
    public AbePrivateKey merge(AbePrivateKey otherKey) {
        if (otherKey == null
                || !k1_ij.equals(otherKey.k1_ij)
                || !k2_ij.equals(otherKey.k2_ij)
                || !k3_ij.equals(otherKey.k3_ij)
                || !Arrays.equals(k_ijj, otherKey.k_ijj)
                || !position.equals(otherKey.position)) {
            return null;
        }
        AbePrivateKey newKey = duplicate();
        newKey.components.addAll(otherKey.getComponents());
        newKey.additionalData.putAll(otherKey.additionalData);
        return newKey;
    }

    public static AbePrivateKey readFromStream(AbeInputStream stream) throws IOException {
        int version = stream.readInt();
        AbePublicKey pubKey = AbePublicKey.readFromStream(stream);
        stream.setPublicKey(pubKey);
        int m = stream.readInt();
        int counter = stream.readInt();
        Element k1_ij = stream.readElement();
        Element k2_ij = stream.readElement();
        Element k3_ij = stream.readElement();

        Element[] k_ijj = Lw14Util.readElementArray(stream);

        byte[] secretSeed = null;
        if (version == 1) {
            secretSeed = Lw14Util.readByteArray(stream);
        }

        int compsLength = stream.readInt();
        ArrayList<Lw14PrivateKeyComponent> components = new ArrayList<Lw14PrivateKeyComponent>(compsLength);

        for (int i = 0; i < compsLength; i++) {
            components.add(Lw14PrivateKeyComponent.readFromStream(stream, version));
        }
        AbePrivateKey sk = new AbePrivateKey(new AbeUserIndex(m, counter), k1_ij, k2_ij, k3_ij, k_ijj,
                components, pubKey);

        if (version == 1) {
            sk.setAdditionalData("secretSeed", secretSeed);
        } else {
            int adLength = stream.readInt();
            for (int i = 0; i < adLength; i++) {
                String name = stream.readString();
                byte[] data = Lw14Util.readByteArray(stream);

                sk.setAdditionalData(name, data);
            }
        }
        return sk;
    }

    public static AbePrivateKey readFromStream(InputStream stream) throws IOException {
        return readFromStream(new AbeInputStream(stream));
    }

    public static AbePrivateKey readFromFile(File file) throws IOException {
        FileInputStream stream = new FileInputStream(file);
        AbePrivateKey priv = readFromStream(stream);
        stream.close();
        return priv;
    }
    
    public void writeToFile(File file) throws IOException {
        FileOutputStream stream = new FileOutputStream(file);
        writeToStream(stream);
        stream.close();
    }

    public void writeToStream(OutputStream stream) throws IOException {
        writeToStream(new AbeOutputStream(stream, pubKey));
    }

    public void writeToStream(AbeOutputStream stream) throws IOException {
        stream.writeInt(SERIALIZE_VERSION);
        pubKey.writeToStream(stream);
        stream.writeInt(position.m);
        stream.writeInt(position.counter);
        stream.writeElement(k1_ij);
        stream.writeElement(k2_ij);
        stream.writeElement(k3_ij);

        Lw14Util.writeArray(k_ijj, stream);

        stream.writeInt(components.size());
        for (Lw14PrivateKeyComponent component : components) {
            component.writeToStream(stream);
        }

        stream.writeInt(additionalData.size());
        for (Map.Entry<String, byte[]> e : additionalData.entrySet()) {
            stream.writeString(e.getKey());
            Lw14Util.writeArray(e.getValue(), stream);
        }
    }

    public byte[] getAsByteArray() throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        this.writeToStream(baos);
        return baos.toByteArray();
    }

    public static AbePrivateKey readFromByteArray(byte[] data) throws IOException {
        AbeInputStream stream = new AbeInputStream(new ByteArrayInputStream(data));
        try {
            return readFromStream(stream);
        } finally {
            stream.close();
        }
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null || !(obj instanceof AbePrivateKey)) {
            return false;
        } else if(this == obj) {
            return true;
        }
        AbePrivateKey p = (AbePrivateKey)obj;

        boolean result = pubKey.equals(p.pubKey);
        result = result && position.equals(p.position);
        result = result && k1_ij.equals(p.k1_ij);
        result = result && k2_ij.equals(p.k2_ij);
        result = result && k3_ij.equals(p.k3_ij);
        result = result && Arrays.equals(k_ijj, p.k_ijj);
        result = result && Arrays.equals(components.toArray(), p.components.toArray());
        result = result && additionalData.size() == p.additionalData.size();
        for (Map.Entry<String, byte[]> dataEntry : additionalData.entrySet()) {
            if (!p.additionalData.containsKey(dataEntry.getKey()) ||
                    !Arrays.equals(dataEntry.getValue(), p.additionalData.get(dataEntry.getKey()))) {
                result = false;
                break;
            }
        }

        return result;
    }
}