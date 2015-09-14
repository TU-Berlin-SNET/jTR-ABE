package trabe.lw14;

import trabe.AbeInputStream;
import trabe.AbeOutputStream;
import trabe.AbePublicKey;
import trabe.ElementVector;
import trabe.lw14.policy.LsssMatrix;
import it.unisa.dia.gas.jpbc.Element;
import trabe.lw14.policy.Lw14PolicyAbstractNode;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

public class CipherText {

    public LsssMatrix accessMatrix = null;
    public Lw14PolicyAbstractNode accessTree = null;
    /** G_1 **/
    public ElementVector[] r1;
    /** G_1 **/
    public ElementVector[] r2;
    /** G_1 **/
    public Element[] q1;
    /** G_1 **/
    public Element[] q2;
    /** G_1 **/
    public Element[] q3;
    /** G_T **/
    public Element[] t;
    /** G_1 **/
    public ElementVector[] c1;
    /** G_1 **/
    public ElementVector[] c2;
    /** G_1 **/
    public Element[] p1;
    /** G_1 **/
    public Element[] p2;
    /** G_1 **/
    public Element[] p3;
    public String policy;

    public int[] revokedUserIndexes;

    private CipherText(){}

    public CipherText(LsssMatrix accessMatrix, ElementVector[] r1, ElementVector[] r2,
                      Element[] q1, Element[] q2, Element[] q3, Element[] t,
                      ElementVector[] c1, ElementVector[] c2,
                      Element[] p1, Element[] p2, Element[] p3,
                      String policy, int[] revokedUserIndexes) {
        this.accessMatrix = accessMatrix;
        this.r1 = r1;
        this.r2 = r2;
        this.q1 = q1;
        this.q2 = q2;
        this.q3 = q3;
        this.t = t;
        this.c1 = c1;
        this.c2 = c2;
        this.p1 = p1;
        this.p2 = p2;
        this.p3 = p3;
        this.policy = policy;
        this.revokedUserIndexes = revokedUserIndexes;
    }

    public CipherText(Lw14PolicyAbstractNode accessTree, ElementVector[] r1, ElementVector[] r2,
                      Element[] q1, Element[] q2, Element[] q3, Element[] t,
                      ElementVector[] c1, ElementVector[] c2,
                      String policy, int[] revokedUserIndexes) {
        this.accessTree = accessTree;
        this.r1 = r1;
        this.r2 = r2;
        this.q1 = q1;
        this.q2 = q2;
        this.q3 = q3;
        this.t = t;
        this.c1 = c1;
        this.c2 = c2;
        this.policy = policy;
        this.revokedUserIndexes = revokedUserIndexes;
    }

    public void writeToStream(AbeOutputStream stream) throws IOException {
        boolean isAccessStructure = isAccessMatrix();
        stream.writeBoolean(isAccessStructure);
        if (isAccessStructure) {
            accessMatrix.writeToStream(stream);
        } else {
            accessTree.writeToStream(stream);
        }
        Lw14Util.writeArray(r1, stream);
        Lw14Util.writeArray(r2, stream);
        Lw14Util.writeArray(q1, stream);
        Lw14Util.writeArray(q2, stream);
        Lw14Util.writeArray(q3, stream);
        Lw14Util.writeArray(t, stream);
        Lw14Util.writeArray(c1, stream);
        Lw14Util.writeArray(c2, stream);
        if (isAccessStructure) {
            Lw14Util.writeArray(p1, stream);
            Lw14Util.writeArray(p2, stream);
            Lw14Util.writeArray(p3, stream);
        }
        stream.writeString(policy);
        Lw14Util.writeArray(revokedUserIndexes, stream);
    }

    public boolean isAccessMatrix() {
        return accessMatrix != null;
    }

    @Override
    public boolean equals(Object ct) {
        if (ct == null || !(ct instanceof CipherText)) {
            return false;
        } else if(this == ct) {
            return true;
        }
        CipherText c = (CipherText)ct;

        boolean result = isAccessMatrix() == c.isAccessMatrix();
        if (isAccessMatrix()) {
            result = result && accessMatrix.equals(c.accessMatrix);
        } else {
            result = result && accessTree.equals(c.accessTree);
        }
        result = result && Arrays.equals(r1, c.r1);
        result = result && Arrays.equals(r2, c.r2);
        result = result && Arrays.equals(q1, c.q1);
        result = result && Arrays.equals(q2, c.q2);
        result = result && Arrays.equals(q3, c.q3);
        result = result && Arrays.equals(t, c.t);
        result = result && Arrays.equals(c1, c.c1);
        result = result && Arrays.equals(c2, c.c2);
        result = result && Arrays.equals(p1, c.p1);
        result = result && Arrays.equals(p2, c.p2);
        result = result && Arrays.equals(p3, c.p3);
        result = result && policy.equals(c.policy);
        result = result && Arrays.equals(revokedUserIndexes, c.revokedUserIndexes);

        return result;
    }

    public static CipherText readFromStream(AbeInputStream stream) throws IOException {
        CipherText ct = new CipherText();

        boolean isAccessStructure = stream.readBoolean();
        if (isAccessStructure) {
            ct.accessMatrix = LsssMatrix.readFromStream(stream);
        } else {
            ct.accessTree = Lw14PolicyAbstractNode.readFromStream(stream);
        }

        ct.r1 = Lw14Util.readElementVectorArray(stream);
        ct.r2 = Lw14Util.readElementVectorArray(stream);
        ct.q1 = Lw14Util.readElementArray(stream);
        ct.q2 = Lw14Util.readElementArray(stream);
        ct.q3 = Lw14Util.readElementArray(stream);
        ct.t = Lw14Util.readElementArray(stream);
        ct.c1 = Lw14Util.readElementVectorArray(stream);
        ct.c2 = Lw14Util.readElementVectorArray(stream);
        if (isAccessStructure) {
            ct.p1 = Lw14Util.readElementArray(stream);
            ct.p2 = Lw14Util.readElementArray(stream);
            ct.p3 = Lw14Util.readElementArray(stream);
        }
        ct.policy = stream.readString();
        ct.revokedUserIndexes = Lw14Util.readIntegerArray(stream);

        return ct;
    }

    public byte[] getAsByteArray(AbePublicKey pub) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        AbeOutputStream stream = new AbeOutputStream(baos, pub);
        this.writeToStream(stream);
        return baos.toByteArray();
    }

    public static CipherText readFromByteArray(byte[] data, AbePublicKey pub) throws IOException {
        AbeInputStream stream = new AbeInputStream(new ByteArrayInputStream(data), pub);
        try {
            return readFromStream(stream);
        } finally {
            stream.close();
        }
    }
}
