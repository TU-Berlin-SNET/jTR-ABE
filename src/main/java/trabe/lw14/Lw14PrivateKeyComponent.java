package trabe.lw14;

import it.unisa.dia.gas.jpbc.Element;
import trabe.AbeInputStream;
import trabe.AbeOutputStream;

import java.io.IOException;

public class Lw14PrivateKeyComponent {
    /* these actually get serialized */

    /** Z_r **/
    public Element hashedAttributeZr;
    public String attribute;
    /** G_1 **/
    public Element k1_ijx;
    /** G_1 **/
    public Element k2_ijx;

    public Element k1Tilde_ijx;
    public Element k2Tilde_ijx;

    private Lw14PrivateKeyComponent(){}

    public Lw14PrivateKeyComponent(String attribute, Element hashedAttributeZr, Element k1_ijx, Element k2_ijx, Element k1Tilde_ijx, Element k2Tilde_ijx) {
        this.attribute = attribute;
        this.hashedAttributeZr = hashedAttributeZr;
        this.k1_ijx = k1_ijx;
        this.k2_ijx = k2_ijx;
        this.k1Tilde_ijx = k1Tilde_ijx;
        this.k2Tilde_ijx = k2Tilde_ijx;
    }

    public void writeToStream(AbeOutputStream stream) throws IOException {
        stream.writeString(attribute);
        stream.writeElement(hashedAttributeZr);
        stream.writeElement(k1_ijx);
        stream.writeElement(k2_ijx);
    }

    public static Lw14PrivateKeyComponent readFromStream(AbeInputStream stream, int serializeVersion) throws IOException {
        Lw14PrivateKeyComponent component = new Lw14PrivateKeyComponent();

        component.attribute = stream.readString();
        if (serializeVersion < 3) {
            stream.readElement();
        }
        component.hashedAttributeZr = stream.readElement();
        component.k1_ijx = stream.readElement();
        component.k2_ijx = stream.readElement();

        return component;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null || !(obj instanceof Lw14PrivateKeyComponent)) {
            return false;
        } else if(this == obj) {
            return true;
        }
        Lw14PrivateKeyComponent component = (Lw14PrivateKeyComponent)obj;

        boolean result = attribute.equals(component.attribute);
        result = result && k1_ijx.equals(component.k1_ijx);
        result = result && k2_ijx.equals(component.k2_ijx);

        return result;
    }
}
