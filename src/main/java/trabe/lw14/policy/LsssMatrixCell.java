package trabe.lw14.policy;

import it.unisa.dia.gas.jpbc.Element;
import trabe.AbeInputStream;
import trabe.AbeOutputStream;

import java.io.IOException;

/**
 *
 */
public class LsssMatrixCell {
    public int i;
    public int j;
    public int value;
    public String attribute;
    public Element hashedElement;

    private LsssMatrixCell(){}

    public LsssMatrixCell(int i, int j, int value, String attribute, Element hashedElement) {
        this.i = i;
        this.j = j;
        this.value = value;
        this.attribute = attribute;
        this.hashedElement = hashedElement;
    }

    public String toString(){
        return "["+i+","+j+"] " + attribute + ": " + value + "(" + hashedElement + ")";
    }

    public void writeToStream(AbeOutputStream stream) throws IOException {
        stream.writeInt(value);
        stream.writeString(attribute);
        stream.writeElement(hashedElement);
    }

    public static LsssMatrixCell readFromStream(AbeInputStream stream) throws IOException {
        LsssMatrixCell cell = new LsssMatrixCell();

        cell.value = stream.readInt();
        cell.attribute = stream.readString();
        cell.hashedElement = stream.readElement();

        return cell;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null || !(obj instanceof LsssMatrixCell)) {
            return false;
        } else if(this == obj) {
            return true;
        }
        LsssMatrixCell c = (LsssMatrixCell)obj;
        return i == c.i && j == c.j && value == c.value && attribute.equals(c.attribute) && hashedElement.equals(c.hashedElement);
    }
}
