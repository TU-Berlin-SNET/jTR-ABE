package trabe;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.plaf.jpbc.field.curve.CurveElement;

import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;

public class AbeOutputStream extends DataOutputStream {
    
    private final AbePublicKey pubKey;

    public AbeOutputStream(OutputStream out, AbePublicKey pubKey) {
        super(out);
        this.pubKey = pubKey;
    }

    // only used for the curve parameters and attributes, no need for fancy encodings
    public void writeString(String string) throws IOException {
        byte[] bytes = string.getBytes(AbeSettings.STRINGS_LOCALE);
        writeInt(bytes.length);
        write(bytes);
    }

    public void writeElement(Element elem) throws IOException {
        writeBoolean(elem == null);
        if (elem == null) {
            return;
        }
        writeInt(pubKey.getPairing().getFieldIndex(elem.getField()));
        byte[] bytes = elem.toBytes();
        writeInt(bytes.length);
        write(bytes);

        // this is a workaround because it.unisa.dia.gas.plaf.jpbc.field.curve.CurveElement does not serialize the infFlag
        writeBoolean(elem instanceof CurveElement && elem.isZero());
        if (elem instanceof CurveElement && elem.isZero()) {
            throw new IOException("Infinite element detected. They should not happen.");
        }
    }

}
