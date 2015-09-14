package trabe.lw14.policy;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;

import trabe.AbeInputStream;
import trabe.AbeOutputStream;
import trabe.AbePrivateKey;
import trabe.AbePublicKey;
import it.unisa.dia.gas.jpbc.Element;
import trabe.policyparser.ParseException;

public abstract class Lw14PolicyAbstractNode {
    protected boolean satisfiable;
    protected int     minLeaves;

    public abstract void fillPolicy(AbePublicKey pub, Element e);

    protected abstract boolean checkSatisfySpecific(AbePrivateKey prv);

    public boolean checkSatisfy(AbePrivateKey prv) {
        satisfiable = checkSatisfySpecific(prv);
        return satisfiable;
    }

    public abstract void pickSatisfyMinLeaves(AbePrivateKey prv);

    protected abstract void decFlattenSpecific(Element r, Element one, AbePrivateKey prv);

    public void decFlatten(Element r, AbePrivateKey prv) {
        Element one = prv.getPublicKey().getPairing().getZr().newOneElement();
        r.setToOne();
        decFlattenSpecific(r, one, prv);
    }

    public abstract int getThreshold();

    public abstract void writeToStream(AbeOutputStream stream) throws IOException;

    public static Lw14PolicyAbstractNode readFromStream(AbeInputStream stream) throws IOException {
        int threshold = stream.readInt();
        int numberOfChildren = stream.readInt();
        if (numberOfChildren == 0) { // is leaf
            Element hashedAttribute = stream.readElement();
            Element p1 = stream.readElement();
            Element p2 = stream.readElement();
            Element p3 = stream.readElement();
            return new Lw14PolicyLeafNode(hashedAttribute, p1, p2, p3);
        } else {
            Lw14PolicyParentNode tmp = new Lw14PolicyParentNode(threshold, numberOfChildren);
            for (int i = 0; i < numberOfChildren; i++) {
                Lw14PolicyAbstractNode readPolicy = Lw14PolicyAbstractNode.readFromStream(stream);
                tmp.addChild(readPolicy);
            }
            return tmp;
        }
    }

    public static Lw14PolicyAbstractNode parsePolicy(String s, AbePublicKey publicKey) throws ParseException {
        ArrayList<Lw14PolicyAbstractNode> stack = new ArrayList<Lw14PolicyAbstractNode>();
        String[] toks = s.split("\\s+");
        for (int index = 0; index < toks.length; index++) {
            String curToken = toks[index];
            if (!curToken.contains("of")) {
                stack.add(new Lw14PolicyLeafNode(curToken, publicKey));
            } else {
                String[] k_n = curToken.split("of"); /* parse kofn node */
                int threshold = Integer.parseInt(k_n[0]);
                int numChildren = Integer.parseInt(k_n[1]);

                if (threshold < 1) {
                    throw new ParseException("error parsing " + s + ": trivially satisfied operator " + curToken);
                } else if (threshold > numChildren) {
                    throw new ParseException("error parsing " + s + ": unsatisfiable operator " + curToken);
                } else if (numChildren == 1) {
                    throw new ParseException("error parsing " + s + ": indentity operator " + curToken);
                } else if (numChildren > stack.size()) {
                    throw new ParseException("error parsing " + s + ": stack underflow at " + curToken);
                }

                /* pop n things and fill in children */
                Lw14PolicyParentNode node = new Lw14PolicyParentNode(threshold, numChildren);
                Lw14PolicyAbstractNode[] tmp = new Lw14PolicyAbstractNode[numChildren];

                for (int i = numChildren - 1; i >= 0; i--)
                    tmp[i] = stack.remove(stack.size() - 1);

                node.addAllChildren(Arrays.asList(tmp));
                /* push result */
                stack.add(node);
            }
        }

        if (stack.size() > 1) {
            throw new ParseException("error parsing " + s + ": extra node left on the stack");
        } else if (stack.size() < 1) {
            throw new ParseException("error parsing " + s + ": empty policy");
        }
        return stack.get(0); // the root of the tree
    }
}
