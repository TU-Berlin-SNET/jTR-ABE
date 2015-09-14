package trabe.policyparser;

import java.math.BigInteger;

public class ASTNumericalAttribute extends SimpleNode {
    private String name;
    private String op;
    private BigInteger value;
    
    
    public ASTNumericalAttribute(int id) {
        super(id);
    }

    public ASTNumericalAttribute(PolicyParser p, int id) {
        super(p, id);
    }
    
    public void setValues(String name, String op, String number) {
        this.name = name;
        this.op = op;
        this.value = new BigInteger(number);
    }

    public String getName() {
        return name;
    }
    
    public String getOp() {
        return op;
    }
    
    public BigInteger getValue() {
        return value;
    }
    
    public String toString() {
        return "NumericalAttribute: " + name + " " + op + " " + value;
    }
}