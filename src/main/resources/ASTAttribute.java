package trabe.policyparser;

public class ASTAttribute extends SimpleNode {
	private String name;

	public ASTAttribute(int id) {
		super(id);
	}

	public ASTAttribute(PolicyParser p, int id) {
		super(p, id);
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getName() {
		return name;
	}

	public String toString() {
		return "Attribute: " + name;
	}
}
