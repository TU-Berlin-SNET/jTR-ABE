package trabe.policyparser;

public class ASTOf extends SimpleNode {
	private int number;

	public ASTOf(int id) {
		super(id);
	}

	public ASTOf(PolicyParser p, int id) {
		super(p, id);
	}

	public void setNumber(String numberString) {
		this.number = Integer.parseInt(numberString);
	}

	public int getNumber() {
		return number;
	}

	public String toString() {
		return "Of: " + number;
	}
}
