package trabe.matrixElimination;

import it.unisa.dia.gas.jpbc.Element;

public final class ElementField extends Field<Element> {

    public final it.unisa.dia.gas.jpbc.Field field;

	public ElementField(it.unisa.dia.gas.jpbc.Field field) {
        this.field = field;
	}


	public Element zero() {
		return field.newZeroElement();
	}
	
	public Element one() {
		return field.newOneElement();
	}
	
	
	public Element add(Element x, Element y) {
        return x.duplicate().add(y);
	}
	
	public Element multiply(Element x, Element y) {
        return x.duplicate().mul(y);
	}
	
	
	public Element negate(Element x) {
        return x.duplicate().negate();
	}
	
	
	public Element reciprocal(Element x) {
        return x.duplicate().invert();
	}
	
	
	public boolean equals(Element x, Element y) {
        return x.isEqual(y);
	}
	
}
