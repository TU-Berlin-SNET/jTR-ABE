package trabe.lw14;

import it.unisa.dia.gas.jpbc.Element;

public class Lw14Polynomial {
    /* coefficients from [0] x^0 to [deg] x^deg */
    public Element[] coef; /* G_T (of length deg+1) */

    private Lw14Polynomial(int deg) {
        coef = new Element[deg + 1];
    }

    /**
     * Generates a new polynomial with random coefficients of the element type given as zeroVal. The 0th coefficient has the same
     * value as zeroVal.
     * 
     * @param deg       number of coefficients
     * @param zeroVal   Zero element
     * @return Random polynomial
     */
    public static Lw14Polynomial createRandom(int deg, Element zeroVal) {
        Lw14Polynomial newPoly = new Lw14Polynomial(deg);
        for (int i = 0; i < newPoly.coef.length; i++)
            newPoly.coef[i] = zeroVal.duplicate();

        newPoly.coef[0].set(zeroVal);

        for (int i = 1; i < newPoly.coef.length; i++)
            newPoly.coef[i].setToRandom();
        return newPoly;
    }

}
