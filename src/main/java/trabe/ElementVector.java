package trabe;

import trabe.lw14.Lw14Util;
import trabe.lw14.policy.LsssMatrix;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;

import java.io.IOException;

public class ElementVector {
    private int dimension;
    private Element[] vector;

    public ElementVector(Element[] vector) {
        this.dimension = vector.length;
        this.vector = vector;
    }

    /**
     * Initialize vector from matrix row.
     * @param vector    Integer vector
     * @param zr        Zr group identifier
     */
    public ElementVector(int[] vector, Field zr) {
        dimension = vector.length;
        this.vector = new Element[dimension];
        for(int i = 0; i < dimension; i++) {
            this.vector[i] = zr.newElement(vector[i]);
        }
    }

    /**
     * Initialize a three dimensional vector.
     * @param x1    Element 1
     * @param x2    Element 2
     * @param x3    Element 3
     */
    public ElementVector(Element x1, Element x2, Element x3){
        this.dimension = 3;
        this.vector = new Element[]{x1, x2, x3};
    }

    /**
     * Create a vector.
     * @param dimension     Dimension of the intended vector
     */
    public ElementVector(int dimension){
        this.dimension = dimension;
        this.vector = new Element[dimension];
    }

    /**
     * Initialize a vector with the same element.
     * @param dimension     Dimension of the intended vector
     * @param e             Element that is set to all components
     */
    public ElementVector(int dimension, Element e){
        this.dimension = dimension;
        this.vector = new Element[dimension];
        for(int i = 0; i < dimension; i++){
            this.vector[i] = e.duplicate();
        }
    }

    /**
     * Create a three dimensional vector.
     */
    public ElementVector(){
        this(3);
    }

    /**
     * Initialize a random three-dimensional vector.
     * @param field        Field type where the random elements should be in
     */
    public ElementVector(Field field){
        this(3, field);
    }

    /**
     * Initialize a random vector.
     * @param dimension    Dimension of the intended vector
     * @param field        Field type where the random elements should be in
     */
    public ElementVector(int dimension, Field field){
        this.dimension = dimension;
        this.vector = new Element[dimension];
        for(int i = 0; i < dimension; i++){
            this.vector[i] = field.newRandomElement();
        }
    }

    public int getDimension(){
        return dimension;
    }

    public Element get(int i){
        return vector[i];
    }

    public void set(int i, Element x){
        vector[i] = x;
    }

    /**
     * Operations on vectors run on the vector itself, so a copy is needed.
     * @return Copy of the vector
     */
    public ElementVector duplicate(){
        Element[] newVector = new Element[dimension];
        for(int i = 0; i < dimension; i++){
            newVector[i] = vector[i].duplicate();
        }
        return new ElementVector(newVector);
    }

    /**
     * Multiply two vectors to get a changed vector. The original vector will be overwritten.
     * Use <code>duplicate()</code> to get a copy.
     *
     * @param v Second vector
     * @return this
     */
    public ElementVector mul(ElementVector v) {
        if (dimension != v.getDimension()) {
            return null;
        }
        for(int i = 0; i < dimension; i++){
            vector[i].mul(v.get(i));
        }
        return this;
    }

    /**
     * Multiply the current vector with a scalar and return it. The original vector will be overwritten.
     * Use <code>duplicate()</code> to get a copy.
     * @param e Element to multiply with
     * @return this
     */
    public ElementVector mul(Element e) {
        for(int i = 0; i < dimension; i++){
            vector[i].mul(e);
        }
        return this;
    }

    /**
     * Computes the scalar product between two vectors. Duplicating is not necessary.
     *
     * @param v Second vector
     * @return Product
     */
    public Element scalar(ElementVector v) {
        return duplicate().mul(v).sum();
    }

    /**
     * Sums all of the components of the vector into a single element. Duplication is not necessary.
     * @return Sum of components
     */
    public Element sum(){
        Element result = vector[0].duplicate();
        for(int i = 1; i < dimension; i++){
            result.add(vector[i]);
        }
        return result;
    }

    /**
     * Adds all the components of the second vector to the current vector. Duplication might be necessary.
     * @param v Second vector
     * @return this
     */
    public ElementVector add(ElementVector v) {
        if (dimension != v.getDimension()) {
            return null;
        }
        for(int i = 0; i < dimension; i++){
            vector[i].add(v.get(i));
        }
        return this;
    }

    /**
     * Raises the passed base element to each of the current vector's components
     * to produce a new vector. Duplication is not necessary. The base vector
     * will not be manipulated.
     * @param base Base for each component
     * @return New vector
     */
    public ElementVector powInBase(Element base) {
        Element[] newVector = new Element[dimension];
        for(int i = 0; i < dimension; i++){
            newVector[i] = base.duplicate().powZn(vector[i]);
        }
        return new ElementVector(newVector);
    }

    /**
     * Computes the pairing of this vector with the second vector component wise
     * and multiplies all the values resulting values in G_T. Duplication is not necessary.
     * @param pairing   Pairing which contains the parameters for the pairing
     * @param vector    Second vector
     * @return new element
     */
    public Element newPair(Pairing pairing, ElementVector vector) {
        if (dimension != vector.getDimension()) {
            return null;
        }
        Element element = pairing.getGT().newOneElement();
        for(int i = 0; i < dimension; i++){
            element = element.mul(pairing.pairing(this.vector[i], vector.get(i))); // assignment not necessary
        }
        return element;
    }

    public boolean equals(Object v) {
        if (this == v) {
            return true;
        }
        if (null == v || !this.getClass().equals(v.getClass())) {
            return false;
        }
        ElementVector ev = (ElementVector)v;
        if (dimension != ev.getDimension()) {
            return false;
        }
        for(int i = 0; i < dimension; i++) {
            if ((vector[i] != null && ev.get(i) == null) || (vector[i] == null && ev.get(i) != null) || !vector[i].isEqual(ev.get(i))) {
                return false;
            }
        }
        return true;
    }

    public String toString(){
        String separator = ", ";
        StringBuilder builder = new StringBuilder();
        builder.append("V[");
        for (int i = 0, il = dimension; i < il; i++) {
            if (i > 0) {
                builder.append(separator);
            }
            builder.append(vector[i]);
        }
        builder.append("]");
        return builder.toString();
    }

    public static ElementVector createFrom(LsssMatrix matrix, int row, Field zr) {
        return matrix.getAttributeRow(row, zr);
    }

    public void writeToStream(AbeOutputStream stream) throws IOException {
        Lw14Util.writeArray(vector, stream);
    }

    public static ElementVector readFromStream(AbeInputStream stream) throws IOException {
        return new ElementVector(Lw14Util.readElementArray(stream));
    }
}
