package trabe.tests;

import trabe.*;
import trabe.lw14.Lw14;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import org.junit.BeforeClass;
import org.junit.Test;
import trabe.lw14.Lw14Util;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Arrays;

import static org.junit.Assert.*;

public class ElementVectorTest {

    private static Pairing p;
    private static AbePublicKey pub;

    @BeforeClass
    public static void setup(){
        AbeSecretMasterKey msk = Lw14.setup(4);
        p = msk.getPublicKey().getPairing();
        pub = msk.getPublicKey();
    }

    @Test
    public void createTests(){
        ElementVector v = new ElementVector();
        assertEquals(v.getDimension(), 3);
        assertNull(v.get(0));

        assertEquals(v, v);

        v = new ElementVector(3);
        assertEquals(v.getDimension(), 3);
        assertNull(v.get(0));

        v = new ElementVector(p.getZr());
        assertEquals(v.getDimension(), 3);
        assertNotNull(v.get(0));

        Element e = p.getZr().newRandomElement();
        v = new ElementVector(e, p.getZr().newRandomElement(), p.getZr().newRandomElement());
        assertEquals(v.getDimension(), 3);
        assertTrue(v.get(0).isEqual(e));

        Element[] ea = { p.getZr().newRandomElement(), p.getZr().newRandomElement()};
        v = new ElementVector(ea);
        assertEquals(v.getDimension(), 2);
        assertTrue(v.get(0).isEqual(ea[0]));

        v = new ElementVector(2, p.getZr());
        assertEquals(v.getDimension(), 2);
        assertNotNull(v.get(0));
        assertNotNull(v.get(1));

        int[] values = { 1, 2, 3, 4};
        v = new ElementVector(values, p.getZr());
        assertEquals(v.getDimension(), 4);
        assertNotNull(v.get(0));
        assertTrue(v.get(0).isOne());
        assertNotNull(v.get(1));

        e = p.getZr().newRandomElement();
        v = new ElementVector(2, e);
        assertEquals(v.getDimension(), 2);
        assertTrue(v.get(0).isEqual(e));
        assertTrue(v.get(1).isEqual(e));
        assertTrue(v.get(0) != v.get(1));
    }

    @Test
    public void negativeTests(){
        ElementVector v1 = new ElementVector(2);
        ElementVector v2 = new ElementVector(3);

        assertNotEquals(v1, v2);
        assertNotEquals(v1, 2);
        assertNotEquals(v1, null);

        v1 = new ElementVector(2, p.getZr());
        v2 = new ElementVector(2);
        assertNotEquals(v1, v2);

        v2 = v1.duplicate();
        v2.set(1, p.getG1().newElement()); // element of different types will be different

        assertNotEquals(v1, v2);
    }

    @Test
    public void duplicateTest() {
        ElementVector v = new ElementVector(2, p.getZr());
        ElementVector vd = v.duplicate();
        assertTrue(v != vd);
        assertTrue(v.get(0) != vd.get(0));
        assertTrue(v.equals(vd));
    }

    @Test
    public void addTest() {
        ElementVector v1 = new ElementVector(2, p.getZr());
        ElementVector v2 = new ElementVector(2, p.getZr());
        ElementVector result = v1.duplicate().add(v2);
        for(int i = 0; i < 2; i++) {
            assertTrue(v1.get(i).duplicate().add(v2.get(i)).isEqual(result.get(i)));
        }

        v1.add(v2);
        for(int i = 0; i < 2; i++) {
            assertTrue(v1.get(i).isEqual(result.get(i)));
        }
    }

    @Test
    public void mulTest() {
        ElementVector v1 = new ElementVector(2, p.getZr());
        ElementVector v2 = new ElementVector(2, p.getZr());
        ElementVector result = v1.duplicate().mul(v2);
        for(int i = 0; i < 2; i++) {
            assertTrue(v1.get(i).duplicate().mul(v2.get(i)).isEqual(result.get(i)));
        }

        v1.mul(v2);
        for(int i = 0; i < 2; i++) {
            assertTrue(v1.get(i).isEqual(result.get(i)));
        }

        Element e = p.getZr().newRandomElement();
        ElementVector result2 = v1.duplicate().mul(e);
        for(int i = 0; i < 2; i++) {
            assertTrue(v1.get(i).duplicate().mul(e).isEqual(result2.get(i)));
        }
    }

    @Test
    public void sumTest() {
        int[] values = { 1, 2, 0};
        ElementVector v = new ElementVector(values, p.getZr());
        ElementVector vd = v.duplicate();
        Element result = v.sum();
        assertTrue(result.isEqual(p.getZr().newElement(3)));

        // non-overwriting:
        assertTrue(v.equals(vd));
    }

    @Test
    public void scalarTest() {
        int[] values1 = { 1, 2, 0};
        int[] values2 = { 0, 1, 5};
        ElementVector v1 = new ElementVector(values1, p.getZr());
        ElementVector v1d = v1.duplicate();
        ElementVector v2 = new ElementVector(values2, p.getZr());
        Element result = v1.scalar(v2);
        assertTrue(result.isEqual(p.getZr().newElement(2)));

        // non-overwriting:
        assertTrue(v1.equals(v1d));
    }

    @Test
    public void powTest() {
        ElementVector v = new ElementVector(2, p.getZr());
        ElementVector vd = v.duplicate();

        Element e = p.getZr().newRandomElement();
        Element ed = e.duplicate();
        ElementVector result = v.powInBase(e);
        for(int i = 0; i < 2; i++) {
            assertTrue(e.duplicate().powZn(v.get(i)).isEqual(result.get(i)));
        }

        assertTrue(v.equals(vd));
        assertTrue(v != vd);
        assertTrue(e.equals(ed));
        assertTrue(e != ed);
    }

    @Test
    public void readWriteTest() throws IOException {
        File folder = TestUtil.prepareTestFolder();
        File file = new File(folder, "eVec_out.dat");

        ElementVector v = new ElementVector(6, p.getZr());
        AbeOutputStream os = new AbeOutputStream(new FileOutputStream(file), pub);
        v.writeToStream(os);
        os.flush();
        os.close();

        AbeInputStream is = new AbeInputStream(new FileInputStream(file), pub);
        ElementVector rv = ElementVector.readFromStream(is);
        is.close();

        assertNotNull(rv);
        assertEquals(v, rv);
    }

    @Test
    public void readWriteArrayTest() throws IOException {
        File folder = TestUtil.prepareTestFolder();
        File file = new File(folder, "eVecArray_out.dat");

        ElementVector[] vArray = new ElementVector[10];
        for(int i = 0; i < 10; i++) {
            vArray[i] = new ElementVector(6, p.getZr());
        }

        AbeOutputStream os = new AbeOutputStream(new FileOutputStream(file), pub);
        Lw14Util.writeArray(vArray, os);
        os.flush();
        os.close();

        AbeInputStream is = new AbeInputStream(new FileInputStream(file), pub);
        ElementVector[] rvArray = Lw14Util.readElementVectorArray(is);
        is.close();

        assertNotNull(rvArray);
        assertTrue(Arrays.equals(vArray, rvArray));
    }
}
