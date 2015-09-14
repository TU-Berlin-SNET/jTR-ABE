package trabe.tests;

import static org.junit.Assert.*;

import trabe.AbePublicKey;
import trabe.AbeSecretMasterKey;
import trabe.ElementVector;
import trabe.lw14.Lw14;
import trabe.lw14.policy.LsssMatrix;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import org.junit.Test;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

public class LsssTest {

    @Test
    public void testExampleLsssPolicy() throws Exception{
        // the test data comes from http://eprint.iacr.org/2010/351
        String p = "a and (d or (b and c))";
        int[][] expectedMatrix = {
                { 1, 1, 0 },
                { 0, -1, 1 },
                { 0, 0, -1 },
                { 0, -1, 0 }};

        AbeSecretMasterKey msk = Lw14.setup(4);
        AbePublicKey pub = msk.getPublicKey();

        LsssMatrix matrix = LsssMatrix.createMatrixFromBooleanFormula(p, pub);

        assertEquals(4, matrix.getAttributes());
        assertEquals(3, matrix.getColumns());

        int i = 0;
        for(int[] row : expectedMatrix) {
            int j = 0;
            for(int value : row) {
                assertEquals(matrix.get(i, j).value, value);
                j++;
            }
            i++;
        }
    }

    @Test
    public void testExampleThresholdLsssPolicy() throws Exception{
        HashMap<String, Integer[][]> matrixesForPolicies = new HashMap<String, Integer[][]>(3);

        matrixesForPolicies.put("a and b and c", new Integer[][]{
                { 1, 1, 1 },
                { 1, 2, 4 },
                { 1, 3, 9 },
        });
        matrixesForPolicies.put("a or b or c", new Integer[][]{
                { 1 },
                { 1 },
                { 1 },
        });
        matrixesForPolicies.put("d or (a and b and c) or e", new Integer[][]{
                { 1, 0, 0 },
                { 1, 1, 1 },
                { 1, 2, 4 },
                { 1, 3, 9 },
                { 1, 0, 0 },
        });
        matrixesForPolicies.put("d and (a or b or c) and e", new Integer[][]{
                { 1, 1, 1 },
                { 1, 2, 4 },
                { 1, 2, 4 },
                { 1, 2, 4 },
                { 1, 3, 9 },
        });
        matrixesForPolicies.put("d and 1 of (a, b, c) and e", new Integer[][]{
                { 1, 1, 1 },
                { 1, 2, 4 },
                { 1, 2, 4 },
                { 1, 2, 4 },
                { 1, 3, 9 },
        });
        matrixesForPolicies.put("d and 2 of (a, b, c) and e", new Integer[][]{
                { 1, 1, 1, 0 },
                { 1, 2, 4, 1 },
                { 1, 2, 4, 2 },
                { 1, 2, 4, 3 },
                { 1, 3, 9, 0 },
        });
        matrixesForPolicies.put("3 of (a, b, c, d)", new Integer[][]{
                { 1, 1, 1 },
                { 1, 2, 4 },
                { 1, 3, 9 },
                { 1, 4, 16 },
        });
        matrixesForPolicies.put("3 of (e, f, g, 3 of (a, b, c, d))", new Integer[][]{
                { 1, 1, 1, 0, 0 },
                { 1, 2, 4, 0, 0 },
                { 1, 3, 9, 0, 0 },
                { 1, 4, 16, 1, 1 },
                { 1, 4, 16, 2, 4 },
                { 1, 4, 16, 3, 9 },
                { 1, 4, 16, 4, 16 },
        });
        matrixesForPolicies.put("2 of (a, 2 of (c, d, e), b)", new Integer[][]{
                { 1, 1, 0 },
                { 1, 2, 1 },
                { 1, 2, 2 },
                { 1, 2, 3 },
                { 1, 3, 0 },
        });
        matrixesForPolicies.put("2 of (a, 3 of (c, d, e), b)", new Integer[][]{
                { 1, 1, 0, 0 },
                { 1, 2, 1, 1 },
                { 1, 2, 2, 4 },
                { 1, 2, 3, 9 },
                { 1, 3, 0, 0 },
        });
        matrixesForPolicies.put("1 of (a, 1 of (c, d, e), b)", new Integer[][]{
                { 1 },
                { 1 },
                { 1 },
                { 1 },
                { 1 },
        });


        AbeSecretMasterKey msk = Lw14.setup(4);
        AbePublicKey pub = msk.getPublicKey();
        Field zR = pub.getPairing().getZr();

        LsssMatrix matrix;
        Integer[][] expectedMatrix;
        Integer[] expectedRow;
        for(Map.Entry<String, Integer[][]> e : matrixesForPolicies.entrySet()) {
            matrix = LsssMatrix.createMatrixFromThresholdFormula(e.getKey(), pub);
            expectedMatrix = e.getValue();
            assertEquals(matrix.getAttributes(), expectedMatrix.length);
            for(int i = 0; i < expectedMatrix.length; i++) {
                expectedRow = expectedMatrix[i];
                assertEquals(matrix.getColumns(), expectedRow.length);
                for(int j = 0; j < expectedRow.length; j++) {
                    assertEquals((Integer)matrix.get(i, j).value, expectedRow[j]);
                }
            }
        }
    }

    @Test
    public void testElementVectorFromLsssPolicy() throws Exception{
        // the test data comes from http://eprint.iacr.org/2010/351
        String p = "a and (d or (b and c))";
        int[][] expectedMatrix = {
                { 1, 1, 0 },
                { 0, -1, 1 },
                { 0, 0, -1 },
                { 0, -1, 0 }};

        AbeSecretMasterKey msk = Lw14.setup(4);
        AbePublicKey pub = msk.getPublicKey();

        LsssMatrix matrix = LsssMatrix.createMatrixFromBooleanFormula(p, pub);

        assertEquals(4, matrix.getAttributes());
        assertEquals(3, matrix.getColumns());

        Field zr = pub.getPairing().getZr();

        for (int row = 0; row < matrix.getAttributes(); row++) {
            ElementVector ev = matrix.getAttributeRow(row, zr);
            assertEquals(ev.getDimension(), matrix.getColumns());
            for(int cell = 0; cell < ev.getDimension(); cell++) {
                Element expectedValue = zr.newElement(expectedMatrix[row][cell]);
                assertTrue(expectedValue.isEqual(ev.get(cell)));
            }
        }

        int i = 0;
        for(int[] row : expectedMatrix) {
            ElementVector v = ElementVector.createFrom(matrix, i, pub.getPairing().getZr());
            int j = 0;
            for(int value : row) {
                assertTrue(v.get(j).isEqual(pub.getPairing().getZr().newElement(value)));
                j++;
            }
            i++;
        }
    }

    @Test
    public void testElementPowerMinusOne() throws Exception{
        AbeSecretMasterKey msk = Lw14.setup(4);
        AbePublicKey pub = msk.getPublicKey();

        Field zr = pub.getPairing().getZr();
        Field gt = pub.getPairing().getGT();

        Element t1 = gt.newRandomElement();
        Element minusOne = zr.newElement(BigInteger.valueOf(-1));

//        System.out.println("t:  " + t1);
//        System.out.println("-1: " + minusOne);

        Element halfMinusOne = minusOne.duplicate().div(zr.newElement(BigInteger.valueOf(2)));

        Element tPowMinusOne = t1.duplicate().powZn(minusOne);
        Element tPowHalfMinusOneMulTPowHalfMinusOne = t1.duplicate().powZn(halfMinusOne).mul(t1.duplicate().powZn(halfMinusOne));

//        System.out.println("-1/2: " + halfMinusOne);
//        System.out.println("t^{-1}:            " + tPowMinusOne);
//        System.out.println("t^{-1/2}*t^{-1/2}: " + tPowHalfMinusOneMulTPowHalfMinusOne);

        assertEquals(tPowMinusOne, tPowHalfMinusOneMulTPowHalfMinusOne);
    }

    /*
    @Test
    public void testWkGeneration() throws Exception{
        // the test data comes from http://eprint.iacr.org/2010/351
        String p = "a and (d or (b and c))";
        int[][] baseMatrix = {
                { 1, 1, 0 },
                { 0, -1, 1 },
                { 0, 0, -1 },
                { 0, -1, 0 }};
        int[][] transposed = {
                { 1, 0, 0, 0 },
                { 1, -1, 0, -1 },
                { 0, 1, -1, 0 }};
        int[][] transposedABC = {
                { 1, 0, 0 },
                { 1, -1, 0 },
                { 0, 1, -1 }};
        int[][] transposedABD = {
                { 1, 0, 0 },
                { 1, -1, -1 },
                { 0, 1, 0 }};
        int[][] transposedACD = {
                { 1, 0, 0 },
                { 1, 0, -1 },
                { 0, -1, 0 }};
        int[][] transposedBCD = {
                { 0, 0, 0 },
                { -1, 0, -1 },
                { 1, -1, 0 }};

        int[][] andMatrix = {
                { 0, 0, 0, 1 },
                { -1, 0, 0, 1 },
                { 0, -1, 0, 1 },
                { 0, -0, -1, 1 }};

        int[][] matrix = andMatrix;

        AbeSecretMasterKey msk = Lw14.setup(4);
        AbePublicKey pub = msk.getPublicKey();
        Field zr = pub.getPairing().getZr();
        ElementField ef = new ElementField(zr);

        Matrix<Element> mat = new Matrix<Element>(matrix.length, matrix[0].length, ef);

        int i = 0;
        for(int[] row : matrix) {
            int j = 0;
            for(int value : row) {
                mat.set(i, j, zr.newElement(value));
                j++;
            }
            i++;
        }

        //mat.invert();
        mat.reducedRowEchelonForm();

        for (i = 0; i < mat.rowCount(); i++) {
            for (int j = 0; j < mat.columnCount(); j++) {
                if (j > 0)
                    System.out.print(" ");
                System.out.print(mat.get(i, j));
            }
            System.out.println();
        }
    }
    */
}
