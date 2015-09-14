package trabe.lw14;

import it.unisa.dia.gas.jpbc.Element;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

import trabe.*;
import it.unisa.dia.gas.jpbc.Field;
import trabe.lw14.policy.Lw14PolicyAbstractNode;
import trabe.policy.PolicyParsing;
import trabe.policyparser.*;

public class Lw14Util {
    private enum ElementType { G1, G2, GT, Zr}

    private static Element elementFromString(ElementType et, String s, AbePublicKey publicKey) {
        try {
            MessageDigest hasher = MessageDigest.getInstance(AbeSettings.ELEMENT_HASHING_ALGORITHM);
            byte[] digest = hasher.digest(s.getBytes());
            Field field;
            switch (et){
                case G1:
                    field = publicKey.getPairing().getG1();
                    break;
                case G2:
                    field = publicKey.getPairing().getG2();
                    break;
                case GT:
                    field = publicKey.getPairing().getGT();
                    break;
                case Zr:
                    field = publicKey.getPairing().getZr();
                    break;
                default:
                    return null;
            }
            return field.newElementFromHash(digest, 0, digest.length);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            System.exit(1);
        }
        return null;
    }

    public static Element elementG1FromString(String s, AbePublicKey publicKey) {
        return elementFromString(ElementType.G1, s, publicKey);
    }

    public static Element elementG2FromString(String s, AbePublicKey publicKey) {
        return elementFromString(ElementType.G2, s, publicKey);
    }

    public static Element elementGtFromString(String s, AbePublicKey publicKey) {
        return elementFromString(ElementType.GT, s, publicKey);
    }

    public static Element elementZrFromString(String s, AbePublicKey publicKey) {
        return elementFromString(ElementType.Zr, s, publicKey);
    }

    public static void writeArray(Element[] array, AbeOutputStream stream) throws IOException {
        writeArray(array, stream, true);
    }

    public static void writeArray(Element[] array, AbeOutputStream stream, boolean withHeader) throws IOException {
        if (withHeader){
            stream.writeInt(array.length);
        }
        for(int i = 0; i < array.length; i++) {
            stream.writeElement(array[i]);
        }
    }

    public static void writeArray(int[] array, AbeOutputStream stream) throws IOException {
        writeArray(array, stream, true);
    }

    public static void writeArray(int[] array, AbeOutputStream stream, boolean withHeader) throws IOException {
        if (withHeader){
            stream.writeInt(array.length);
        }
        for(int i = 0; i < array.length; i++) {
            stream.writeInt(array[i]);
        }
    }

    public static void writeArray(ElementVector[] array, AbeOutputStream stream) throws IOException {
        writeArray(array, stream, true);
    }

    public static void writeArray(ElementVector[] array, AbeOutputStream stream, boolean withHeader) throws IOException {
        if (withHeader) {
            stream.writeInt(array.length);
        }
        for (ElementVector vec : array) {
            vec.writeToStream(stream);
        }
    }

    public static void writeArray(byte[] array, DataOutputStream stream) throws IOException {
        if (array == null || array.length == 0) {
            stream.writeInt(0);
        } else {
            stream.writeInt(array.length);
            stream.write(array);
        }
    }

    public static Element[] readElementArray(AbeInputStream stream) throws IOException {
        int len = stream.readInt();
        return readElementArray(len, stream);
    }

    public static Element[] readElementArray(int length, AbeInputStream stream) throws IOException {
        Element[] vec = new Element[length];
        for(int i = 0; i < length; i++) {
            vec[i] = stream.readElement();
        }
        return vec;
    }

    public static int[] readIntegerArray(AbeInputStream stream) throws IOException {
        int len = stream.readInt();
        return readIntegerArray(len, stream);
    }

    public static int[] readIntegerArray(int length, AbeInputStream stream) throws IOException {
        int[] vec = new int[length];
        for(int i = 0; i < length; i++) {
            vec[i] = stream.readInt();
        }
        return vec;
    }

    public static byte[] readByteArray(DataInputStream stream) throws IOException {
        int len = stream.readInt();
        byte[] result =  new byte[len];
        stream.read(result);
        return result;
    }

    public static ElementVector[] readElementVectorArray(AbeInputStream stream) throws IOException {
        int len = stream.readInt();
        return readElementVectorArray(len, stream);
    }

    public static ElementVector[] readElementVectorArray(int length, AbeInputStream stream) throws IOException {
        ElementVector[] vec = new ElementVector[length];
        for(int i = 0; i < length; i++) {
            vec[i] = ElementVector.readFromStream(stream);
        }
        return vec;
    }

    public static String getSpaces(int number) {
        StringBuilder sb = new StringBuilder(number);
        for(int i = 0; i < number; i++) {
            sb.append(" ");
        }
        return sb.toString();
    }

    private static AbePrivateKey mockPrivateKey(Set<String> attributes, AbePublicKey publicKey) {
        ArrayList<Lw14PrivateKeyComponent> components = new ArrayList<Lw14PrivateKeyComponent>();
        for (String s : attributes) {
            components.add(new Lw14PrivateKeyComponent(s, null, elementZrFromString(s, publicKey), null, null));
        }
        return new AbePrivateKey(null, null, null, null, null, components, publicKey);
    }

    public static Lw14PolicyAbstractNode getPolicyTree(String policy, AbePublicKey publicKey) throws ParseException {
        String postFixPolicy = PolicyParsing.parsePolicy(policy);
        return Lw14PolicyAbstractNode.parsePolicy(postFixPolicy, publicKey);
    }

    public static boolean satisfies(String policy, AbePrivateKey privateKey) throws ParseException {
        return satisfies(getPolicyTree(policy, privateKey.getPublicKey()), privateKey);
    }

    public static boolean satisfies(Lw14PolicyAbstractNode policy, AbePrivateKey privateKey) {
        return policy.checkSatisfy(privateKey);
    }

    /**
     * Generates a parse tree and uses it to check whether the passed set of attributes satisfies the access tree.
     *
     * @param policy    policy
     * @param set       Attribute string set
     * @return  Set satisfies the policy
     * @throws ParseException Policy parsing failed
     */
    public static boolean satisfies(String policy, Set<String> set, AbePublicKey publicKey) throws ParseException {
        return satisfies(policy, mockPrivateKey(set, publicKey));
    }

    /**
     * Uses the parse tree to check whether the passed set of attributes satisfies the access tree.
     *
     * @param policyTree    Root node of the tree
     * @param set           Attribute string set
     * @param publicKey     Public key for some internal elements
     * @return  Set satisfies the tree
     */
    public static boolean satisfies(Lw14PolicyAbstractNode policyTree, Set<String> set, AbePublicKey publicKey) {
        return satisfies(policyTree, mockPrivateKey(set, publicKey));
    }

    /**
     * Computes the power set of the original set, but limits the items to a length or <code>length</code>.
     * @param originalSet    Original items as a set
     * @param length         Intended length of the items of the power set
     * @param <T>            Item type
     * @return filtered power set
     */
    public static <T> Set<Set<T>> powerSet(Set<T> originalSet, int length) {
        if (originalSet.size() < length) {
            throw new RuntimeException("Filter length cannot be larger than the set size");
        }
        Set<Set<T>> sets = powerSet(originalSet);
        Set<Set<T>> removeSet = new HashSet<Set<T>>();
        for (Set<T> set : sets) {
            if (set.size() != length) {
                removeSet.add(set);
            }
        }
        sets.removeAll(removeSet);
        return sets;
    }

    /**
     * Computes the power set of the given set.
     * Copied from <a href="http://stackoverflow.com/a/1670871">StackOverflow by João Silva</a>.
     * @param originalSet    Set to build the power set from
     * @param <T>            Set element type
     * @return  Power set of {@code T}
     */
    public static <T> Set<Set<T>> powerSet(Set<T> originalSet) {
        Set<Set<T>> sets = new HashSet<Set<T>>();
        if (originalSet.isEmpty()) {
            sets.add(new HashSet<T>());
            return sets;
        }
        List<T> list = new ArrayList<T>(originalSet);
        T head = list.get(0);
        Set<T> rest = new HashSet<T>(list.subList(1, list.size()));
        for (Set<T> set : powerSet(rest)) {
            Set<T> newSet = new HashSet<T>();
            newSet.add(head);
            newSet.addAll(set);
            sets.add(newSet);
            sets.add(set);
        }
        return sets;
    }

    public static String toString(Element[] array, int initialIndent, int additionalIndent){
        return toString(Arrays.asList(array), initialIndent, additionalIndent);
    }

    public static String toString(Collection<Element> collection, int initialIndent, int additionalIndent){
        StringBuilder sb;

        String iiString = getSpaces(initialIndent);
        String aiString = getSpaces(additionalIndent);

        sb = new StringBuilder();
        sb.append(iiString);
        sb.append("[\n");
        int i = 0;
        for(Element el : collection) {
            if (i != 0) {
                sb.append(",\n");
            }
            sb.append(iiString);
            sb.append(aiString);
            sb.append('"');
            sb.append(el);
            sb.append('"');
            i++;
        }
        sb.append("\n");
        sb.append(iiString);
        sb.append("]");
        return sb.toString();
    }

    /**
     * Returns one pascal row as array. For example would be
     * <code>getPascalRow(4) == { 1, 3, 3, 1}</code>
     * @param n    Pascal row index
     * @return  Row as long array
     */
    public static long[] getPascalRow(int n) {
        long[] row = new long[n];
        row[0] = 1L;

        for(int col = 1; col < n; col++) {
            row[col] = row[col - 1] * (n - col) / col;
        }

        return row;
    }

    /**
     * It computes lexicographically the next permutation of the bits in the given number.
     *
     * For example 3 = 0b000011<br>
     * - next: 0b000101 (5)<br>
     * - next: 0b000110 (6)<br>
     * - next: 0b001001 (9)<br>
     * - next: 0b001010 (10)<br>
     * - next: 0b001100 (12)<br>
     * - next: 0b010001 (17)<br>
     *
     * Copied from <a href="http://graphics.stanford.edu/~seander/bithacks.html#NextBitPermutation">Bit Twiddling Hacks: Compute the lexicographically next bit permutation</a>
     * @param v    Source number
     * @return  Bit-twiddled number
     */
    public static long getNextLexicographicalPermutation(long v) {
        long t = (v | (v - 1)) + 1;
        return t | ((((t & -t) / (v & -v)) >> 1) - 1);
    }

    /**
     * It computes lexicographically the next permutation of the bits in the given number.
     *
     * For example 3 = 0b000011<br>
     * - next: 0b000101 (5)<br>
     * - next: 0b000110 (6)<br>
     * - next: 0b001001 (9)<br>
     * - next: 0b001010 (10)<br>
     * - next: 0b001100 (12)<br>
     * - next: 0b010001 (17)<br>
     *
     * Copied from <a href="http://graphics.stanford.edu/~seander/bithacks.html#NextBitPermutation">Bit Twiddling Hacks: Compute the lexicographically next bit permutation</a>
     * @param v    Source number
     * @return  Bit-twiddled number
     */
    public static BigInteger getNextLexicographicalPermutation(BigInteger v) {
        BigInteger t = v.or(v.subtract(BigInteger.ONE)).add(BigInteger.ONE);
        return t.and(t.negate()).divide(v.and(v.negate())).shiftRight(1).subtract(BigInteger.ONE).or(t);
    }
}
