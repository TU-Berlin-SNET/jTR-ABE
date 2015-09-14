package trabe.policy;

import java.math.BigInteger;

public class Util {

    public static final String      FLEXINT_TYPE    = "flexint";
    public static final int         FLEXINT_MAXBITS = 64;

    public static final String      GEOHASH_TYPE    = "geohash";
    public static final int         GEOHASH_MAXBITS = 64;

    private static final BigInteger BI_2_64         = BigInteger.ONE.shiftLeft(64);

    public static BigInteger unsignedToBigInteger(long l) {
        final BigInteger bi = BigInteger.valueOf(l);
        return l >= 0 ? bi : bi.add(BI_2_64);
    }

    public static String bit_marker_flexint(String attribute, int bit, boolean on) {
        return bit_marker(attribute, FLEXINT_TYPE, FLEXINT_MAXBITS, bit, on);
    }

    public static String bit_marker_geohash(String attribute, int bit, boolean on) {
        return bit_marker(attribute, GEOHASH_TYPE, GEOHASH_MAXBITS, bit, on);
    }

    private static String bit_marker(String attribute, String type, int maxBits, int bit, boolean on) {
        StringBuilder result = new StringBuilder(attribute.length() + maxBits + type.length() + 2);
        StringBuilder bitmarks = new StringBuilder(maxBits + 1);
        result.append(attribute).append('_').append(type).append('_');
        for (int i = 0; i < maxBits; i++) {
            bitmarks.append('x');
        }
        bitmarks.insert(maxBits - bit, on ? '1' : '0');

        // delete leading x
        // decreasing the maxBits in the loop by one would also fix this, but that leads to
        // an out of bounds exception, when trying to insert with bit = 0.
        bitmarks.deleteCharAt(0);

        return result.append(bitmarks).toString();
    }

    public static boolean isLessThanUnsigned(long n1, long n2) {
        boolean comp = (n1 < n2);
        if ((n1 < 0) != (n2 < 0)) {
            comp = !comp;
        }
        return comp;
    }

}
