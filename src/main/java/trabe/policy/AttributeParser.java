package trabe.policy;

import java.text.DecimalFormat;
import java.text.NumberFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import ch.hsr.geohash.*;

import java.util.regex.Pattern;
import java.util.regex.Matcher;

import trabe.policyparser.ParseException;

public class AttributeParser {

    private static StringBuffer getNumericalAttributeResult(String attribute, String number) {
        ArrayList<String> attributes = new ArrayList<String>();
        Long value = Long.valueOf(number);

        for (int i = 2; i <= 32; i *= 2) {
            attributes.add(String.format((Util.isLessThanUnsigned(value, (long) 1 << i) ? "%s_lt_2^%02d" : "%s_ge_2^%02d"), attribute, i));
        }

        for (int i = 0; i < 64; i++) {
            attributes.add(Util.bit_marker_flexint(attribute, i, (((long) 1 << i) & value) > 0));
        }

        attributes.add(String.format("%s_%s_%d", attribute, Util.FLEXINT_TYPE, Util.unsignedToBigInteger(value)));

        StringBuffer result = new StringBuffer();
        for (String s : attributes) {
            result.append(s).append(' ');
        }
        return result;
    }
    private static NumberFormat numberFormat = DecimalFormat.getInstance(Locale.ENGLISH);
    
    private static StringBuffer locationToAttributes(String attributeName, String latString, String lonString) throws ParseException {
    	double lon;
    	double lat;
        try {
        	lon = numberFormat.parse(lonString).doubleValue();
        	lat = numberFormat.parse(latString).doubleValue();
        } catch (java.text.ParseException e) {
        	throw new ParseException("Could not parse double: "+ e.getMessage());
        }
        GeoHash hash = GeoHash.withBitPrecision(lat, lon, Util.GEOHASH_MAXBITS);
        List<String> attributes = geoHashToAttributes(attributeName, hash, Util.GEOHASH_MAXBITS);

        StringBuffer result = new StringBuffer();
        for (String s : attributes) {
            result.append(s).append(' ');
        }
        return result;
    }

    public static List<String> geoHashToAttributes(String attributeName, GeoHash hash, int precision) {
        ArrayList<String> attributes = new ArrayList<String>(precision);
        String binaryString = hash.toBinaryString();
        for (int i = 0; i < binaryString.length(); i++) {
            attributes.add(Util.bit_marker_geohash(attributeName, Util.GEOHASH_MAXBITS - i - 1, binaryString.charAt(i) == '1'));
        }
        return attributes;
    }

    private final static String name = "([a-zA-Z]\\w*)";
    private final static String numberInt = "(\\d+)";
    // <name><whitespace>*=<whitespace>*<value>
    private final static Pattern NumbericalAttributePattern = Pattern.compile(name + "\\s*=\\s*" + numberInt);
    // <name>:<lat>:<lon>
    private final static String numberDouble = "(\\d+[\\.]\\d*)"; // needs .
    private final static Pattern GeohashAttributePattern        = Pattern.compile(name + ":" + numberDouble + ":" + numberDouble);
    public static String parseAttributes(String attributes) throws ParseException {
        attributes = attributes.replace(",", ".");
        // AttributeValue
        Matcher matched = NumbericalAttributePattern.matcher(attributes);
        StringBuffer afterNumericalAttribute = new StringBuffer();
        while (matched.find()) {
            matched.appendReplacement(afterNumericalAttribute, getNumericalAttributeResult(matched.group(1), matched.group(2)).toString());
        }
        matched.appendTail(afterNumericalAttribute);

        // Geohash
        matched = GeohashAttributePattern.matcher(afterNumericalAttribute);
        StringBuffer finalResult = new StringBuffer();
        while (matched.find()) {
            matched.appendReplacement(finalResult, locationToAttributes(matched.group(1), matched.group(2), matched.group(3)).toString());
        }
        matched.appendTail(finalResult);
        String finalResultAsString = finalResult.toString().replaceAll("\\s+", " ").trim();
        if (finalResultAsString.contains("=")) {
        	throw new ParseException("Error occured while parsing attribute string: " + attributes);
        }
        return finalResultAsString;
    }
}
