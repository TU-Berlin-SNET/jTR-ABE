package trabe.policyparser;

import java.text.DecimalFormat;
import java.text.NumberFormat;
import java.util.Locale;

public class ASTGeoHashAttribute extends SimpleNode {
    private String name;
    private double lon;
    private double lat;
    private int precision;
    private boolean useAdjacentHashes;
    
    private static NumberFormat numberFormat = DecimalFormat.getInstance(Locale.ENGLISH);
    
    public ASTGeoHashAttribute(int id) {
        super(id);
    }

    public ASTGeoHashAttribute(PolicyParser p, int id) {
        super(p, id);
    }
    
    public void setValues(String name, String lon, String lat, String precision, String useAdjacentHashes) throws ParseException {
        this.name = name;
        try {
        	this.lon = numberFormat.parse(lon).doubleValue();
        	this.lat = numberFormat.parse(lat).doubleValue();
        	this.useAdjacentHashes = Integer.parseInt(useAdjacentHashes) != 0;
        } catch (java.text.ParseException e) {
        	throw new ParseException("Could not parse double: "+ e.getMessage());
        }
        this.precision = Integer.valueOf(precision);
    }
    
    
    public String getName() {
        return name;
    }
    
    public double getLatitude() {
        return lat;
    }
    
    public double getLongitude() {
        return lon;
    }
    
    public int getPrecision() {
        return precision;
    }
    
    public boolean useAdjacentHashes() {
    	return useAdjacentHashes;
    }
    
    public String toString() {
        return "GeoHashAttribute: " + name + " " + lat + " " + lon + " " + precision + " " + (useAdjacentHashes ? "adjacent" : "notadjacent");
    }
}