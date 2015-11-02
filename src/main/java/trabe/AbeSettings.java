package trabe;

public class AbeSettings {
    public final static boolean DEBUG                     = false;
    public final static String  STRINGS_LOCALE            = "US-ASCII";
    public final static String  ELEMENT_HASHING_ALGORITHM = "SHA-1";
    public final static String  curveParams               = "type a\n"
            + "q 87807107996633125224377819847540498158068831994142082"
            + "1102865339926647563088022295707862517942266222142315585"
            + "8769582317459277713367317481324925129998224791\n"
            + "h 12016012264891146079388821366740534204802954401251311"
            + "822919615131047207289359704531102844802183906537786776\n"
            + "r 730750818665451621361119245571504901405976559617\n"
            + "exp2 159\n" + "exp1 107\n"
            + "sign1 1\n" + "sign0 1\n";
    public final static boolean USE_TREE = true; // otherwise LSSS matrix

    // currently broken:
    public final static boolean USE_THRESHOLD_MATRIX = false; // otherwise LSSS matrix from boolean formula
}
