package trabe.tests;

import static org.junit.Assert.*;
import trabe.policy.*;
import trabe.policyparser.ParseException;

import org.junit.Test;

public class ParserTest {

    @Test
    @SuppressWarnings("unused")
    public void testPolicyParser() throws ParseException {
        // String policyInput = "a or (b > 5 and a:52.52001:13.40495:22 and 3 of (1 of (c, d, e),x,y))";
        String policyInput = "a:52.52001:13.40495:32:1";
        //ASTStart policyTree = PolicyParser.parsePolicy(policyInput);
        //policyTree.dump("");
		String parsedPolicy = PolicyParsing.parsePolicy(policyInput);
        //System.out.println("Parsed policy:\n" + parsedPolicy);
        // TODO check if parsed policy is correct
    }

    @Test //TODO finish writing test
    public void testAttributeParser() throws ParseException {
        //String attributes4 = "att1:52.52001:13.40495";
        //String parsed4 = AttributeParser.parseAttributes(attributes4);
    }
    
    @Test
    public void attributeParserWhitespaceTest() throws ParseException {
        String attributes1 = "att1        att2";
        String attributes2 = "att1\t\n\f\r\t\tatt2";
        
        String parsed1 = AttributeParser.parseAttributes(attributes1);
        String parsed2 = AttributeParser.parseAttributes(attributes2);

        assertEquals(parsed1, "att1 att2");
        assertEquals(parsed2, "att1 att2");
    }
    
    
    @Test(expected=ParseException.class)
    public void attributeParserInvalidNumberTest() throws ParseException {
    	System.out.println("Parsed as: " + AttributeParser.parseAttributes("att1 = -5"));
    }
    
    @Test(expected=ParseException.class)
    public void attributeParserEqualSignTest() throws ParseException {
    	System.out.println("Parsed as: " + AttributeParser.parseAttributes("att1 = test"));
    }

}
