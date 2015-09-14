package trabe.lw14.policy;

import trabe.*;
import trabe.lw14.Lw14Util;
import trabe.policyparser.*;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;

import java.io.IOException;
import java.math.BigInteger;
import java.util.*;

/**
 * An LSSS matrix is a more general approach to access structures than a boolean formula.
 */
public class LsssMatrix {

    /**
     * Encapsulates the AST tree into a much less complicated object.
     */
    private static class TreeNode {
        public int[] vector;
        public TreeNode parent;
        public Node node;
        public TreeNode leftChild;
        public TreeNode rightChild;

        public TreeNode(Node node) {
            this.node = node;
        }

        /**
         * Doesn't access the underlying node, but only checks whether
         * <code>this</code> has a left or right child.
         * @return Has children?
         */
        public boolean hasChildren() {
            return leftChild != null || rightChild != null;
        }

        /**
         * Accesses the underlying AST node to retrieve all the children.
         * @return  Child nodes
         */
        public List<Node> getChildren() {
            ArrayList<Node> children = new ArrayList<Node>(node.jjtGetNumChildren());
            for(int i = 0; i < node.jjtGetNumChildren(); i++) {
                children.add(node.jjtGetChild(i));
            }
            return children;
        }
    }

    /**
     * This matrix automatically grows by assigning values into its cells.
     */
    private static class GrowingMatrix<T> {
        private ArrayList<ArrayList<T>> matrix = new ArrayList<ArrayList<T>>();
        private ArrayList<String> attributes = new ArrayList<String>();

        private int columns = 0;
        private final int addOne;

        public GrowingMatrix(boolean zeroBased) {
            this.addOne = zeroBased ? 0 : 1;
        }

        private GrowingMatrix(ArrayList<ArrayList<T>> matrix, ArrayList<String> attributes, int columns, int addOne) {
            this.matrix = matrix;
            this.attributes = attributes;
            this.columns = columns;
            this.addOne = addOne;
        }

        public String getAttribute(int rowIndex) {
            return attributes.get(rowIndex - addOne);
        }

        public void setAttribute(int rowIndex, String attribute) {
            int size = attributes.size();
            for(int i = size; i < rowIndex + 1 - addOne; i++) {
                // add empty attributes, because they were never written to
                attributes.add(null);
            }
            attributes.set(rowIndex - addOne, attribute);
        }

        public T get(int rowIndex, int colIndex) {
            ArrayList<T> row = matrix.get(rowIndex - addOne);
            return row.get(colIndex - addOne);
        }

        public T safeGet(int rowIndex, int colIndex) {
            try {
                ArrayList<T> row = matrix.get(rowIndex);
                return row.get(colIndex);
            } catch (IndexOutOfBoundsException e) {
                return null;
            }
        }

        public void set(int rowIndex, int colIndex, T value) {
            int rowSize = matrix.size();
            for(int i = rowSize; i < rowIndex + 1 - addOne; i++) {
                // add empty rows, because they were never written to
                matrix.add(new ArrayList<T>());
            }

            ArrayList<T> row = matrix.get(rowIndex - addOne);
            int colSize = row.size();
            for(int i = colSize; i < colIndex + 1 - addOne; i++) {
                // add empty cells, because they were never written to
                row.add(null);
            }

            row.set(colIndex - addOne, value);

            // save the current largest row vector size
            columns = Math.max(columns, colIndex + 1 - addOne);
        }

        public int getRows() {
            return matrix.size();
        }

        public int getColumns() {
            return columns;
        }

        public boolean getZeroBased() {
            return addOne == 0;
        }

        /**
         * Generates a copy of the current matrix.
         * @return  Matrix
         */
        public GrowingMatrix<T> duplicate() {
            ArrayList<ArrayList<T>> dMatrix = new ArrayList<ArrayList<T>>();
            ArrayList<String> dAttributes = new ArrayList<String>();

            for (ArrayList<T> row : matrix) {
                ArrayList<T> dRow = new ArrayList<T>();
                for (T i : row) {
                    dRow.add(i);
                }
                dMatrix.add(dRow);
            }
            for (String att : attributes) {
                dAttributes.add(att);
            }

            return new GrowingMatrix<T>(dMatrix, dAttributes, getColumns(), addOne);
        }

        /**
         * Checks whether
         *
         * <ol>
         *     <li>at least one attribute is used</li>
         *     <li>the same number of attributes and rows is present</li>
         *     <li>no <code>null</code> values or attributes are left</li>
         * </ol>
         * @return  is valid?
         */
        public boolean valid() {
            // 1.
            try {
                get(addOne, addOne); // check first cell
            } catch (IndexOutOfBoundsException e) {
                return false;
            }

            // 2.
            if (attributes.size() != matrix.size()) {
                return false;
            }

            // 3.
            try {
                for (int i = 0; i < getRows(); i++) {
                    if (attributes.get(i) == null) {
                        return false;
                    }
                    for (int j = 0; j < getColumns(); j++) {
                        if (get(i + addOne, j + addOne) == null) {
                            return false;
                        }
                    }
                }
            } catch(IndexOutOfBoundsException e) {
                return false;
            }

            return true;
        }

        public String toNiceString() {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < getRows(); i++) {
                try {
                    sb.append(attributes.get(i));
                } catch (IndexOutOfBoundsException e) {
                    sb.append("unknown");
                }
                sb.append(": ");
                for (int j = 0; j < getColumns(); j++) {
                    try {
                        sb.append(get(i + addOne, j + addOne));
                    } catch (IndexOutOfBoundsException e) {
                        sb.append("NaN");
                    }
                    sb.append(" ");
                }
                sb.append("\n");
            }
            return sb.toString();
        }
    }

    private LsssMatrixCell[][] matrix;

    private LsssMatrix(LsssMatrixCell[][] matrix){
        this.matrix = matrix;
    }

    private LsssMatrix(){}

    /**
     * Get a complete cell of the matrix with all its stored information based on the given coordinates.
     * @param i    Row index
     * @param j    Column index
     * @return  Cell of (i, j)
     */
    public LsssMatrixCell get(int i, int j) {
        return this.matrix[i][j];
    }

    /**
     * Returns the attribute name of the given row index.
     * @param row    Row index starting with 0
     * @return  Attribute of row
     */
    public String getAttribute(int row) {
        return get(row, 0).attribute;
    }

    /**
     * Retrieve the row index of the given attribute name. Returns -1 if the
     * given attribute name does not exist.
     * @param attribute    Attribute string
     * @return  Row index of attribute
     */
    public int getAttributeRowIndex(String attribute) {
        for(int i = 0; i < matrix.length; i++) {
            if (getAttribute(i).equals(attribute)) {
                return i;
            }
        }
        return -1;
    }

    /**
     * Create a new element vector for the row identified by the row index.
     * @param row    Row index (from 0)
     * @param f      Field identifier
     * @return  Row vector
     */
    public ElementVector getAttributeRow(int row, Field f) {
        ElementVector r = new ElementVector(matrix[row].length);
        for(int col = 0; col < matrix[row].length; col++) {
            r.set(col, f.newElement(new BigInteger(""+get(row, col).value)));
        }
        return r;
    }

    /**
     * Create a new element vector from the row identified by the given attribute.
     * @param attribute    Attribute string
     * @param f            Field identifier
     * @return  Row vector
     */
    public ElementVector getAttributeRow(String attribute, Field f) {
        for(int i = 0; i < matrix.length; i++) {
            if (getAttribute(i).equals(attribute)) {
                return getAttributeRow(i, f);
            }
        }
        return null;
    }

    /**
     * Get the element hash of the attribute identified by its row index.
     * @param row    Attribute row index
     * @return Attribute hash as element
     */
    public Element getHashedAttribute(int row) {
        return get(row, 0).hashedElement;
    }

    /**
     * Return the attributes of the matrix. The list is ordered according to the rows.
     * @return  Attrbute list
     */
    public List<String> getAttributeList() {
        int attributes = getAttributes();
        List<String> list = new ArrayList<String>(attributes);
        for(int i = 0; i < attributes; i++) {
            list.add(getAttribute(i));
        }
        return list;
    }

    /**
     * Return the number of rows in the matrix.
     * @return  number of attributes
     */
    public int getAttributes() {
        return matrix.length;
    }

    /**
     * Return the number of columns in the matrix.
     * @return  number of columns
     */
    public int getColumns() {
        return matrix[0].length;
    }

    /**
     * LSSS matrix generation for threshold formula based on the 2014 paper
     * "Efficient Generation of Linear Secret Sharing Scheme Matrices from
     * Threshold Access Trees" by Liu, Cao and Wong.
     * @param policy    Policy string containing simple attributes and AND/OR/THRESHOLD gates
     * @param pub       public key
     * @return  Generated access matrix
     * @throws ParseException Policy parsing failed
     */
    public static LsssMatrix createMatrixFromThresholdFormula(String policy, AbePublicKey pub)
            throws ParseException {
        ASTStart tree = PolicyParser.parsePolicy(policy);

        Field zR = pub.getPairing().getZr();

        // The some comments denote the corresponding positions of this algorithm in the paper
        GrowingMatrix<Element> mainMatrix = new GrowingMatrix<Element>(false);
        mainMatrix.set(1, 1, zR.newOneElement());
        ArrayList<Node> nodeList = new ArrayList<Node>();
        nodeList.add(tree.jjtGetChild(0)); // root node
        int m = 1;
        int d = 1;
        int z = 1;
        int i;
        while (z != 0) {
            z = 0;
            i = 1;
            // line 4
            while (i <= m && z == 0) {
                Node n = nodeList.get(i - 1);
                if (n instanceof ASTOf ||
                        (n instanceof ASTExpression &&
                                (((ASTExpression)n).getType().equalsIgnoreCase("and") ||
                                        ((ASTExpression)n).getType().equalsIgnoreCase("or")))) {
                    z = i;
                }
                i++;
            }

            // line 10
            if (z == 0) {
                continue;
            }

            // line 11
            Node cn = nodeList.get(z - 1);
            int m2 = 0;
            int d2 = 0;
            if (cn instanceof ASTOf) {
                ASTOf currentThresholdNode = (ASTOf)cn;
                m2 = currentThresholdNode.jjtGetNumChildren(); // maximum value
                d2 = currentThresholdNode.getNumber();         // threshold value
            } else if (cn instanceof ASTExpression) {
                ASTExpression currentExpressionNode = (ASTExpression)cn;
                m2 = currentExpressionNode.jjtGetNumChildren(); // maximum value
                d2 = currentExpressionNode.getType().equalsIgnoreCase("and") ? m2 : 1; // set threshold value
            }

            // line 13 is removed in favor of directly accessing the children in line 25

            // line 14
            GrowingMatrix<Element> childMatrix = mainMatrix.duplicate();
            ArrayList<Node> nodeList2 = new ArrayList<Node>(nodeList.size());
            nodeList2.addAll(nodeList);
            // the list will be populated later through nodeList2 and that's why we can use `nodeList.add` later
            nodeList.clear();
            int m1 = m;
            int d1 = d;

            // line 15
            for (i = 1; i <= z - 1; i++) {
                nodeList.add(nodeList2.get(i - 1));
                for (int j = 1; j <= d1; j++) {
                    mainMatrix.set(i, j, childMatrix.get(i, j));
                }
                for (int j = d1 + 1; j <= d1 + d2 - 1; j++) {
                    mainMatrix.set(i, j, zR.newZeroElement());
                }
            }

            // line 24
            for (i = z; i <= z + m2 - 1; i++) {
                nodeList.add(cn.jjtGetChild(i - z)); // diff is zero-based
                for (int j = 1; j <= d1; j++) {
                    mainMatrix.set(i, j, childMatrix.get(z, j));
                }
                int a = i - z + 1;
                Element x = zR.newElement(new BigInteger(""+a)); // not directly using integer method because of jpbc bug
                for (int j = d1 + 1; j <= d1 + d2 - 1; j++) {
                    mainMatrix.set(i, j, x);
                    x = x.duplicate().mul(new BigInteger(""+a)); // assignment not necessary
                }
            }

            // line 35
            for (i = z + m2; i <= m1 + m2 - 1; i++) {
                nodeList.add(nodeList2.get(i - m2)); // diff is zero-based
                for (int j = 1; j <= d1; j++) {
                    mainMatrix.set(i, j, childMatrix.get(i - m2 + 1, j));
                }
                for (int j = d1 + 1; j <= d1 + d2 - 1; j++) {
                    mainMatrix.set(i, j, zR.newZeroElement());
                }
            }
            m = m1 + m2 - 1;
            d = d1 + d2 - 1;
        }

        // here nodeList must contain only attributes, so mainMatrix.attributes can be populated
        i = 1;
        for(Node n : nodeList) {
            mainMatrix.setAttribute(i, ((ASTAttribute)n).getName());
            i++;
        }

        return createMatrixFromGrowingMatrix(mainMatrix, pub);
    }

    private static LsssMatrix createMatrixFromGrowingMatrix(GrowingMatrix<Element> matrix, AbePublicKey pub) {
        LsssMatrixCell[][] newMatrix = new LsssMatrixCell[matrix.getRows()][matrix.getColumns()];
        int addOne = matrix.getZeroBased() ? 0 : 1;
        for(int i = 0; i < matrix.getRows(); i++) {
            String attribute = matrix.getAttribute(i + addOne);
            Element hashedAttribute = Lw14Util.elementZrFromString(attribute, pub);
            for(int j = 0; j < matrix.getColumns(); j++) {
                // TODO: for big matrices the `value` may be bigger than what `int` can handle: make the matrix completely handle `Element` values instead of `int`
                newMatrix[i][j] = new LsssMatrixCell(i, j, matrix.get(i + addOne, j + addOne).toBigInteger().intValue(), attribute, hashedAttribute);
            }
        }
        return new LsssMatrix(newMatrix);
    }

    /**
     * Generates the LSSS matrix from the given policy. Only boolean formulas are usable.
     * Passing a threshold formula will lead to RuntimeExceptions.
     * @param policy    Policy string
     * @param pub       public key
     * @return  Generated access matrix
     * @throws ParseException Policy parsing failed
     */
    public static LsssMatrix createMatrixFromBooleanFormula(String policy, AbePublicKey pub)
            throws ParseException {
        ASTStart tree = PolicyParser.parsePolicy(policy);

        LinkedHashMap<String, TreeNode> vectors = new LinkedHashMap<String, TreeNode>();
        traverseVector(new TreeNode(tree.jjtGetChild(0)), null, null, null, 1, vectors, null);

        return createMatrixFromVectors(vectors, pub);
    }

    /**
     * Every vector represents the share of one attribute and takes up one row
     * of the resulting matrix. If the vectors are not of the same size, they the
     * matrix row will be padded with zeros.
     *
     * @param vectors    Mapping of attribute to its node in the AST tree
     * @param pub        public key
     * @return  Generated access matrix
     */
    private static LsssMatrix createMatrixFromVectors(Map<String, TreeNode> vectors, AbePublicKey pub) {
        Set<String> strings = vectors.keySet();
        String[] attributes = strings.toArray(new String[strings.size()]);
        Arrays.sort(attributes);


        int columns = 0;
        for(String attribute : attributes) {
            columns = Math.max(columns, vectors.get(attribute).vector.length);
        }
        LsssMatrixCell[][] matrix = new LsssMatrixCell[attributes.length][columns];
        int i = 0;
        for(String attribute : attributes) {
            Element attributeHash = Lw14Util.elementZrFromString(attribute, pub);
            int[] vector = vectors.get(attribute).vector;
            for(int j = 0; j < columns; j++) {
                int value = j < vector.length ? vector[j] : 0; // take vector value or pad with 0
                matrix[i][j] = new LsssMatrixCell(i, j, value, attribute, attributeHash);
            }
            i++;
        }

        return new LsssMatrix(matrix);
    }

    /**
     * Recursive function to traverse over the AST tree and extend the vector at
     * every node depending on the node type.
     *
     * At the beginning, <code>node</code> must be initialized with the tree root node,
     * but its children shouldn't be already initialized.
     * <code>c</code> must be 1 and <code>attributes</code> must be an empty Map that
     * will be filled with attributes and their resulting vectors.
     *
     * @param node          current tree node
     * @param parent        parent node (null if root)
     * @param left          left child (will be filled in if null)
     * @param right         right child (will be filled in if null)
     * @param c             counter
     * @param attributes    Mapping of attribute to its node in the AST tree
     * @param leftChild     denotes whether the current node is the left child of its parent
     * @return root tree node with populated child nodes.
     */
    private static TreeNode traverseVector(TreeNode node, TreeNode parent, List<Node> left,
                                          List<Node> right, int c, Map<String, TreeNode> attributes,
                                          Boolean leftChild) {
        if (left == null && right == null && node.node instanceof ASTExpression) {
            List<Node> children = node.getChildren();
            if (children != null && children.size() > 1){
                return traverseVector(node, parent,
                        children.subList(0, children.size()/2),
                        children.subList(children.size()/2, children.size()),
                        c, attributes, leftChild);
            }
        }

        if (parent == null) {
            node.vector = new int[]{ 1 };

            if (left == null && right == null && node.node instanceof ASTAttribute) {
                attributes.put(((ASTAttribute) node.node).getName(), node);
                return node;
            }
        } else {
            node.parent = parent;
            // TODO: maybe there are other types of parent nodes than expressions

            ASTExpression p;
            try {
                p = (ASTExpression)parent.node;
            } catch (ClassCastException e) {
                throw new RuntimeException("Only ASTExpression intermediate nodes are supported.", e);
            }

            boolean isAnd = "and".equals(p.getType());
            boolean isOr = "or".equals(p.getType());

            // create vector for current node
            if (isAnd) {
                node.vector = new int[c+1];
                if (leftChild) {
                    System.arraycopy(parent.vector, 0, node.vector, 0, parent.vector.length);
                    node.vector[c] = 1;
                } else {
                    Arrays.fill(node.vector, 0);
                    node.vector[c] = -1;
                }
                c++;
            } else if (isOr) {
                node.vector = Arrays.copyOf(parent.vector, parent.vector.length);
            } else {
                throw new RuntimeException("Unknown expression type: " + p.getType());
            }

            if (node.node instanceof ASTAttribute) {
                attributes.put(((ASTAttribute) node.node).getName(), node);
            }
        }
        if (left != null && right != null && node.node instanceof ASTExpression) {
            // TODO: make another node for more than 2 children
            node.leftChild = traverseVector(new TreeNode(left.get(0)), node, null, null, c, attributes, true);
            node.rightChild = traverseVector(new TreeNode(right.get(0)), node, null, null, c, attributes, false);
        }
        return node;
    }

    public void writeToStream(AbeOutputStream stream) throws IOException {
        stream.writeInt(getAttributes());
        stream.writeInt(getColumns());
        for(int i = 0; i < matrix.length; i++) {
            for(int j = 0; j < matrix[i].length; j++) {
                get(i, j).writeToStream(stream);
            }
        }
    }

    public static LsssMatrix readFromStream(AbeInputStream stream) throws IOException {
        int attributes = stream.readInt();
        int columns = stream.readInt();
        LsssMatrixCell[][] mat = new LsssMatrixCell[attributes][columns];
        for(int i = 0; i < attributes; i++) {
            for(int j = 0; j < columns; j++) {
                mat[i][j] = LsssMatrixCell.readFromStream(stream);
                mat[i][j].i = i;
                mat[i][j].j = j;
            }
        }
        return new LsssMatrix(mat);
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null || !(obj instanceof LsssMatrix)) {
            return false;
        } else if(this == obj) {
            return true;
        }
        LsssMatrix m = (LsssMatrix)obj;
        if (getAttributes() != m.getAttributes() || getColumns() != m.getColumns()) {
            return false;
        }

        for(int i = 0; i < matrix.length; i++) {
            for(int j = 0; j < matrix[i].length; j++) {
                if (!get(i, j).equals(m.get(i, j))) {
                    return false;
                }
            }
        }
        return true;
    }

    @Override
    public String toString(){
        StringBuilder sb = new StringBuilder();

        sb.append("[\n");

        for(int i = 0; i < matrix.length; i++) {
            sb.append("    [\n");
            for(int j = 0; j < matrix[i].length; j++) {
                sb.append("        \"").append(matrix[i][j]).append('"');
                if (j < matrix[i].length-1) {
                    sb.append(",");
                }
                sb.append("\n");
            }
            sb.append("    ]");
            if (i < matrix.length-1) {
                sb.append(",");
            }
            sb.append("\n");
        }

        sb.append("]");

        return sb.toString();
    }

    /**
     * Builds a nice multiline matrix representation of the values without positions,
     * attribute names of hashed values.
     * @return  Nice representation of access matrix
     */
    public String toNiceString(){
        StringBuilder sb = new StringBuilder();

        for(int i = 0; i < matrix.length; i++) {
            sb.append(matrix[i][0].attribute).append(": ");
            for(int j = 0; j < matrix[i].length; j++) {
                sb.append(matrix[i][j].value).append(' ');
            }
            sb.append("\n");
        }

        return sb.toString();
    }
}
