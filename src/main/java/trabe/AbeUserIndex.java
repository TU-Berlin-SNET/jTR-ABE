package trabe;

/**
 * Defines a position in a matrix starting with (0,0) and ending with (m-1,m-1).
 * It relies on the counter and matrix side length according to the formula:
 * <code>i * m + j = ctr - 1</code>.
 * */
public class AbeUserIndex {
    public final int i;
    public final int j;

    public final int counter;
    public final int m;

    public AbeUserIndex(int matrixLength, int counter){
        this.i = counter / matrixLength;
        this.j = counter % matrixLength;
        this.counter = counter;
        this.m = matrixLength;
    }

    public AbeUserIndex(int i, int j, int matrixLength){
        this.i = i;
        this.j = j;
        this.counter = i * matrixLength + j;
        this.m = matrixLength;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null || !(obj instanceof AbeUserIndex)) {
            return false;
        } else if(this == obj) {
            return true;
        }
        AbeUserIndex index = (AbeUserIndex)obj;

        boolean result = i == index.i;
        result = result && j == index.j;
        result = result && counter == index.counter;
        result = result && m == index.m;

        return result;
    }
}
