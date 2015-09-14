package trabe.lw14;

import java.math.BigInteger;
import java.util.*;

/**
 * This iterator uses the provided set to generate a power set of it on the fly.
 * The size of the elements of the power set is monotonously increasing. For
 * example the firs element of the iteration is always an empty set and the last
 * iteration is the full set that was provided.
 *
 * It has a constant amount of internal objects during its execution.
 * @param <T> Element type
 */
public class SortedPowerSetIterator<T> implements Iterator<Set<T>> {
    private T[] elements;

    private long[] buckets;
    private int currentBucketIndex;
    private int currentIndexInBucket;
    private BigInteger currentPermutation;

    @SuppressWarnings("unchecked")
    public SortedPowerSetIterator(Set<T> set) {
        elements = (T[])set.toArray();
        buckets = Lw14Util.getPascalRow(set.size()+1);
        currentBucketIndex = 0;
        currentIndexInBucket = 0;
    }

    @Override
    public boolean hasNext() {
        return (currentIndexInBucket+1 < buckets[currentBucketIndex]) ||
                (currentBucketIndex+1 < buckets.length);
    }

    @Override
    public Set<T> next() {
        if (currentPermutation == null) {
            currentPermutation = BigInteger.ZERO;
            return new HashSet<T>();
        }
        if (currentIndexInBucket+1 < buckets[currentBucketIndex]) {
            currentIndexInBucket++;
            currentPermutation = Lw14Util.getNextLexicographicalPermutation(currentPermutation);
        } else if (currentBucketIndex+1 < buckets.length) {
            currentIndexInBucket = 0;
            currentBucketIndex++;

            // compute 2^bucketIndex - 1 to get the starting permutation
            BigInteger two = BigInteger.valueOf(2);
            currentPermutation = two.pow(currentBucketIndex).add(BigInteger.ONE.negate());
        } else {
            throw new NoSuchElementException();
        }
        return getSetFromBits(currentPermutation);
    }

    @Override
    public void remove() {
        throw new RuntimeException("Not implemented");
    }

    /**
     * Create a set that is an element of the power set represented by the passed permutation/bits.
     * @param bits    Permutation of the initial set signified by bits
     * @return  Subset of the underlying set derived from the given {@code bits}
     */
    private Set<T> getSetFromBits(BigInteger bits) {
        Set<T> set = new HashSet<T>();

        int bitCount = bits.bitCount();
        int counted = 0;
        int i = 0;
        while(counted < bitCount) {
            if (bits.testBit(i)) {
                set.add(elements[i]);
                counted++;
            }
            i++;
        }
        return set;
    }
}
