package trabe.lw14;

import java.util.Iterator;
import java.util.Set;

public class SortedPowerSet<T> implements Iterable<Set<T>> {
    private Iterator<Set<T>> iterator;

    public SortedPowerSet(Set<T> set){
        iterator = new SortedPowerSetIterator<T>(set);
    }

    @Override
    public Iterator<Set<T>> iterator() {
        return iterator;
    }
}
