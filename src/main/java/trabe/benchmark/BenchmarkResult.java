package trabe.benchmark;

public class BenchmarkResult {
	private double[] averagedResults;
	private int current;
	
	public BenchmarkResult(int testRuns) {
		averagedResults = new double[testRuns];
		current = 0;
	}
	
	public void addResult(double averageTime) {
		averagedResults[current++] = averageTime;
	}
	
	public boolean isFull() {
		return current == averagedResults.length;
	}
	
	public double[] getAveragedResults() {
		return averagedResults;
	}

	public double getAverageTime(){
        double avg = 0.0;
        for (int i = 0; i < averagedResults.length; i++) {
            avg += averagedResults[i];
        }
        return avg / averagedResults.length;
    }
	
	@Override
	public String toString() {
		// is directly usable in pgfplots
		StringBuilder table = new StringBuilder();
		table.append("iteration avgtime\n");
		for (int i = 0; i < averagedResults.length; i++) {
			table.append(i + 1);
			table.append(' ');
			table.append(averagedResults[i] / 1E9);
			table.append('\n');
		}
        table.append("Overall average: ");
        table.append(getAverageTime() / 1E9);
        table.append('\n');
        return table.toString();
	}
}
