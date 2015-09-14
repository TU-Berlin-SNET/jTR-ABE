package trabe.benchmark;

import trabe.AbeSecretMasterKey;
import trabe.Cpabe;

public class CpabeEncryptionAttributeNumberTest extends Benchmark {
	
	private byte[] data;
	
	private AbeSecretMasterKey msk;

	private String policy = "";
	
	
	@Override
	public void initializeIteration(int iteration) {
		policy = "a";
		for (int i = 0; i < iteration; i++) {
			policy += " and a";
		}
	}
	
	@Override
	public void singleRun(int iteration) {
		try {
			Cpabe.encrypt(msk.getPublicKey(), policy, data); // hope this doesnt get optimized away
		} catch (Exception e) {
			throw new RuntimeException("exception thrown during test", e);
		}
	}

	@Override
	public void initializeBenchmark() {
		msk = Cpabe.setup(numIterations() * numRunsPerIteration() + numWarmupRuns());

		data = new byte[255]; // not actually relevant, since we dont really encrypt this
		for (int i = 0; i < data.length; i++) {
			data[i] = (byte) (i % 256);
		}
	}

	@Override
	public int numWarmupRuns() {
		return 5;
	}

	@Override
	public int numIterations() {
		return 20;
	}

	@Override
	public int numRunsPerIteration() {
		return 5;
	}

}
