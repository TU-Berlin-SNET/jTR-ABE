package trabe.benchmark;

import java.util.UUID;

import trabe.AbeEncrypted;
import trabe.AbeSecretMasterKey;
import trabe.Cpabe;
import trabe.AbePrivateKey;

public class CpabeDecryptionAndAttributeNumberTest extends Benchmark {
	
	private byte[] data;
	
	private AbeSecretMasterKey msk;

	private AbePrivateKey privateKey;
	private AbeEncrypted encrypted;
	
	
	@Override
	public void initializeIteration(int iteration) {
		String[] splitAttributes = new String[iteration + 1]; // at least one

		for (int i = 0; i < splitAttributes.length; i++) {
			splitAttributes[i] = "a" + UUID.randomUUID().toString().replace('-', '0'); // policy attribute have to begin with a letter
		}

		String policy = splitAttributes[0];
		String attributes = splitAttributes[0];
		for (int i = 1; i < splitAttributes.length; i++) {
			attributes += " " + splitAttributes[i];
			policy += " and " + splitAttributes[i];
		}
		
		try {
			encrypted = Cpabe.encrypt(msk.getPublicKey(), policy, data);
			privateKey = Cpabe.keygenSingle(msk, attributes);
		} catch (Exception e) {
			throw new RuntimeException("exception thrown iteration initialization", e);
		}
	}
	
	@Override
	public void singleRun(int iteration) {
		try {
            if (Cpabe.decrypt(privateKey, encrypted) == null) {
                throw new RuntimeException("couldn't recover plaintext");
            }
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
