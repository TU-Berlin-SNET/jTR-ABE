package trabe.tests;

import java.io.*;
import java.security.SecureRandom;
import java.util.UUID;

public class TestUtil {
    private static String testPath = "testFolder";

    private static SecureRandom random = new SecureRandom();

    /**
     * Generates a new test folder if it is not yet available and return it.
     * @return Old or newly created test folder
     */
    public static File prepareTestFolder() throws IOException {
        File f = new File(testPath);
        if (!f.exists() && !f.mkdirs()) {
            throw new IOException("Test folder could not be created");
        }
        return f;
    }

    /**
     * Creates a randomly named file and fills it with random data.
     *
     * @param bytes    Number of random bytes in the file
     * @return Created file
     * @throws IOException
     */
    public static File randomData(int bytes) throws IOException{
        byte[] data = new byte[bytes];
        random.nextBytes(data);
        File randomFile = new File(testPath, UUID.randomUUID().toString()+".dat");
        FileOutputStream fos = new FileOutputStream(randomFile);
        fos.write(data);
        fos.flush();
        fos.close();
        return randomFile;
    }

    /**
     * Creates a randomly named file and fills it with random data.
     *
     * @return Created file
     * @throws IOException
     */
    public static File randomData() throws IOException{
        return randomData(125);
    }

    public static byte[] read(File f) throws IOException {
        FileInputStream fis = new FileInputStream(f);
        byte[] b = new byte[(int) f.length()];
        fis.read(b);
        fis.close();
        return b;
    }
}
