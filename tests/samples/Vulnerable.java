// tests/samples/Vulnerable.java
import java.io.*;

public class Vulnerable {
    public void unsafeExec(String command) throws IOException {
        // Vulnerability: Command injection
        Runtime.getRuntime().exec(command);
    }
    
    public Object unsafeDeserialization(byte[] data) throws Exception {
        // Vulnerability: Insecure deserialization
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        return ois.readObject();
    }
}
