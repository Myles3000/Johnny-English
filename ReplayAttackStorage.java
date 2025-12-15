import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class ReplayAttackStorage {
    public static List<byte[]> captureMessages = new ArrayList<>();

    public static void store(byte[] cipher) throws IOException {
        File logger = new File("Logger.txt");
		try (BufferedWriter log = new BufferedWriter(new FileWriter(logger))) {
            captureMessages.add(cipher.clone());
            //Log Attacker captured message
            log.write("[ATTACKER] Captured ciphertext {" + cipher.length + " bytes}");
            log.flush();
        }
    }

    public static byte[] lastCaptured() {
        if(captureMessages.isEmpty()) return null;
        return captureMessages.get(captureMessages.size() - 1);
    }
}
