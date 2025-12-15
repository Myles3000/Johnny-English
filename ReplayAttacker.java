import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.OutputStream;
import java.net.Socket;

public class ReplayAttacker {

    public static void replay(Socket socket) throws Exception {
        
        byte[] replayData = ReplayAttackStorage.lastCaptured();
        File logger = new File("Logger.txt");
		BufferedWriter log = new BufferedWriter(new FileWriter(logger));
        
        if(replayData == null){
            log.write("[ATTACKER] No ciphertext to replay");
            return;
        }

        OutputStream out = socket.getOutputStream();
        out.write(replayData);
        out.flush();
        
    }

}

