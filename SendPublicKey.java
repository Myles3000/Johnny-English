
import java.io.PrintWriter;
import java.security.PublicKey;
import java.util.Base64;

public class SendPublicKey {

    public static void sendPublicKey(PublicKey publicKey, PrintWriter writer)
    {
        //FIRST SEND: SENDING PUBLIC KEY OF CLIENT TO RELAY (have to convert to bytes and string to send 
            // to not result in corruption)
            //convert publickey into bytes
            byte[] keyBytes = publicKey.getEncoded();

            //encode the bytes into text safe string 
            String base64Key = Base64.getEncoder().encodeToString(keyBytes);
            //send the string to relay or client 
            writer.println(base64Key);
            writer.flush();

    }
}
