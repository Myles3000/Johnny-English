
import java.io.BufferedReader;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class ReceivePublicKey {

    public static PublicKey receivePublicKey(BufferedReader reader) throws Exception
    {
        //read from the buffer 
        String base64Key = reader.readLine();

        //convert string into bytes 
        byte[] keyBytes = Base64.getDecoder().decode(base64Key);

        if (base64Key == null) 
        {
            throw new IllegalStateException("Null Public Key Received");
        }
        //reconstruct the public key from the bytes 
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory key = KeyFactory.getInstance("RSA"); 
        
        //return the key
        return key.generatePublic(keySpec);

    }
}
