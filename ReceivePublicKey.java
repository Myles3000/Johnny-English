
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

        //reconstruct the public key from the bytes 
        KeyFactory keyFactory = KeyFactory.getInstance("RSA"); 
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        
        //return the key
        return keyFactory.generatePublic(keySpec);

    }
}
