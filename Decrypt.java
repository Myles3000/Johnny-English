//algorithms for decrpting using publickeys (for the msgs encrypted with private keys) and privatekeys (for the msgs encrypted with public keys)

//this does MessageDigest using rsa keys for sha 256 hashing 

import java.security.*;
import java.util.*;
import javax.crypto.Cipher;
public class Decrypt {

    public static boolean decryptedFromPrivateKey(byte[] data, byte[] signature, PublicKey publicKey) throws Exception
    {
        //signature object
        Signature s = Signature.getInstance("SHA256withRSA");
        
        //using public key to decrypt 
        s.initVerify(publicKey);
        
        //get the decrytped hash 
        s.update(data);
        
        //compare and return comparison 
        return s.verify(signature);
    }

    public static boolean decryptedFromPublicKey(byte[] data, byte[] signature, PrivateKey privateKey) throws Exception 
    {
        //calculating the size of the hash of the data 
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] expectedHash = digest.digest(data);

        //using cipher to decrypt using private key
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        //decrpt and attain hashed value 
        byte[] decryptedHash = cipher.doFinal(signature);

        //compare and return comparison 
        return Arrays.equals(expectedHash, decryptedHash);
    }
}

