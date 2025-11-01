//algorithms for encrypting using publickeys and privatekeys

//this does MessageDigest using rsa keys for sha 256 hashing 

import java.security.*;
import javax.crypto.Cipher;

public class Encrypt{

    public static byte[] enctryptWithPrivateKey(byte[] data, PrivateKey privateKey) throws Exception
    {
        //Create a Signature object with SHA256withRSA algorithm
        Signature signature = Signature.getInstance("SHA256withRSA");
        
        //initialize signing with private key
        signature.initSign(privateKey);
        
        //Supply the data to be signed
        signature.update(data);
        
        //return generated signatures 
        return signature.sign();
    }

    public static byte[] enctryptWithPublicKey(byte[] data, PublicKey publicKey) throws Exception
    {
        //calculating the size of the hash of the data 
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(data);

        //use cipher to encrypt with public key 
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding"); 
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        //sign and return 
        byte[] nonStandardSignature = cipher.doFinal(hash);
        return nonStandardSignature;
    
    }
}


