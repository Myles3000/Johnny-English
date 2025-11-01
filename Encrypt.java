//algorithms for encrypting using publickeys and privatekeys

//this does MessageDigest using rsa keys for sha 256 hashing 

//not secure but does not use cipher. How do we fix it to be more secure (mainly the enctryptWithPublicKey function)

import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

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

    public static String enctryptWithPublicKey(byte[] data, PublicKey publicKey) throws Exception
    {

        //modular math prep 
        RSAPublicKey rsaKey = (RSAPublicKey) publicKey;
        BigInteger e = rsaKey.getPublicExponent();
        BigInteger n = rsaKey.getModulus();

        //calculating the size of the hash of the data 
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(data);

        //conveting hashes to ints
        BigInteger messageInt = new BigInteger(1, hash);
        

        //sign and return 
        BigInteger signatureInt = messageInt.modPow(e, n);
        return Base64.getEncoder().encodeToString(signatureInt.toByteArray());
    
    }
}

