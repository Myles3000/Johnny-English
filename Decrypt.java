//not secure but does not use cipher. How do we fix it to be more secure (mainly the decryptedFromPublicKey function)

import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.util.*;
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

    public static boolean decryptedFromPublicKey(byte[] data, String signature, PrivateKey privateKey) throws Exception 
    {
        //modular math prep
        RSAPrivateKey rsaKey = (RSAPrivateKey) privateKey;
        BigInteger d = rsaKey.getPrivateExponent();
        BigInteger n = rsaKey.getModulus();

        //calculating the size of the hash of the data 
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] expectedHash = digest.digest(data);

        //changing string into int 
        byte[] signatureBytes = Base64.getDecoder().decode(signature);
        BigInteger signatureInt = new BigInteger(signatureBytes);


        //decrpt and attain hashed value 
        BigInteger decryptedInt = signatureInt.modPow(d, n);

        //compare and return comparison 
        byte[] decryptedHash = decryptedInt.toByteArray();
        return Arrays.equals(expectedHash, decryptedHash);
    }
}
