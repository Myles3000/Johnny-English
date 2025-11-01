//not secure but does not use cipher. How do we fix it to be more secure (mainly the decryptedFromPublicKey function)

import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;
public class Decrypt {

    public static byte [] decryptedFromPrivateKey(byte[] message, PublicKey publicKey) throws Exception
    {
        RSAPublicKey p = (RSAPublicKey) publicKey;
        int K = (p.getModulus().bitLength() + 7) >>> 3;
        if (message.length != K)
        {
            throw new IllegalArgumentException("Incorrect length");
        }

        // Decrypt: EM = c^e mod n
        byte[] decryptBlock = Encrypt.fix(new BigInteger(1, message).modPow(p.getPublicExponent(), p.getModulus()).toByteArray(), K);
        
        int i = 0;

        //checking block structure contains : 0x00 | 0x02 | PS | 0x00 | M
        if (decryptBlock[i++] != 0x00 || decryptBlock[i++] != 0x01)
        {
            throw new IllegalArgumentException("Block structure not correct ");
        }

        //skip over PS (≥8 random bytes)
        int ps = 0;
        while (i < decryptBlock.length && decryptBlock[i] == (byte) 0xFF) 
        { 
            i++; 
            ps++; 
        }
        if (ps < 8 || i >= decryptBlock.length || decryptBlock[i++] != 0x00)
        {
            throw new IllegalArgumentException("Incorrect padding");
        }
        //get hash
        if (i + 32 >= decryptBlock.length)
        {
            throw new IllegalArgumentException("Incorrect/missing Hash");
        }
        byte[] H = Arrays.copyOfRange(decryptBlock, i, i + 32);
        i += 32;

        //check for the separator before the message
        if (i >= decryptBlock.length || decryptBlock[i++] != 0x00)
        {
            throw new IllegalArgumentException("No separator ");
        }
        //get msg
        byte[] originalM= Arrays.copyOfRange(decryptBlock, i, decryptBlock.length);
        byte [] shM = MessageDigest.getInstance("SHA-256").digest(originalM);
        //verify hash(H) == SHA256(M)
        if (!Arrays.equals(H, shM))
        {
            throw new IllegalArgumentException("Hashes do not match ");
        }
        return originalM;
    }

    public static byte[] decryptedFromPublicKey(byte[] message, PrivateKey privateKey) throws Exception 
    {
        RSAPrivateKey p = (RSAPrivateKey) privateKey;
        int K = (p.getModulus().bitLength() + 7) >>> 3;
        if (message.length != K)
        {
            throw new IllegalArgumentException("Incorrect length");
        }

        // Decrypt block: EM = c^d mod n
        byte[] decryptBlock = Encrypt.fix(new BigInteger(1, message).modPow(p.getPrivateExponent(), p.getModulus()).toByteArray(), K);
        int i = 0;

        //checking block structure contains : 0x00 | 0x02 | PS | 0x00 | M
        if (decryptBlock[i++] != 0x00 || decryptBlock[i++] != 0x02)
        {
            throw new IllegalArgumentException("Block structure not correct ");
        }

        //skip over PS (≥8 random bytes)
        int ps = 0;
        while (i < decryptBlock.length && decryptBlock[i] != 0x00) 
        {
            if (decryptBlock[i] == 0) 
            {
                throw new IllegalArgumentException();
            }
            i++; 
            ps++;
        }
        if (ps < 8 || i >= decryptBlock.length)
        {
            throw new IllegalArgumentException("Incorrect padding");
        }

        //return the decrypted original msg 
        return Arrays.copyOfRange(decryptBlock, i + 1, decryptBlock.length);
    }
}
