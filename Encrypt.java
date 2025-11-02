//not secure but does not use cipher. How do we fix it to be more secure (mainly the enctryptWithPublicKey function)

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

public class Encrypt{

    //fixing length for exactly n bytes 
    static byte[] fix(byte[] y, int k) 
    {
        if (y.length == k) 
        {   
            return y;                                       // already correct length
        }
        if (y.length == k + 1 && y[0] == 0)                // drop sign byte
        {
            return Arrays.copyOfRange(y, 1, y.length);
        }
        byte[] z = new byte[k];                             //pad left with zeros
        System.arraycopy(y, 0, z, k - y.length, y.length);
        return z;
    } 
    public static byte[] enctryptWithPrivateKey(byte[] message, PrivateKey privateKey) throws Exception
    {

        RSAPrivateKey p = (RSAPrivateKey) privateKey;
        int K = (p.getModulus().bitLength() + 7) >>> 3;

        //compute the SHA-256 hash of the message
        byte[] H = MessageDigest.getInstance("SHA-256").digest(message);        
        int ps = K - (3 + H.length + 1 + message.length); // compute pad length
        if (ps < 8)
        {
            throw new IllegalArgumentException("Message is too long");
        } 

        //building encryption block encyBlock = 0x00 | 0x02 | PS | 0x00 | M
        byte[] encyBlock = new byte[K];
        int i = 0;
        encyBlock[i++] = 0x00;                        // leading 0
        encyBlock[i++] = 0x02;                        
     
        Arrays.fill(encyBlock, i, i + ps, (byte) 0xFF);  // PS = all 0xFF
        i += ps;
        encyBlock[i++] = 0x00;                           // separator
        System.arraycopy(H, 0, encyBlock, i, H.length);  // insert hash
        i += H.length;
        encyBlock[i++] = 0x00;                           // second separator
        System.arraycopy(message, 0, encyBlock, i, message.length);  // append message

        // Compute c = EM^d mod n (private exponent)
        return fix(new BigInteger(1, encyBlock).modPow(p.getPrivateExponent(), p.getModulus()).toByteArray(), K);
    }

    public static byte[] enctryptWithPublicKey(byte[] message, PublicKey publicKey, SecureRandom randNum) throws Exception
    {

        RSAPublicKey p = (RSAPublicKey) publicKey;
        int K = (p.getModulus().bitLength() + 7) >>> 3;          // modulus length in bytes
        int ps = K - message.length - 3;             // length of padding string PS
        if (ps < 8) 
        {
            throw new IllegalArgumentException("Message is too long");
        }

        //building encryption block encyBlock = 0x00 | 0x02 | PS | 0x00 | M
        byte[] encyBlock = new byte[K];
        int i = 0;
        encyBlock[i++] = 0x00;                        // leading 0
        encyBlock[i++] = 0x02;                        
        
        //fill ps with random bytes
        for (int j = 0; j < ps; j++) 
        {
            byte b;
            do 
            { 
                b = (byte) randNum.nextInt(256); 
            } while (b == 0);
            encyBlock[i++] = b;
        }
        encyBlock[i++] = 0x00;                        //final separator b/w random bytes and msg
        System.arraycopy(message, 0, encyBlock, i, message.length); // copy plaintext message

        // Encrypt block: c = EM^e mod n
        return fix(new BigInteger(1, encyBlock).modPow(p.getPublicExponent(), p.getModulus()).toByteArray(), K);

    }

    public static byte[] stringToByte(String s) 
    { 
        return s.getBytes(StandardCharsets.UTF_8); 
    }

    public static String byteToString(byte[] b) 
    { 
        return new String(b, StandardCharsets.UTF_8); 
    }
}

