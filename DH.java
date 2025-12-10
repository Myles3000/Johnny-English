import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;

public class DH {

  //private static final int pNum = 512; // same ballpark as your RSA keys

  private static final String EQUALIZER =
        "D5BBB96D30086EC484EBA3D7F9CAEB07D43F6F0A5D8FCD62" +
        "FCEB41F1A5FB8E113A43E55A7F5F7F2E03AE6A5F2075C3B6" +
        "2DEADC0BAA7B";
    // public static final BigInteger p;
    // public static final BigInteger g;

    public static final BigInteger p = new BigInteger(EQUALIZER, 16);

    public static final BigInteger g = BigInteger.valueOf(2L);

    //a for A mod
    public static BigInteger generatePrivate(SecureRandom rnd) {
        //using 256-bit 
        return new BigInteger(256, rnd).mod(p.subtract(BigInteger.ONE)).add(BigInteger.ONE);
    }

    // A = g^a mod p
    public static BigInteger computePublic(BigInteger priv) {
        return g.modPow(priv, p);
    }

    //computing shared secret key
    public static BigInteger computeShared(BigInteger priv, BigInteger otherPub) {
        return otherPub.modPow(priv, p);
    }

    //turning bigint into 32 bytes
    public static byte[] deriveKey(BigInteger shared) throws Exception {
        byte[] sBytes = shared.toByteArray(); 
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        return sha.digest(sBytes);    //a 32-byte key
    }

}
