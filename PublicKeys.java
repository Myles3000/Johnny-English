import java.security.*;
import java.util.TreeMap;

public class PublicKeys {

    //Do we need to store the private keys separately, no? That looks like a security risk
    //TreeMap<String, PrivateKey> privateKeys = new TreeMap<>();

    String userName;
    PublicKey pk;
    static TreeMap<String, PublicKey> publicKeys = new TreeMap<>();

    public PublicKeys(){};

    public static void addPublicKey(String u, PublicKey p)
    {
        publicKeys.put(u,p);
    }

    //for when clients want to msgs to each other (can refrence their names instead of just their public keys )
    public static PublicKey getPublicKey(String u)
    {
        return publicKeys.get(u);
    }

    public static boolean containsKey(String un)
    {
        return publicKeys.containsKey(un);
    }
    
}
