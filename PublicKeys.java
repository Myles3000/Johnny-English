//this class stores all public keys so that all clients and servers cann use this class to get public keys of anyone
//THIS IS USED BY THE SERVER/RELAY AFTER A CLIENT HAS SUCCESSFULLY AUTHENTICATED WITH THE RELAY

import java.security.*;
import java.util.TreeMap;

public class PublicKeys {

    //Do we need to store the private keys separately, no? That looks like a security risk
    //TreeMap<String, PrivateKey> privateKeys = new TreeMap<>();

    String userName;
    PublicKey pk;
    TreeMap<String, PublicKey> publicKeys = new TreeMap<>();

    public PublicKeys(){};

    public void addPublicKey(String u, PublicKey p)
    {
        publicKeys.put(u,p);
    }

    //for when clients want to msgs to each other (can refrence their names instead of just their public keys )
    public PublicKey getPublicKey(String u)
    {
        return publicKeys.get(u);
    }
    
}


