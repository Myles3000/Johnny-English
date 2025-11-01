//this class just generates rsa keys and returns the keypair generated

import java.security.*;

public class RSAKeys {

    public static KeyPair rsaKeysGenerator() throws Exception
    {
        //keypairgenerator instance to create keys with 
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");

        //key size (using 1024 for now )
        keyPairGenerator.initialize(1024); 

        //creating keypair 
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        return keyPair;

    }
}

