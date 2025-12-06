import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;

public class Client 
{
    //TreeMap<String> mutualAuthentication = new TreeMap<>();
    static String mutualAuthenticationRandomMSG = null;
    static String userName = null;
    static int sequenceNumber = 1;
    static PublicKey publicKey;
    static PrivateKey privateKey;
	static PublicKeys pubKeys = new PublicKeys();

    public static void main(String[] args) throws Exception
    {
        //getting username from user (pseudonym)
        Scanner scan = new Scanner(System.in);
        System.out.print("Enter Username: ");
        userName = scan.nextLine();

        //no username repetitions 
        while(PublicKeys.containsKey(userName))
        {
            System.out.print("Username Taken, enter a new one: ");
            userName = scan.nextLine();
        }


        //generated rsa key 
        KeyPair clientRSAkey = RSAKeys.rsaKeysGenerator(1024);
        //NEED TO MAKE RELAY'S RSA KEY 2048
        

        //THIS IS WHAT THE SERVER DOES AFTER A SUCCESSFUL MUTUAL AUTHENTICATION 
        // //storing public key in a public class for all to use 
        // PublicKeys p = new PublicKeys();
        // p.addPublicKey(userName, rsakey.getPublic());

        //getting public and private keys 
        publicKey = clientRSAkey.getPublic();
        privateKey = clientRSAkey.getPrivate();

        byte[] message;
        String receivedMSG = null;
        PublicKey relaysPublicKey;
        PublicKeys p = new PublicKeys();
		try
		{
			//Create a client socket and connect to server at 127.0.0.1 port 5000
			Socket clientSocket = new Socket("localhost",5000);
            System.out.println("connected");
			
			BufferedReader reader = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            PrintWriter writer = new PrintWriter(clientSocket.getOutputStream(), true);

            System.out.println("sending pk");
            //FIRST SEND: sending public key to relay 
            SendPublicKey.sendPublicKey(publicKey, writer);
            relaysPublicKey = ReceivePublicKey.receivePublicKey(reader);
            System.out.println("pk sent");            

            /* while the relay has not placed the username and public key into the publickeys map, we are in 
             *    MUTUAL AUTHENTICATION MODE!!
            */
            int sendCount = 0;
            while(p.containsKey(userName) == false && sendCount < 2)
            {
                sendCount++;
                System.out.println("Here, send count = " + sendCount);
                //get ecrypted message for mutual authentication msg
                message = mutualAuthentication(clientRSAkey, relaysPublicKey, sendCount, receivedMSG);

                //encode it for safer transport and send it relay
                String cipherText = Base64.getEncoder().encodeToString(message);
                writer.println(cipherText);
                writer.flush();

                //wait for response
                receivedMSG = reader.readLine();
            
            }

            while(receivedMSG != null)
            {
                System.out.print("Recepient of msg: ");
                String receiver = scan.nextLine();
                System.out.print("Enter message: ");
                String msg = scan.nextLine();
                sendMsg(receiver, relaysPublicKey, msg, writer);
                receivedMSG = reader.readLine();
                receiveMsg(receivedMSG);

            }
			
			reader.close();
		}
		catch(IOException ex)
		{
			ex.printStackTrace();
		}

    }

    

    public static byte[] mutualAuthentication(KeyPair k, PublicKey relay, int sendNum, String receivedMSG) throws Exception
    {
        
        byte [] cipherText = null;
        System.out.println("IN MUTUAL AUTH");

        //FIRST MSG: Send (msg with E_privateKey)E_relayPublicKey
        if(sendNum == 1)
        {
            System.out.println("!11111");
            int randomNum = (int) (Math.random() * 1000);

            //creating SecureRandom (used for PKCS 1 padding randomness)
            SecureRandom rnd = SecureRandom.getInstanceStrong();

            String randomeMsg = "rndm" + "" + randomNum;
            mutualAuthenticationRandomMSG = randomeMsg;
            byte[] m = Encrypt.stringToByte(randomeMsg);
            //encrypt with private key of client 
            byte[] encrypt = Encrypt.enctryptWithPrivateKey(m, k.getPrivate());
			// ✅ Real local verification:
byte[] recovered = Decrypt.decryptedFromPrivateKey(encrypt, k.getPublic());
System.out.println("Local verify OK? " + Encrypt.byteToString(recovered));
            //encrypt with public key of relay 
            cipherText = Encrypt.enctryptWithPublicKey(encrypt, relay,  rnd);

        }
        else if(sendNum == 2)
        {
            //decrypt the public key encryption using private key 
            byte[] rcvedMSG = Base64.getDecoder().decode(receivedMSG);
            byte[] decryptedMSG= Decrypt.decryptedFromPublicKey(rcvedMSG, k.getPrivate());
            System.out.println(Encrypt.byteToString(decryptedMSG));
            String fullmsg = Encrypt.byteToString(decryptedMSG);
            System.out.println(fullmsg);
            String[] rcved = fullmsg.split("\\|");
            //get a treemap with exntrypeted data and string separated by the delimeter
            //TreeMap<byte[], String> delimiterSeparated = split(decryptedMSG);
            //separate them out 
            //byte[] dec1 = delimiterSeparated.firstKey();
            //String msg = delimiterSeparated.get(dec1);
            //check if received challage msg is correct 
            System.out.println("recved: " + rcved[1]);
            System.out.println("sent: "+ mutualAuthenticationRandomMSG);
            if(rcved[1].compareTo(mutualAuthenticationRandomMSG) != 0)
            {
                throw new IllegalArgumentException("Sent challenge message and received messages do not Match");
            }

            //decrypt second part of received msg 
            //byte[] fulldecryption = Decrypt.decryptedFromPrivateKey(dec1, relay);
            
            //encrypt decrypted relay challege with username of client -> | delimeter  
            //String challenge = Encrypt.byteToString(fulldecryption);
            //String toSend = "RickRolled" + "|" + userName;
            String thrirdMsg = rcved[0] + "|" + userName;
            byte[] toEncrypt = Encrypt.stringToByte(thrirdMsg);
            
            //creating SecureRandom (used for PKCS 1 padding randomness)
            SecureRandom rnd = SecureRandom.getInstanceStrong();

            //encrypt 
            cipherText = Encrypt.enctryptWithPublicKey(toEncrypt, relay, rnd);
        }
        return cipherText;
    }

    public static TreeMap<byte[], String> split(byte[] decryptedBytes) 
    {
        TreeMap<byte[],String> delimiterSeparated = new TreeMap<>();
        
        //finding delimiter index
        int delim = -1;
        for (int i = 0; i < decryptedBytes.length; i++) 
        {
            if (decryptedBytes[i] == (byte) '|') 
            { 
                delim = i;
                break;
            }
        }
        if (delim == -1)
        {
            throw new IllegalArgumentException("Delimiter '|' not found");
        }

        //left = encrypted msg (expected Base64 text)
        byte[] left = Arrays.copyOfRange(decryptedBytes, 0, delim);
        System.out.println(Encrypt.byteToString(left));
        
        //right = string msg (expected UTF-8 string)
        byte[] right = Arrays.copyOfRange(decryptedBytes, delim + 1, decryptedBytes.length);
        System.out.println(Encrypt.byteToString(right));
        //triming possible whitespace/newlines around base64 and string
        String encmsg = new String(left, StandardCharsets.US_ASCII).trim(); 
        String str = new String(right, StandardCharsets.UTF_8).trim();
        System.out.println(encmsg + "\t\t" + str);
        //decode left part from Base64 -> encrypted bytes
        byte[] encryptedBytes;
        try 
        {
            encryptedBytes = Base64.getDecoder().decode(encmsg);
        } 
        catch (IllegalArgumentException e) 
        {
            throw new IllegalArgumentException("Left side is not an Encrypted Base64 format: ", e);
        }

        //put into map
        delimiterSeparated.put(encryptedBytes, str);

        //return map
        return delimiterSeparated;
    }

    public static void sendMsg(String receiver, PublicKey relay, String msg, PrintWriter writer) throws Exception
    {
        // if(pubKeys.containsKey(receiver) == false)
        // {
        //     throw new IllegalArgumentException("Receiver with that username does not exist");
        // }
        String msgFormat = userName + "|" + receiver + "|" + sequenceNumber + "|" + msg;
        byte[] toSend = Encrypt.stringToByte(msgFormat);

        //creating SecureRandom (used for PKCS 1 padding randomness)
        SecureRandom rnd = SecureRandom.getInstanceStrong();

        //encrypt the message with public key of receiver
        byte[] innerEncryption = Encrypt.enctryptWithPublicKey(toSend, PublicKeys.getPublicKey(receiver), rnd);
		
		

        //do an outer encryption of encrypted message with public key of the relay
        rnd = SecureRandom.getInstanceStrong();
        byte[] cipherTextBytes = Encrypt.enctryptWithPublicKey(innerEncryption, relay, rnd);

        //encode it for safer transport and send it relay
        String c= Base64.getEncoder().encodeToString(toSend);
		String cipherText = c + "|"+ receiver; 
        writer.println(cipherText);
        writer.flush();

    }

    public static void receiveMsg(String msg) throws Exception
    {
        byte[] m = Encrypt.stringToByte(msg);
        byte[] rcvMsg = Decrypt.decryptedFromPublicKey(m, privateKey);

        if(rcvMsg == null)
        {
            throw new IllegalArgumentException("Received Message is empty");
        }

        //String rcvedmsg = Encrypt.byteToString(rcvMsg);
        String[] splitMessage = msg.split("\\|");

        System.out.println("Message sent from: \nSender: " + splitMessage[0] +"\nMessage: " + splitMessage[splitMessage.length-1]);
        
    }
    
}












