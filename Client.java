import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;
import java.util.Scanner;
import java.util.concurrent.ConcurrentHashMap;

public class Client {

    //TreeMap<String> mutualAuthentication = new TreeMap<>();
    static String mutualAuthenticationRandomMSG = null;
    static String userName = null;
    static int sequenceNumber = 1;
    static PublicKey publicKey;
    static PrivateKey privateKey;
	static PublicKeys pubKeys = new PublicKeys();
    static Map<String, PublicKey> systemPublicKeys = new ConcurrentHashMap<>();
    static Map<String, SecureRandom> sequenceNumbers = new ConcurrentHashMap<>();
    static volatile boolean receivedAuthenticatedClients = false;
    public static void main(String[] args) throws Exception
    {
        //getting username from user (pseudonym)
        Scanner scan = new Scanner(System.in);
        System.out.print("Enter Username: ");
        userName = scan.nextLine();

        //generated rsa key 
        KeyPair clientRSAkey = RSAKeys.rsaKeysGenerator(1024);

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

            //threads for receiving and sending 
            Thread receiver = new Thread(() -> 
            {
                try 
                {
                    listenLoop(reader);
                } 
                catch (Exception e) 
                {
                    System.out.println("Receiver error: " + e.getMessage());
                    e.printStackTrace();
                }
            });

            Thread sender = new Thread(() -> 
            {
                try 
                {
                    sendLoop(scan, writer, relaysPublicKey);
                } 
                catch (Exception e) 
                {
                    System.out.println("Sender thread error: " + e.getMessage());
                    e.printStackTrace();
                }
            });

            receiver.start();
            sender.start();

            //waiting for both threads to finish 
            receiver.join();
            sender.join();

            //closing buffers 
            reader.close();
            writer.close();
            clientSocket.close();
        } catch (IOException ex) {
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
            int randomNum = (int) (Math.random() * 1000);

            //creating SecureRandom (used for PKCS 1 padding randomness)
            SecureRandom rnd = SecureRandom.getInstanceStrong();

            String randomeMsg = "rndm" + "" + randomNum;
            mutualAuthenticationRandomMSG = randomeMsg;
            byte[] m = Encrypt.stringToByte(randomeMsg);
            
            //encrypt with private key of client 
            byte[] encrypt = Encrypt.enctryptWithPrivateKey(m, k.getPrivate());
			
            //encrypt with public key of relay 
            cipherText = Encrypt.enctryptWithPublicKey(encrypt, relay,  rnd);

        }
        else if(sendNum == 2)
        {
            //decrypt the public key encryption using private key 
            byte[] rcvedMSG = Base64.getDecoder().decode(receivedMSG);
            byte[] decryptedMSG= Decrypt.decryptedFromPublicKey(rcvedMSG, k.getPrivate());
            
            //convert to string for splitting 
            String fullmsg = Encrypt.byteToString(decryptedMSG);
            String[] rcved = fullmsg.split("\\|");
           
           //check matching challenge 
            if(rcved[1].compareTo(mutualAuthenticationRandomMSG) != 0)
            {
                throw new IllegalArgumentException("Sent challenge message and received messages do not Match");
            }

            String thrirdMsg = rcved[0] + "|" + userName;
            byte[] toEncrypt = Encrypt.stringToByte(thrirdMsg);
            
            //creating SecureRandom (used for PKCS 1 padding randomness)
            SecureRandom rnd = SecureRandom.getInstanceStrong();

            //encrypt 
            cipherText = Encrypt.enctryptWithPublicKey(toEncrypt, relay, rnd);
        }
        return cipherText;
    }

    private static void listenLoop(BufferedReader reader) throws Exception {
        String receivedMSG;
         

            //communication between clients
            while((receivedMSG = reader.readLine()) != null)
            {
                //first client to enter chat system
                if(receivedMSG.startsWith("You are the only user"))
                {
                    continue;
                }
                //a new client connected to chat system
                else if(receivedMSG.startsWith("A new user"))
                {
                    //get name from the relay message
                    System.out.println(receivedMSG);
                    String broacaseMSG = receivedMSG;
                    String[] nameSplit =broacaseMSG.split("\\: ");

                    //add new client name and public key to inner list 
                    System.out.println(nameSplit[1]);
                    PublicKey newUser = ReceivePublicKey.receivePublicKey(reader);
                    systemPublicKeys.put(nameSplit[1], newUser);
                    receivedAuthenticatedClients = true;
                }
                //this client is the new client into the system with other clients 
                else if(receivedMSG.startsWith("Here are all"))
                {
                    //while we don't get notice from the relay that all clients on list have been given
                    while(!(receivedMSG = reader.readLine()).startsWith("All current"))
                    {
                        //get client name
                        System.out.println(receivedMSG);
                        String clientlist = receivedMSG;
                        String[] nameSplit =clientlist.split("\\: ");

                        //add client to inner client list
                        System.out.println(nameSplit[1]);
                        PublicKey newUser = ReceivePublicKey.receivePublicKey(reader);
                        systemPublicKeys.put(nameSplit[1], newUser);
                    }
                    receivedAuthenticatedClients = true;
                }
                else if (receivedMSG.startsWith("Error:") || receivedMSG.startsWith("Your have been succefully")) 
                {
                    System.out.println(receivedMSG);
                }
                else if(receivedMSG.startsWith("Incoming MSG"))
                {
                    //if the message is no other system message, it is a client-to-client message
                    receiveMsg(receivedMSG = reader.readLine());
                }
            }
        }
        private static void sendLoop(Scanner scan, PrintWriter writer, PublicKey relaysPublicKey) throws Exception {
            while (true) {
                // Wait until we know of at least one other user
                if (!receivedAuthenticatedClients || systemPublicKeys.isEmpty()) {
                    Thread.sleep(500);
                    continue;
                }

                System.out.print("Recipient of msg: ");
                String receiver = scan.nextLine().trim();
                System.out.print("Enter message: ");
                String msg = scan.nextLine();

                try {
                    sendMsg(receiver, relaysPublicKey, msg, writer);
                } catch (IllegalArgumentException e) {
                    System.out.println("Send error: " + e.getMessage());
                }
            }
        }
    

    public static void sendMsg(String receiver, PublicKey relay, String msg, PrintWriter writer) throws Exception
    {
        if(systemPublicKeys.containsKey(receiver) == false)
        {
            throw new IllegalArgumentException("Receiver with that username does not exist");
        }
        String msgFormat = userName + "|" + receiver + "|" + sequenceNumber + "|" + msg;
        byte[] toSend = Encrypt.stringToByte(msgFormat);

        //creating SecureRandom (used for PKCS 1 padding randomness)
        SecureRandom rnd = SecureRandom.getInstanceStrong();

        //encrypt the message with public key of receiver
        byte[] innerEncryption = Encrypt.enctryptWithPublicKey(toSend, systemPublicKeys.get(receiver), rnd);
		
        //making it string to add receiver's name 
        String innerBase64 = Base64.getEncoder().encodeToString(innerEncryption);
        System.out.println(innerBase64);
        
        //adding receiver's name 
        String innerEncryptionWithRcver = innerBase64 + "|" + receiver;

        //converting it back into bytes
        byte[]  innerEncryptionWithRcverByte = Encrypt.stringToByte(innerEncryptionWithRcver);
		

        //do an outer encryption of encrypted message with public key of the relay
        rnd = SecureRandom.getInstanceStrong();
        byte[] cipherTextBytes = Encrypt.enctryptWithPublicKey(innerEncryptionWithRcverByte, relay, rnd);

        //encode it for safer transport and send it relay
        String cipherText= Base64.getEncoder().encodeToString(cipherTextBytes);
		//String cipherText = c + "|"+ receiver; 
        writer.println(cipherText);
        writer.flush();

    }

    public static void receiveMsg(String msg) throws Exception
    {
        // byte[] m = Base64.getDecoder().decode(msg);
        // byte[] rcvMsg = Decrypt.decryptedFromPublicKey(m, privateKey);

        // if(rcvMsg == null)
        // {
        //     throw new IllegalArgumentException("Received Message is empty");
        // }

        // String decryptedMSG = Encrypt.byteToString(rcvMsg);

        // //String rcvedmsg = Encrypt.byteToString(rcvMsg);
        // String[] splitMessage = decryptedMSG.split("\\|");
        System.out.println("DEBUG receiveMsg(): got line of length " + msg.length());

        byte[] cipher;
        try {
            cipher = Base64.getDecoder().decode(msg);
        } catch (IllegalArgumentException e) {
            System.out.println("DEBUG: Not valid Base64 for ciphertext: " + msg);
            return; // don't try to decrypt garbage
        }

        byte[] rcvMsg;
        try {
            rcvMsg = Decrypt.decryptedFromPublicKey(cipher, privateKey);
        } catch (IllegalArgumentException e) {
            // This is where your "Incorrect length" comes from
            System.out.println("DEBUG: Decryption failed (probably wrong length): " + e.getMessage());
            return;
        }

        if (rcvMsg == null || rcvMsg.length == 0)
        {
            System.out.println("DEBUG: Received empty decrypted message");
            return;
        }

        String decryptedMSG = Encrypt.byteToString(rcvMsg);
        System.out.println("DEBUG: Decrypted plaintext: " + decryptedMSG);

        String[] splitMessage = decryptedMSG.split("\\|", 4);
        if (splitMessage.length < 4) {
            System.out.println("DEBUG: Bad plaintext format: " + decryptedMSG);
            return;
        }

        System.out.println("Message sent from: " + splitMessage[0] +"\nMessage: " + splitMessage[splitMessage.length-1]);
        
    }

}
