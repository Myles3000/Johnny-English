import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
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
    static int sequenceNumber =  (int) (Math.random() * 1000);
    static PublicKey publicKey;
    static PrivateKey privateKey;
	static PublicKeys pubKeys = new PublicKeys();
    static Map<String, PublicKey> systemPublicKeys = new ConcurrentHashMap<>();
    static Map<String, Integer> sequenceNumbers = new ConcurrentHashMap<>();
    static Map<String, Integer> sendSeq = new ConcurrentHashMap<>();
    static Map<String, Integer> recvSeq = new ConcurrentHashMap<>();
    static Map<String, BigInteger> dhkey = new ConcurrentHashMap<>(); 
    static Map<String, byte[]> sessionKeys = new ConcurrentHashMap<>();
    static Map<String, String> firstSend = new ConcurrentHashMap<>();
    static volatile boolean receivedAuthenticatedClients = false;
    static File logger = new File("Logger.txt");
    static BufferedWriter log;
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
			
			BufferedReader reader = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            PrintWriter writer = new PrintWriter(clientSocket.getOutputStream(), true);
            log = new BufferedWriter(new FileWriter(logger));
    
            //FIRST SEND: sending public key to relay 
            SendPublicKey.sendPublicKey(publicKey, writer);
            relaysPublicKey = ReceivePublicKey.receivePublicKey(reader);
                  

            /* while the relay has not placed the username and public key into the publickeys map, we are in 
             *    MUTUAL AUTHENTICATION MODE!!
            */
            int sendCount = 0;
            while(p.containsKey(userName) == false && sendCount < 2)
            {
                sendCount++;
                
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
                    listenLoop(reader, writer, relaysPublicKey);
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

    private static void listenLoop(BufferedReader reader, PrintWriter writer, PublicKey relaysPublicKey) throws Exception {
        
        
        String receivedMSG;
         
            //communication between clients
            while((receivedMSG = reader.readLine()) != null)
            {
                //first client to enter chat system
                if(receivedMSG.startsWith("You are the only user"))
                {
                    System.out.println(receivedMSG);
                    continue;
                }
                //a new client connected to chat system
                else if(receivedMSG.startsWith("A new user"))
                {
                    //get name from the relay message
                    String broacaseMSG = receivedMSG;
                    String[] nameSplit =broacaseMSG.split("\\: ");

                    //add new client name and public key to inner list 
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
                        String clientlist = receivedMSG;
                        String[] nameSplit =clientlist.split("\\: ");

                        //add client to inner client list
                        PublicKey newUser = ReceivePublicKey.receivePublicKey(reader);
                        systemPublicKeys.put(nameSplit[1], newUser);
                    }
                    receivedAuthenticatedClients = true;
                }
                else if (receivedMSG.startsWith("Error:") || receivedMSG.startsWith("Your have been succefully")) 
                {
                    log.write(receivedMSG);
                    log.flush();
                }
                else if(receivedMSG.startsWith("Incoming MSG"))
                {
                    //if the message is no other system message, it is a client-to-client message
                    receiveMsg(receivedMSG = reader.readLine(), writer, relaysPublicKey);
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

                try 
                {
                    if(!sessionKeys.containsKey(receiver))
                    {
                        sendMsg(receiver, relaysPublicKey, msg, writer, true);
                        firstSend.put(receiver, msg);
                    }
                    else 
                    {
                        sendMsg(receiver, relaysPublicKey, msg, writer, false);
                    }
                } 
                catch (IllegalArgumentException e) 
                {
                    System.out.println("Send error: " + e.getMessage());
                }
            }
        }
    

    public static void sendMsg(String receiver, PublicKey relay, String msg, PrintWriter writer, boolean diffie) throws Exception
    {
        int seq;
        String innerBase64;
        SecureRandom rnd;
        String msgFormat;


        //creating SecureRandom (used for PKCS 1 padding randomness)
        rnd = SecureRandom.getInstanceStrong();

        if(systemPublicKeys.containsKey(receiver) == false)
        {
            throw new IllegalArgumentException("Receiver with that username does not exist");
        }

        if(diffie)
        {
            if(!sessionKeys.containsKey(receiver))
            {
                //register sequence number 
                sequenceNumbers.put(receiver, ++sequenceNumber);

                //get dh values
                BigInteger a = DH.generatePrivate(rnd);
                dhkey.put(receiver, a);
                BigInteger A = DH.computePublic(a);

                byte[] A_bytes = A.toByteArray();                     
                String A_b64 = Base64.getEncoder().encodeToString(A_bytes);
                //create dh msg
                msgFormat =  userName + "|" + receiver + "|" + "DH" + "|" + A_b64;            
            }
            else
            {
                
                //already crafted
                msgFormat = msg;
            }
        }
        else
        {   
            //updating sequence numbers 
            Integer currentSeq = sendSeq.get(receiver);
            int nextSeq;
            if(currentSeq == null)
            {
                nextSeq = 1;
            }
            else 
            {
                nextSeq = ++currentSeq;
            }
           
            sendSeq.put(receiver, nextSeq);
            sequenceNumbers.put(receiver, nextSeq);
        
            byte[] sessionKey = sessionKeys.get(receiver);
            msgFormat = userName + "|" + receiver + "|" + nextSeq + "|" + msg;
            
            byte[] notEncrypted = Encrypt.stringToByte(msgFormat);

            byte[] dhEcrypt = DHEncryptDecrypt.xorEncrypt(notEncrypted, sessionKey);
            String dhEcryptBase64 = Base64.getEncoder().encodeToString(dhEcrypt);

            //new format with encrypted message
            msgFormat = userName + "|" + receiver + "|" + "MSG" + "|" + dhEcryptBase64;

        }

        byte[] toSend = Encrypt.stringToByte(msgFormat);

        //encrypt the message with public key of receiver
        byte[] innerEncryption = Encrypt.enctryptWithPublicKey(toSend, systemPublicKeys.get(receiver), rnd);
        
        //making it string to add receiver's name 
        innerBase64 = Base64.getEncoder().encodeToString(innerEncryption);
        
        //adding receiver's name 
        String innerEncryptionWithRcver = innerBase64 + "|" + receiver;

        //converting it back into bytes
        byte[]  innerEncryptionWithRcverByte = Encrypt.stringToByte(innerEncryptionWithRcver);
		

        //do an outer encryption of encrypted message with public key of the relay
        rnd = SecureRandom.getInstanceStrong();
        byte[] cipherTextBytes = Encrypt.enctryptWithPublicKey(innerEncryptionWithRcverByte, relay, rnd);

        //encode it for safer transport and send it relay
        String cipherText= Base64.getEncoder().encodeToString(cipherTextBytes);

        //update Logger
        log.write("CLIENT SENT:\n USERNAME: " + userName + "\n RECEIVER: " + receiver + "\n MSG: " + msg + 
        "\n INNER ENCRYPT: " +  innerEncryptionWithRcver + "\n DOUBLE ENCRYPT: " + cipherText);
        log.flush();
		//String cipherText = c + "|"+ receiver; 
        writer.println(cipherText);
        writer.flush();

    }

    public static void receiveMsg(String msg, PrintWriter writer, PublicKey relaysPublicKey) throws Exception
    {
        byte[] m = Base64.getDecoder().decode(msg);
        byte[] rcvMsg = Decrypt.decryptedFromPublicKey(m, privateKey);
        String message = null;

        if(rcvMsg == null)
        {
            throw new IllegalArgumentException("Received Message is empty");
        }

        String decryptedMSG = Encrypt.byteToString(rcvMsg);

        String[] splitMessage = decryptedMSG.split("\\|");
        
        if(splitMessage[2].compareTo("DH") == 0)
        {
            byte[] Abytes = Base64.getDecoder().decode(splitMessage[3]);
            BigInteger A = new BigInteger(1, Abytes);
            SecureRandom rnd = new SecureRandom();

            //receiver calculated own dh
            BigInteger b = DH.generatePrivate(rnd);
            BigInteger B = DH.computePublic(b);

            //A^b mod p
            BigInteger shared = DH.computeShared(b, A);
            byte[] key = DH.deriveKey(shared);

            //populate map
            sessionKeys.put(splitMessage[0], key);
            dhkey.remove(splitMessage[0]);

            byte[] B_bytes = B.toByteArray();
            String B_b64 = Base64.getEncoder().encodeToString(B_bytes);
            //reply
            String dhReply = userName + "|" + splitMessage[0] + "|" + "DHREPLY" + "|" + B_b64;
            sendMsg(splitMessage[0], relaysPublicKey, dhReply, writer, true);
        }
        else if(splitMessage[2].compareTo("DHREPLY") == 0)
        {
            //get B and a
            byte[] Bbytes = Base64.getDecoder().decode(splitMessage[3]);
            BigInteger B = new BigInteger(1, Bbytes);
            BigInteger a = dhkey.get(splitMessage[0]);

            //computer the shared key 
            BigInteger shareKey = DH.computeShared(a, B);
            byte[] key = DH.deriveKey(shareKey);
            
            //populate map
            sessionKeys.put(splitMessage[0], key);
            dhkey.remove(splitMessage[0]);

            //sequenceNumbers.put(splitMessage[0], sequenceNumber);
            //now df is done, send original msg
            sendMsg(splitMessage[0], relaysPublicKey, firstSend.remove(splitMessage[0]), writer, false);
            
        }
        else
        {
            byte[] secretKey = sessionKeys.get(splitMessage[0]);
            byte[] decryptReady = Base64.getDecoder().decode(splitMessage[splitMessage.length-1]);
            byte[] decrypted = DHEncryptDecrypt.xorDecrypt(decryptReady, secretKey);
            message = Encrypt.byteToString(decrypted);
            String[] split = message.split("\\|");

            //checking for replay attacks using sequence number 
            if(recvSeq.get(split[0]) != null)
            {
                if( Integer.parseInt(split[2]) != recvSeq.get(split[0])+1)
                {
                    System.out.println("DUPLICATED MESSAGE FOUND: DROPPING");
                    return;
                }
            }
            else
            {
                sequenceNumbers.put(split[0], Integer.valueOf(split[2]));
                recvSeq.put(split[0], Integer.valueOf(split[2]));
            }
    
            System.out.println("\nMessage sent from: " + splitMessage[0] +"\nMessage: " + split[split.length-1]);
            log.write("CLIENT RECEIVED \n SENDER: " + splitMessage[0] + "\n MESSAGE: " + m + "\n FULLY DECRYPTED MSG: " + message);
            log.flush();
        
        }
        
    }

}
