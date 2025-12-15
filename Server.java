//this is the starter severside code with TCP connection. Basically it would be the relay in our case. It also works on a specified port #

import java.io.*;
import java.net.*;
import java.security.*;
import java.util.*;

public class Server{
	static PublicKeys usersPub = new PublicKeys();
	private HashMap<String, Socket> currentClients = new HashMap<>();
	private HashMap<String, PublicKey> authClients = new HashMap<>();

	public void go(KeyPair keys) {
		
		try{
			//Create a server socket at port 5000
			ServerSocket serverSock = new ServerSocket(5000);
			//Server goes into a permanent loop accepting connections from clients			
			while(true)
			{
				//Listens for a connection to be made to this socket and accepts it
				//The method blocks until a connection is made
				Socket sock = serverSock.accept();
				//PrintWriter is a bridge between character data and the socket's low-level output stream
				new Thread(new ClientHandler(sock, keys)).start();
			}

		}
		catch(IOException ex) {
			ex.printStackTrace();
		}
	}

	private String gauntlet() throws FileNotFoundException{
		String challenge = "";
		Vector<String> maze = new Vector<>();
		File file = new File("challenge.txt");
      
        Scanner sc = new Scanner(file);

        while (sc.hasNextLine()){
			maze.add(sc.nextLine());
    	}
		Random rand = new Random();

		int lucky = rand.nextInt(maze.size() - 1);

		challenge = maze.elementAt(lucky);
		sc.close();

		return challenge;
	}

	public static void main(String args[]) throws Exception{
		RSAKeys locksmith = new RSAKeys();
		KeyPair keys = locksmith.rsaKeysGenerator(2048);
		Server SampleServerObj = new Server();
		SampleServerObj.go(keys);
	}

	private class ClientHandler implements Runnable{
		private Socket sock;
		private KeyPair keys;
		private ReceivePublicKey pubKey = new ReceivePublicKey();

		ClientHandler(Socket sock, KeyPair keys) {
			this.sock = sock;
			this.keys = keys;
		}

		private void newUser(String user, PublicKey clientKey, PrintWriter out) throws IOException{
			for (Map.Entry<String, PublicKey> entry : authClients.entrySet())
			{
				//SendPublicKey.sendPublicKey(entry.getValue(), out);
				Socket update = currentClients.get(entry.getKey());
				if(update != null && !update.isClosed()){
					PrintWriter send = new PrintWriter(update.getOutputStream(), true);
					String broadcastMSG = "A new user has been added, here is their public key. Name: " + user;
					send.println(broadcastMSG);
					SendPublicKey.sendPublicKey(clientKey, send);
				}
			}
		}

		@Override
		public void run(){
			Decrypt decode = new Decrypt();
			Encrypt encode = new Encrypt();
			String delimit = "|";
			String receiver = null;
			try {
				String challenge = gauntlet();
				byte[] rubix = encode.stringToByte(challenge);
				SecureRandom rnd = SecureRandom.getInstanceStrong();
				BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
				PrintWriter out = new PrintWriter(sock.getOutputStream(), true);
				PublicKey clientKey = pubKey.receivePublicKey(in);
				SendPublicKey.sendPublicKey(keys.getPublic(), out);
				File logger = new File("Logger.txt");
				BufferedWriter log = new BufferedWriter(new FileWriter(logger));

				if(!authClients.containsValue(clientKey)){
					// FIRST MSG: Decrypted with private key of relay, decrypted with public key of client
					String line = in.readLine();
					if (line == null) {
					    System.err.println("Received Null from Client");
					    return;
					}
					byte[] firstMsg = Base64.getDecoder().decode(line);
					log.write("RELAY RECEIVED: " + line);
					log.flush();

					//byte[] firstMsg = Base64.getDecoder().decode(in.readLine());
					byte[] partialDecode = decode.decryptedFromPublicKey(firstMsg, keys.getPrivate());
					byte[] fullyDecode = decode.decryptedFromPrivateKey(partialDecode, clientKey);

                    String msg = Encrypt.byteToString(rubix) + delimit + Encrypt.byteToString(fullyDecode);

					byte[] secondMsg = encode.enctryptWithPublicKey(encode.stringToByte(msg), clientKey, rnd);
					String cipherText = Base64.getEncoder().encodeToString(secondMsg);

					//Attacker captures second message
					log.write("Oh No, an Attacker gained access to the second authenticating msg.");
					ReplayAttackStorage.store(secondMsg);
					out.println(cipherText);

					String l = in.readLine();

					// Third MSG
					byte[] thirdMsg = Base64.getDecoder().decode(l);
					byte[] clientResponse = decode.decryptedFromPublicKey(thirdMsg, keys.getPrivate());
					String s = Encrypt.byteToString(clientResponse);

					String[] response = s.split("\\|");

					if(response[0].equals(challenge)){
						System.out.println("client authentication has been successful!");
						out.println("Your have been succefully authenticated and your public key has been documented!");
						if(!authClients.isEmpty()){

							//sending all authenticated clients to new client 
							out.println("Here are all of the current users public keys.");
							for (Map.Entry<String, PublicKey> entry : authClients.entrySet()) 
							{
								String clientList = "Name: " + entry.getKey();
								out.println(clientList);
								SendPublicKey.sendPublicKey(entry.getValue(), out);
							}
							out.println("All current clients listed");
							
							//broacasting new client to existing users and registering client in private map
							newUser(response[1], clientKey, out);
							authClients.put(response[1], clientKey);
							usersPub.addPublicKey(response[1], clientKey);
							
						}
						else
						{
							//client is the only one in the system 
							out.println("You are the only user in the system, please wait for other to connect before chatting");
							authClients.put(response[1], clientKey);
							usersPub.addPublicKey(response[1], clientKey);
						}
					}else {
						System.out.println("Authentication failed for " + sock.getInetAddress());
						sock.close();
						return;
					}
					String name = response[1];
					currentClients.put(name, sock);
				}
				

				String connect;
				while((connect = in.readLine()) != null) {
					
					//get message
					byte[] firstMsg = Base64.getDecoder().decode(connect);

					//decrypt outer shell
					byte[] partialDecode = decode.decryptedFromPublicKey(firstMsg, keys.getPrivate());
					String pd = Encrypt.byteToString(partialDecode);
					String[] line = pd.split("\\|");
					
					receiver = line[1];
					
					byte[] msg = Base64.getDecoder().decode(line[0]);
					
					Socket receiverSocket = currentClients.get(receiver);
					log.write("SERVER RECEIVED:\n FULLY ENCRYPTED MSG: " + firstMsg + "\n RECEIVER: " + receiver + 
					"\n INNER ENCRYPTION: " + partialDecode);
					log.flush();


					if(receiver != null && !receiverSocket.isClosed()){
						PrintWriter send = new PrintWriter(receiverSocket.getOutputStream(), true);
						//msg = receiver + "|" + msg;
						//ATTACKER captures msg
						log.write("Oh No, an Attacker gained access to the msg being sent to the other client!");
						ReplayAttackStorage.store(msg);
						send.println("Incoming MSG");
						send.println(line[0]);
					} else {
						out.println("Error: Target client " + receiver + " not found or disconnected");
					}
				}		
				//sock.close();
			} catch (IOException e) {
				System.err.println("There was an IOexception " + e.getMessage());

			} catch (NoSuchAlgorithmException e){
				System.err.println("There was an NoSuchAlgorithmException " + e.getMessage());
			} catch (Exception e){
				e.printStackTrace();
			} finally {
				if (receiver != null){
					currentClients.remove(receiver);
				}
			}
		}
	}
}
