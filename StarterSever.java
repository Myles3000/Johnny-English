//this is the starter severside code with TCP connection. Basically it would be the relay in our case. It also works on a specified port #

import java.io.*;
import java.net.*;
import java.security.*;
import java.util.*;

public class TCPSampleServer {
	static PublicKeys usersPub = new PublicKeys();
	private HashMap<String, Socket> currentClients = new HashMap<>();
	private HashMap<String, PublicKey> authClients = new HashMap<>();

	public void go(KeyPair keys) {
		
		try{
			//Create a server socket at port 7777
			ServerSocket serverSock = new ServerSocket(7777);
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

	public static void main(String args[]) throws Exception{
		RSAKeys locksmith = new RSAKeys();
		KeyPair keys = locksmith.rsaKeysGenerator();
		TCPSampleServer SampleServerObj = new TCPSampleServer();
		SampleServerObj.go(keys);
	}

	private class ClientHandler implements Runnable{
		private Socket sock;
		private KeyPair keys;
		private String challenge = "RickRolled";
		private ReceivePublicKey pubKey = new ReceivePublicKey();

		ClientHandler(Socket sock, KeyPair keys) {
			this.sock = sock;
			this.keys = keys;
		}

		@Override
		public void run(){
			Decrypt decode = new Decrypt();
			Encrypt encode = new Encrypt();
			String delimit = "|";
			String sender = null;
			byte[] rubix = encode.stringToByte(challenge);
			try {
				SecureRandom rnd = SecureRandom.getInstanceStrong();
				BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
				PrintWriter out = new PrintWriter(sock.getOutputStream(), true);
				PublicKey clientKey = pubKey.receivePublicKey(in);
				SendPublicKey.sendPublicKey(keys.getPublic(), out);


				if(!authClients.containsValue(clientKey)){
					// FIRST MSG: Decrypted with private key of relay, decrypted with public key of client
					String line = in.readLine();
					if (line == null) {
					    System.err.println("Received Null from Client");
					    return;
					}
					byte[] firstMsg = Base64.getDecoder().decode(line);

					//byte[] firstMsg = Base64.getDecoder().decode(in.readLine());
					byte[] partialDecode = decode.decryptedFromPublicKey(firstMsg, keys.getPrivate());
					byte[] fullyDecode = decode.decryptedFromPrivateKey(partialDecode, clientKey);

					// SECOND MSG: Encrypted with relay private key the encrypted with clients public key
					byte[] partialEncode = encode.enctryptWithPrivateKey(rubix, keys.getPrivate());
					String temp = encode.byteToString(partialEncode);
					byte[] secondMsg = encode.enctryptWithPublicKey(encode.stringToByte(temp + delimit + fullyDecode), clientKey, rnd);

					out.println(encode.byteToString(secondMsg));

					// Third MSG
					byte[] thirdMsg = Base64.getDecoder().decode(in.readLine());
					String clientResponse = encode.byteToString(decode.decryptedFromPublicKey(thirdMsg, keys.getPrivate()));
					String[] response = clientResponse.split(delimit);

					if(response[0].equals(challenge)){
						System.out.println("client authentication has been successful!");
						out.println("Your have been succefully authenticated and your public key has been documented");
						authClients.put(response[1], clientKey);
						usersPub.addPublicKey(response[1], clientKey);
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

					String code = new String(decode.decryptedFromPublicKey(encode.stringToByte(connect), keys.getPrivate()));

					String[] line = code.split(delimit);
					sender = line[0];
					String target = line[1];
					String sqn = line[2];
					String msg = line[3];

					Socket receiver = currentClients.get(target);
					if(receiver != null && !receiver.isClosed()){
						PrintWriter send = new PrintWriter(receiver.getOutputStream(), true);
						msg = sender + "|" + msg;
						send.println(encode.enctryptWithPrivateKey(encode.stringToByte(msg), keys.getPrivate()));
					} else {
						out.println("Error: Target client " + target + " not found or disconnected");
					}
				}		
				sock.close();
			} catch (IOException e) {
				System.err.println("There was an IOexception " + e.getMessage());
			} catch (NoSuchAlgorithmException e){
				System.err.println("There was an NoSuchAlgorithmException " + e.getMessage());
			} catch (Exception e){
				e.printStackTrace();
			} finally {
				if (sender != null){
					currentClients.remove(sender);
				}
			}
		}
	}
}
