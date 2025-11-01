//this is the starter severside code with TCP connection. Basically it would be the relay in our case. It also works on a specified port #

import java.io.*;
import java.net.*;
import java.security.*;
import java.util.*;

public class TCPSampleServer 
{
	PublicKeys usersPub = new PublicKeys();
	private static HashMap<String, Socket> currentClients = new HashMap<>();

	public void go()
	{
		
		try
		{
			//Create a server socket at port 7777
			ServerSocket serverSock = new ServerSocket(7777);
			RSAKeys craft = new RSAKeys();
			//Server goes into a permanent loop accepting connections from clients			
			while(true)
			{
				//Listens for a connection to be made to this socket and accepts it
				//The method blocks until a connection is made
				Socket sock = serverSock.accept();
				//PrintWriter is a bridge between character data and the socket's low-level output stream
				new Thread(new ClientHandler(sock)).start();
			}

		}
		catch(IOException ex)
		{
			ex.printStackTrace();
		}
	}
	public static void main(String args[])
	{
		
		TCPSampleServer SampleServerObj = new TCPSampleServer();
		SampleServerObj.go();
	}

	private static class ClientHandler implements Runnable{
		private Socket sock;
		private String challenge = "RickRolled";
		private ReceivePublicKey pubKey = new ReceivePublicKey();
		Decrypt decode = new Decrypt();
		Encrypt encode = new Encrypt();


		ClientHandler(Socket sock) {
			this.sock = sock;
		}

		@Override
		public void run(){
			try {
				BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
				PrintWriter out = new PrintWriter(sock.getOutputStream(), true)
				PublicKey clientKey = pubKey.receivePublicKey(in);

				iD = in.readLine();
				if(currentClients.containsKey(iD)){

				} else {
					
				}

				currentClients.put(iD, sock);

				String connect;
				while((connect = in.readLine()) != null) {

					String delimit = "|";

					String[] line = connect.split(delimit);
					String sender = line[0];
					String target = line[1];
					String sqn = line[2];
					String msg = line[3];

					Socket receiver = currentClients.get(target);

					PrintWriter send = new PrintWriter(receiver.getOutputStream(), true);
					send.println(msg);

				}
			

			} catch (Exception e) {
				e.printStackTrace();
			} finally {
				if (iD != null){
					currentClients.remove(iD);
				}
				sock.close();
			}
		}
	}
}
