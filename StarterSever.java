//this is the starter severside code with TCP connection. Basically it would be the relay in our case. It also works on a specified port #

import java.io.*;
import java.net.*;
import java.security.*;
import java.util.*;

public class TCPSampleServer 
{
	PublicKeys usersPub = new PublicKeys();

	public void go()
	{
		String message="Hello from server";
		try
		{
			//Create a server socket at port 7777
			ServerSocket serverSock = new ServerSocket(7777);
			RSAKeys craft = new RSAKeys();
			KeyPair keys = craft.KeyPairGenerator();
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
		Decrypt decode = new Decrypt();
		Encrypt encode = new Encrypt();
		KeyPair keys;


		ClientHandler(Socket sock, KeyPair keys) {
			this.sock = sock;
			this.key = key;
		}

		@Override
		public void run(){
			try(BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
			PrintWriter out = new PrintWriter(sock.getOutputStream(), true)) {
				String firstCode = in.readLine();
				

			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}
}
