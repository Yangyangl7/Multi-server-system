import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.net.UnknownHostException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

public class ClientSkeleton extends Thread {
	private static final Logger log = LogManager.getLogger();
	private static ClientSkeleton clientSolution;
	private TextFrame textFrame;

	private Socket socket;
	private DataInputStream in;
	private DataOutputStream out;
	private BufferedReader inreader;
	private PrintWriter outwriter;
	private boolean term = false;

	private JSONParser parser = new JSONParser();

	public static ClientSkeleton getInstance(){
		if(clientSolution==null){
			clientSolution = new ClientSkeleton();
		}
		return clientSolution;
	}

	public ClientSkeleton(){
		try {
			socket = Client.clientSocket;
			in = new DataInputStream(socket.getInputStream());
		    out = new DataOutputStream(socket.getOutputStream());
		    inreader = new BufferedReader(new InputStreamReader(in));
		    outwriter = new PrintWriter(out, true);
		} catch (UnknownHostException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		

		//textFrame = new TextFrame();
		start();
		
		if (!Settings.getUsername().equals("anonymous")) {
			if (Settings.getSecret() == null) {
				sendToServer(makeRegister());
			} else {
				sendToServer(makeLogin());
			}
		} else {
			sendToServer(makeLogin());
		}
		
	
	}
	
	@SuppressWarnings("unchecked")
	public JSONObject makeRegister() {
		JSONObject registerMsgObj = new JSONObject();
		registerMsgObj.put("command", "REGISTER");
		registerMsgObj.put("username", Settings.getUsername());
		String autoGenSecret = Settings.nextSecret();
		Settings.setSecret(autoGenSecret);
		// print the generated secret for later use.
		System.out.println("The auto gererated serect for login is: " + autoGenSecret);
		registerMsgObj.put("secret", autoGenSecret);
		
		return registerMsgObj;
	}
	
	@SuppressWarnings("unchecked")
	public JSONObject makeLogin() {
		JSONObject loginMsgObj = new JSONObject();
		loginMsgObj.put("command", "LOGIN");
		loginMsgObj.put("username", Settings.getUsername());
		if (!Settings.getUsername().equals("anonymous")) {
			loginMsgObj.put("secret", Settings.getSecret());
		}

		return loginMsgObj;
	}
	
	
	@SuppressWarnings("unchecked")
	public void sendActivityObject(JSONObject activityObj) {
		JSONObject activityMsgObj = new JSONObject();
		activityMsgObj.put("command", "ACTIVITY_MESSAGE");
		activityMsgObj.put("username", Settings.getUsername());		
		activityMsgObj.put("secret", Settings.getSecret());
		activityMsgObj.put("activity", activityObj);
		outwriter.println(activityMsgObj.toJSONString());
		outwriter.flush();
	}


	//@SuppressWarnings("unchecked")
	public void sendToServer(JSONObject toServerObj) {
		String command = (String) toServerObj.get("command");

		if (command == null) {
			outwriter.println(toServerObj.toJSONString());
		} else {
			if (command.equals("LOGIN")) {
				outwriter.println(toServerObj.toJSONString());

			} else if (command.equals("LOGOUT") ||
					command.equals("INVALID_MESSAGE")) {
				outwriter.println(toServerObj.toJSONString());
				disconnect();
				System.exit(0);
			} else if (command.equals("REGISTER")) {
				outwriter.println(toServerObj.toJSONString());

			} else {
				outwriter.println(toServerObj.toJSONString());
			}

			outwriter.flush();
		}
	
	}


	public void disconnect() {
		try {
			term = true;
			out.close();
			inreader.close();
			in.close();
			socket.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}


	// process some fail messages received from server.
	public void processInMsg(JSONObject obj) {
		String recvCmd = (String) obj.get("command");
		
		// if the received message has no "command", then return an
		// "INVALID_MESSAGE" to server, then close the connection.
		if (recvCmd == null) {
			sendInvalidMsgObj("noCmdError");
		} else {
			if (recvCmd.equals("INVALID_MESSAGE") ||
				recvCmd.equals("REGISTER_FAILED") ||
				recvCmd.equals("AUTHENTICATION_FAIL")) {
				System.out.println(obj);
				textFrame.setVisible(false);
				disconnect();
				System.exit(0);
			} else if (recvCmd.equals("LOGIN_SUCCESS")) {
				textFrame = new TextFrame();
				System.out.println(obj);
			} else if (recvCmd.equals("REGISTER_SUCCESS")) {
				System.out.println(obj);
				disconnect();
			} else if (recvCmd.equals("ACTIVITY_BROADCAST")) {
				textFrame.setOutputText((JSONObject) obj.get("activity"));
			} else if (recvCmd.equals("LOGIN_FAILED")) {
				System.out.println(obj);
				disconnect();
			} else if (recvCmd.equals("REDIRECT")) {
				System.out.println(obj);
				textFrame.setVisible(false);
				int newPort = Integer.parseInt((String) obj.get("port"));
				String newHostname = (String) obj.get("hostname");
				Settings.setRemotePort(newPort);
				Settings.setRemoteHostname(newHostname);
				try {
					Client.clientSocket.close();
					Client.clientSocket = new Socket(Settings.getRemoteHostname(), Settings.getRemotePort());
					clientSolution = null;
					getInstance();
				} catch (UnknownHostException e) {
					e.printStackTrace();
				} catch (IOException e) {
					e.printStackTrace();
				}
			} else {
				sendInvalidMsgObj("wrongCmdError");
			}
		}
		
	}

	// for each invalid cases, send corresponding "INVALID_MESSAGE".
	@SuppressWarnings("unchecked")
	public void sendInvalidMsgObj(String invalidCase) {
		JSONObject invalidMsg = new JSONObject();
		invalidMsg.put("command", "INVALID_MESSAGE");

		if (invalidCase.equals("JSONParseError")) {
			invalidMsg.put("info", "JSON parse error while parsing message");
		} else if (invalidCase.equals("noCmdError")) {
			invalidMsg.put("info", "the received message did not contain a command");
		} else if (invalidCase.equals("wrongCmdError")) {
			invalidMsg.put("info", "cannot find a matching command");
		}
		
		System.out.println(invalidCase);
		sendToServer(invalidMsg);
	}


	public void run() {
		try {
			log.info("listening for server on " + socket.getPort());
			while (!term) {
				String data;
				while ((data = inreader.readLine()) != null) {
					JSONObject obj;
					try {
						obj = (JSONObject) parser.parse(data);
						processInMsg(obj);
					} catch (ParseException e) {
						log.error("JSON parse error while parsing message");
						sendInvalidMsgObj("JSONParseError");
					}
				}

			}

			log.info("Disconnect!");
		} catch (IOException e) {
			System.out.println("Connection closed by foreign host.");
			disconnect();
		}

	}

	public void setTerm(boolean term) {
		this.term = term;
		if (term) interrupt();
	}

}

