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
		textFrame = new TextFrame();
		start();
	}
	
	
	@SuppressWarnings("unchecked")
	public void sendActivityObject(JSONObject activityObj) {
		String command = (String) activityObj.get("command");
		
		if (command == null) {
			outwriter.println(activityObj.toJSONString());
		} else {
			if (command.equals("LOGIN")) {
				// if the user the gives no username on the command line arguments. 
				// then login as anonymous on start
			    if (activityObj.get("username") == null) {
			        JSONObject anonymousLogin = new JSONObject();
			        anonymousLogin.put("command", "LOGIN");
			        anonymousLogin.put("username", "anonymous");
			        outwriter.println(anonymousLogin.toJSONString());
			    // if the user gives only a username but no secret then first register the user.
			    } else if ((activityObj.get("username") != null && 
			    			activityObj.get("secret") == null)) {
			    	JSONObject registerObj = new JSONObject();
			    	String autoGenSecret = Settings.nextSecret();
			    	// print the generated secret for later use.
			    	System.out.println("The auto gererated serect is: " + autoGenSecret);
			    	registerObj.put("command", "REGISTER");
			    	registerObj.put("username", activityObj.get("username"));
			    	registerObj.put("secret", autoGenSecret);
			    	outwriter.println(registerObj.toJSONString());
			    } else {
			    	outwriter.println(activityObj.toJSONString());
			    }
			    
			} else if (command.equals("LOGOUT") ||
					   command.equals("INVALID_MESSAGE")) {
				outwriter.println(activityObj.toJSONString());
				disconnect();

			} else if (command.equals("ACTIVITY_MESSAGE") || 
					   command.equals("REGISTER")) {
				outwriter.println(activityObj.toJSONString());
				
			} else {
				outwriter.println(activityObj.toJSONString());
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
	public void failureHandle(JSONObject obj) {
		String recvCmd = (String) obj.get("command");
		// if the received message has no "command", then return an 
		// "INVALID_MESSAGE" to server, then close the connection.
		if (recvCmd == null) {
			sendInvalidMsgObj("noCmdError");
		} else {
			if (recvCmd.equals("INVALID_MESSAGE") ||
				recvCmd.equals("REDIRECT") || 
				recvCmd.equals("LOGIN_FAILED") ||
				recvCmd.equals("REGISTER_FAILED") ||
				recvCmd.equals("AUTHENTICATION_FAIL")) {
				disconnect();
			} else if (recvCmd.equals("LOGIN_SUCCESS") ||
				       recvCmd.equals("ACTIVITY_BROADCAST") ||
					   recvCmd.equals("REGISTER_SUCCESS")) {
					return;
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
		
		sendActivityObject(invalidMsg);
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
						failureHandle(obj);
						textFrame.setOutputText(obj);
					} catch (ParseException e) {
						log.error("JSON parse error while parsing message");
						sendInvalidMsgObj("JSONParseError");	
					}					
				}
				
			}
			
			log.info("Disconnect!");
		} catch (IOException e) {
			log.error("Shutting down");
			disconnect();
		}
		
	}
	
	public void setTerm(boolean term) {
		this.term = term;
		if (term) interrupt();
	}	
}
