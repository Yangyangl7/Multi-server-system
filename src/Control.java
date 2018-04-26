import java.io.IOException;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Control extends Thread {
	private static final Logger log = LogManager.getLogger();
	private static ArrayList<Connection> connections;
	private static Map<String, String> userTable = new ConcurrentHashMap<>();
	private static Map<String, String[]> serverTable = new ConcurrentHashMap<>();
	private static boolean term = false;
	private static Listener listener;
	private static final String ID = Settings.nextSecret();
	
	protected static Control control = null;
	
	private JSONParser parser = new JSONParser();
	
	public static Control getInstance() {
		if(control == null){
			control = new Control();
		} 
		return control;
	}
	
	public Control() {
		// initialize the connections array
		connections = new ArrayList<Connection>();
		try {
			// start a listener
			listener = new Listener();
			//try to connect to other servers
			this.initiateConnection();
			//server announcement in every 5 seconds
			start();
			
			// the server will print its secret if it starts alone.
			if (serverTable.size() == 0) {
				System.out.println("The secret for server connection is: " + 
								   Settings.getSecret());
			}
			
		} catch (IOException e1) {
			log.fatal("failed to startup a listening thread: "+e1);
			System.exit(-1);
		}	
	}
	
	public void initiateConnection(){
		// make a connection to another server if remote hostname is supplied
		if(Settings.getRemoteHostname()!=null){
			try {
				outgoingConnection(new Socket(Settings.getRemoteHostname(), Settings.getRemotePort()));
			} catch (IOException e) {
				log.error("failed to make connection to " + Settings.getRemoteHostname() + ":" 
			              + Settings.getRemotePort() + " :" + e);
				System.exit(-1);
			}
		}
	}
	
	/*
	 * Processing incoming messages from the connection.
	 * Return true if the connection should close.
	 */
	@SuppressWarnings("unchecked")
	public synchronized boolean process(Connection con,String msg){
		try {
			
			JSONObject inputJson = (JSONObject) parser.parse(msg);
			
			String command = (String) inputJson.get("command");
			String username = (String) inputJson.get("username");
			
			if (command == null) {
				JSONObject invalidMsg = new JSONObject();
				invalidMsg.put("command", "INVALID_MESSAGE");
				invalidMsg.put("info", "the received message did not contain a command");
				if (con.writeMsg(invalidMsg.toJSONString()))
					return true;
			}
			else {
				if (command.equals("REGISTER")) {
					String secret = (String) inputJson.get("secret");
					
					JSONObject registerMsg = new JSONObject();
					registerMsg.put("command", "REGISTER_FAILED");
					
					if (secret == null) {
						registerMsg.put("info", "secret cannot be none");
						if (con.writeMsg(registerMsg.toJSONString()))
							return true;
					}
					
					registerMsg.put("info", username + 
							" is already registered with the system");
					for (String name : userTable.keySet()) {
						if (name.equals(username)) {
							if (con.writeMsg(registerMsg.toJSONString()))
								return true;
						} 
					}
					//Identifier of the connection. 
					con.setUsername(username);
				    con.setSecret(secret);
				    
				    //Number of allowed response should be received when the registry is successful
				    con.setNumOfAllow(serverTable.size());
				    
					//valid register, need to broadcast to all servers for further checking
				    JSONObject LOCK_REQUEST = new JSONObject();
				    LOCK_REQUEST.put("command", "LOCK_REQUEST");
				    LOCK_REQUEST.put("username", username);
				    LOCK_REQUEST.put("secret", secret);
				    
				    // check whether there is only one server or not.
				    int numOfServer = serverTable.size();
					if (numOfServer > 0) {
						broadCastAllServer(LOCK_REQUEST);
						return false;
					} else {
						//Single server model
						registerMsg.replace("command", "REGISTER_SUCCESS");
						registerMsg.replace("info", "register success for " + username);
						con.setUsername(username);
					    con.setSecret(secret);
					    userTable.put(username, secret);
						if (con.writeMsg(registerMsg.toJSONString())) {
							return false;
						}
					}
				}
				else if (command.equals("LOGIN")) {
					JSONObject loginMsg = new JSONObject();
					
					if (username == null) {
						loginMsg.put("command", "LOGIN_FAILED");
						loginMsg.put("info", "attempt to login with null username");
						if (con.writeMsg(loginMsg.toJSONString()));
							return true;
					}
					else if (!con.isLogin() && username.equals("anonymous")) {
						con.login();
						loginMsg.put("command", "LOGIN_SUCCESS");
						loginMsg.put("info", "Logged in as user " + username);
						
						if (isRedirect(con, loginMsg)) {
							return true;
						}
						else {
							if (con.writeMsg(loginMsg.toJSONString()))
								return false;
						}
					}
					else if (!con.isLogin()) {
						String secret = (String) inputJson.get("secret");
						loginMsg.put("command", "LOGIN_SUCCESS");
						loginMsg.put("info", "Logged in as user " + username);
						
						for (String name : userTable.keySet()) {
							if (userTable.get(name) != null && userTable.get(name).equals(secret) && 
								name.equals(username)) {
								con.login();
								
								if (!con.getUsername().equals(username)) {
									con.setUsername(username);
								}
								if (!con.getSecret().equals(secret)) {
									con.setSecret(secret);
								}
								
								if (isRedirect(con, loginMsg)) {
									return true;
								}
								else {
									if (con.writeMsg(loginMsg.toJSONString()))
										return false;
								}
							}
						}
						
						loginMsg.replace("command", "LOGIN_FAILED");
						loginMsg.replace("info", "attempt to login with wrong secret OR "
								        + "please register first OR you already logged in");
						if (con.writeMsg(loginMsg.toJSONString()))
							return true;
					}
				}
				else if (command.equals("LOGOUT")) {
					con.logout();
					return true;
				}
				else if (command.equals("ACTIVITY_MESSAGE")) {
					JSONObject actMsg = new JSONObject();
					
					if (username == null) {
						actMsg.put("command", "INVALID_MESSAGE");
						actMsg.put("info", 
								"the received mssage did not contain an username");
						if (con.writeMsg(actMsg.toJSONString()))
							return true;
					} 
					else {
						String secret = (String) inputJson.get("secret");
						
						if (!con.isLogin() || !con.getUsername().equals(username) || 
							(!con.getUsername().equals("anonymous") && !con.getSecret().equals(secret))) {
							if (!con.isLogin()) {
								actMsg.put("command", 
										"AUTHTENTICATION_FAIL");
								actMsg.put("info",
										"user should logged in first");
								if (con.writeMsg(actMsg.toJSONString()))
									return true;
							}
							else {
								actMsg.put("command", 
										"AUTHENTICATION_FAIL");
								actMsg.put("info",
										"the supplied secret is incorrect:" + 
								          secret);
								if (con.writeMsg(actMsg.toJSONString()))
									return true;
							}
						}
						else {
							JSONObject processedMsg = new JSONObject();
							processedMsg = (JSONObject) inputJson.get("activity");

							processedMsg.put("authenticated_user", username);
							JSONObject finalMsg = new JSONObject();
							finalMsg.put("command", "ACTIVITY_BROADCAST");
							finalMsg.put("activity", processedMsg);
							
							//broad cast to all client in the server except the one who sends the msg.
							broadCastAllClient(finalMsg);
							
							//broad cast to all server
							broadCastSomeServer(con, finalMsg);
							return false;
						}
					}
				}
				else if (command.equals("ACTIVITY_BROADCAST")) {
					//invalid message
					if (!con.getSecret().equals(Settings.getSecret())) {
						JSONObject invalidMsg = new JSONObject();
						invalidMsg.put("command", "INVALID_MESSAGE");
						invalidMsg.put("info", "non-authenticated server");
						if (con.writeMsg(invalidMsg.toJSONString()))
							return true;
					}
					//valid message
					else {
						//Broadcast to all clients connecting to the server
						JSONObject recvMsg = new JSONObject();
						recvMsg = (JSONObject) inputJson.get("activity");
						JSONObject finalMsgObj = new JSONObject();
						finalMsgObj.put("activity", recvMsg);
						finalMsgObj.put("command", "ACTIVITY_BROADCAST");

						broadCastAllClient(finalMsgObj);
						broadCastSomeServer(con, finalMsgObj);
						return false;
					}
				}
				else if (command.equals("AUTHENTICATE")) {
					String secret = (String) inputJson.get("secret");
					if (secret == null) {
						JSONObject authFailMsg = new JSONObject();
						authFailMsg.put("command", "INVALID_MESSAGE");
						authFailMsg.put("info", "secret part missed");
						if (con.writeMsg(authFailMsg.toJSONString()))
							return true;
					}
					else {
						if (!secret.equals(Settings.getSecret())) {
							JSONObject authFailMsg = new JSONObject();
							authFailMsg.put("command", "AUTHENTICATION_FAIL");
							authFailMsg.put("info", "the supplied secret is incorret: " + secret);
							if (con.writeMsg(authFailMsg.toJSONString()))
								return true;
						}
						else {
							//Server who sent the initial authentication message should have a default name
							if (!con.getUsername().equals("anonymous")) {
								JSONObject invalidMsg = new JSONObject();
								invalidMsg.put("command", "INVALID_MESSAGE");
								invalidMsg.put("info", "the server already authenticated");
								if (con.writeMsg(invalidMsg.toJSONString()))
									return true;
							}
							else {
								con.setUsername(Settings.nextSecret());
								con.setSecret(secret);
								return false;
							}
						}
					}
				}
				else if  (command.equals("LOCK_REQUEST")) {
					String secret = (String) inputJson.get("secret");
					//invalid LOCK_REQUEST
					if (secret == null || username == null) {
						JSONObject invalidMsg = new JSONObject();
						invalidMsg.put("command", "INVALID_MESSAGE");
						invalidMsg.put("info", "wrong LOCK_REQUEST command");
						if (con.writeMsg(invalidMsg.toJSONString()))
							return true;
					}
					else if (!con.getSecret().equals(Settings.getSecret())) {
						JSONObject invalidMsg = new JSONObject();
						invalidMsg.put("command", "INVALID_MESSAGE");
						invalidMsg.put("info", "non-authenticated server");
						if (con.writeMsg(invalidMsg.toJSONString()))
							return true;
					}
					//valid LOCK_REQUEST
					else {
						JSONObject lockMsg = new JSONObject();
						for (String name : userTable.keySet()) {
							// User has already been registered.
							if (name.equals(username)) {
								lockMsg.put("command", "LOCK_DENIED");
								lockMsg.put("username", username);
								lockMsg.put("secret", secret);
								//broadcast LOCK_DENIED to all servers connected to the server.
								broadCastAllServer(lockMsg);
								return false;
							}
						}
						
						JSONObject Brequest = inputJson;
						//record the pair, since this server does not include the user info
						userTable.put(username, secret);
						lockMsg.put("command", "LOCK_ALLOWED");
						lockMsg.put("username", username);
						lockMsg.put("secret", secret);
						
						//broadcast LOCK_ALLOWED to all servers connected to the server
						broadCastAllServer(lockMsg);
						//broadcast LOCK_REQUEST to all servers except the one who sends the message
						broadCastSomeServer(con, Brequest);
						return false;
					}
				}
				else if (command.equals("LOCK_DENIED")) {
					//invalid message
					String secret = (String) inputJson.get("secret");
					if (secret == null || username == null) {
						JSONObject invalidMsg = new JSONObject();
						invalidMsg.put("command", "INVALID_MESSAGE");
						invalidMsg.put("info", "wrong LOCK_REQUEST command");
						if (con.writeMsg(invalidMsg.toJSONString()))
							return true;
					}
					else if (!con.getSecret().equals(Settings.getSecret())) {
						JSONObject invalidMsg = new JSONObject();
						invalidMsg.put("command", "INVALID_MESSAGE");
						invalidMsg.put("info", "non-authenticated server");
						if (con.writeMsg(invalidMsg.toJSONString()))
							return true;
					}
					//valid message
					else {
						//check userTable
						for (String name: userTable.keySet()) {
							//remove existed denied user
							if (name.equals(username)) {
								userTable.remove(username);
								//Further check is unnecessary.
								break;
							}
						}
						
						for (Connection c: this.getConnections()) {
							// Check whether the server is the one who send the initial lock_request
							// It is also the one who is checking the register user
							if (!c.getSecret().equals(Settings.getSecret()) && c.getUsername().equals(username)) {
								JSONObject registerFail = new JSONObject();
								registerFail.put("command", "REGISTER_FAILED");
								registerFail.put("info", username + " is already in the system");
								
								//reset the number of allowed should be received to successfully register a client
								c.setNumOfAllow(serverTable.size());
								if (c.writeMsg(registerFail.toJSONString()))
									return true;
							}
						}
						
						//The server is not the one who initialize the lock_request, so broadcast denied to servers except the one who sends it
						broadCastSomeServer(con, inputJson);
					}
				}
				else if (command.equals("LOCK_ALLOWED")) {
					String secret = (String) inputJson.get("secret");
					if (secret == null || username == null) {
						JSONObject invalidMsg = new JSONObject();
						invalidMsg.put("command", "INVALID_MESSAGE");
						invalidMsg.put("info", "wrong LOCK_REQUEST command");
						if (con.writeMsg(invalidMsg.toJSONString()))
							return true;
					}
					else if (!con.getSecret().equals(Settings.getSecret())) {
						JSONObject invalidMsg = new JSONObject();
						invalidMsg.put("command", "INVALID_MESSAGE");
						invalidMsg.put("info", "non-authenticated server");
						if (con.writeMsg(invalidMsg.toJSONString()))
							return true;
					}
					//valid message
					else {
						//calculating the received number of lock_allowed
						//Check whether the server has the registry that is checked.
						for (Connection c: this.getConnections()) {
							if (!c.getSecret().equals(Settings.getSecret()) && c.getUsername().equals(username)) {
								int nofa = c.getNumOfAllow();
								nofa--;
								c.setNumOfAllow(nofa);
								if (nofa == 0) {
									JSONObject registerMsg = new JSONObject();
									registerMsg.put("command", "REGISTER_SUCCESS");
									registerMsg.put("info", "reigster success for " + username);
									userTable.put(username, secret);
									//reset number of allowed should be received to successfully register a client
									c.setNumOfAllow(serverTable.size());
									if (c.writeMsg(registerMsg.toJSONString()))
										return false;
								}
								return false;
							}
						}
						//Other servers should broadcast the lock_allow to servers except the one who sent the allowed message
						broadCastSomeServer(con, inputJson);
						return false;
					}	
				}
				else if (command.equals("SERVER_ANNOUNCE")) {
					//invalid message
					if (!con.getSecret().equals(Settings.getSecret())) {
						JSONObject invalidMsg = new JSONObject();
						invalidMsg.put("command", "INVALID_MESSAGE");
						invalidMsg.put("info", "non-authenticated server");
						if (con.writeMsg(invalidMsg.toJSONString()))
							return true;
					}
					//valid message
					else {
						String id = (String) inputJson.get("id");
						//Load in 0 index, hostname in 1 index, port in 2 index
						String[] info = new String[3];
						info[0] = (String) inputJson.get("load");
						info[1] = (String) inputJson.get("hostname");
						info[2] = (String) inputJson.get("port");
						serverTable.put(id, info);
						
						//broadcast server_announce to other servers except the one sent it
						broadCastSomeServer(con, inputJson);
						return false;
					}
				}
				else if (command.equals("INVALID_MESSAGE") || command.equals("AUTHENTICATION_FAIL")) {
					System.out.println(msg);
					con.closeCon();
				}
				else {
					JSONObject invalidMsg = new JSONObject();
					invalidMsg.put("command", "INVALID_MESSAGE");
					invalidMsg.put("info", "unknown command operation");
					if (con.writeMsg(invalidMsg.toJSONString()))
						return true;
				}
			}	
		} catch (ParseException e) {
			JSONObject invalid = new JSONObject();
			invalid.put("command", "INVALID_MESSAGE");
			invalid.put("info", "JSON parse error while parsing message");
			if (con.writeMsg(invalid.toJSONString()))
				return true;
			
			log.error("Invalid jsonString input" + con.getSocket().getRemoteSocketAddress() + 
					": " + con.getSocket().getPort());
			e.printStackTrace();
		}
		
		return true;
	}
	
	/*
	 * The connection has been closed by the other party.
	 */
	public synchronized void connectionClosed(Connection con){
		if(!term) connections.remove(con);
	}
	
	/*
	 * A new incoming connection has been established, and a reference is returned to it
	 */
	public synchronized Connection incomingConnection(Socket s) throws IOException{
		log.debug("incomming connection: " + Settings.socketAddress(s));
		Connection c = new Connection(s);
		connections.add(c);
		return c;
	}
	
	/*
	 * A new outgoing connection has been established, and a reference is returned to it
	 */
	@SuppressWarnings("unchecked")
	public synchronized Connection outgoingConnection(Socket s) throws IOException{
		log.debug("outgoing connection: " + Settings.socketAddress(s));
		Connection c = new Connection(s);
		
		//Set identifier for outgoing connections
		c.setUsername(Settings.nextSecret());
		c.setSecret(Settings.getSecret());
		connections.add(c);
	
		JSONObject authenticateMsg = new JSONObject();
		authenticateMsg.put("command", "AUTHENTICATE");
		authenticateMsg.put("secret", Settings.getSecret());
		if (c.writeMsg(authenticateMsg.toJSONString())) {
			//System.out.println("Successfully authentication");
		}
		
		return c;
		
	}
	
	@SuppressWarnings("unchecked")
	@Override
	public void run(){
		log.info("using activity interval of "+Settings.getActivityInterval()+" milliseconds");
		
		JSONObject serverAnnounce = new JSONObject();
		serverAnnounce.put("command", "SERVER_ANNOUNCE");
		serverAnnounce.put("id", ID);
		serverAnnounce.put("load","0");
		serverAnnounce.put("hostname", Settings.getLocalHostname());
		serverAnnounce.put("port", Settings.getLocalPort()+"");
		while(!term){
			// do something with 5 second intervals in between
			int numOfClients = numOfClient();
			//System.out.println("Connection: " + this.getConnections().size());
			
			serverAnnounce.replace("load", numOfClients+"");
				
			broadCastAllServer(serverAnnounce);
			try {
				Thread.sleep(Settings.getActivityInterval());
			} catch (InterruptedException e) {
				log.info("received an interrupt, system is shutting down");
				break;
			}
			if(!term){
				//log.debug("doing activity");
				term=doActivity();
			}
			
		}
		log.info("closing "+ connections.size() + " connections");
		// clean up
		for(Connection connection : connections){
			connection.closeCon();
		}
		listener.setTerm(true);
	}
	
	public boolean doActivity(){
		return false;
	}
	
	public final void setTerm(boolean t){
		term = t;
	}
	
	public final ArrayList<Connection> getConnections() {
		return connections;
	}
	
	@SuppressWarnings("unchecked")
	private boolean isRedirect(Connection con, JSONObject loginMsg) {
		int clientNum = numOfClient();
		
		//Check load of all connected servers
		Iterator<Map.Entry<String, String[]>> checker = serverTable.entrySet().iterator();
		while (checker.hasNext()) {
			Map.Entry<String, String[]> entry = checker.next();
			String[] info = entry.getValue();
			if (clientNum - 2 >= Integer.parseInt(info[0])) {
				JSONObject redirectMsg = new JSONObject();
				redirectMsg.put("command", "REDIRECT");
				redirectMsg.put("hostname", info[1]);
				redirectMsg.put("port", info[2]);
				if (con.writeMsg(loginMsg.toJSONString()))
					if (con.writeMsg(redirectMsg.toJSONString())) {
						return true;
					}
			}
		}
		return false;
	}
	
	private int numOfClient() {
		int numOfClient = 0;
		//Calculate number of connected clients in the server
		for (Connection c: this.getConnections()) {
			if (!c.getSecret().equals(Settings.getSecret()) && c.isLogin()) {
				numOfClient++;
			}
		}
		return numOfClient;
	}
	
	private void broadCastAllServer(JSONObject msg) {
		for (Connection c : this.getConnections()) {
			if (c.getSecret().equals(Settings.getSecret())) {
				if (c.writeMsg(msg.toJSONString())) {
					//System.out.println("Successfully broadcast to one server");
				}
			}
		}
		//System.out.println("Successfully broadcast to all servers");
	}
	
	private void broadCastSomeServer(Connection con, JSONObject msg) {
		//broadcast to all server except the server sending it
		for (Connection c : this.getConnections()) {
			if (c.getSecret().equals(Settings.getSecret()) && !c.getUsername().equals(con.getUsername())) {
				if (c.writeMsg(msg.toJSONString())) {}
					//System.out.println("Successfully broadcast to other servers.");
			}
		}

	}
	
	private void broadCastAllClient(JSONObject msg) {
		//broadcast to all client in this server
		for (Connection c: this.getConnections()) {
			if (!c.getSecret().equals(Settings.getSecret())) {
				System.out.println(msg);
				if (c.writeMsg(msg.toJSONString())) {
					//System.out.println("Successfully broadcast to all clients");
				}
			}
		}
	}
}
