package receiver;

import java.io.IOException;
import java.net.*;
import java.util.Base64;


public class Receiver {
	
	private int publicKeyClient;
	private int iv;
	private int key;
	private String keyString;
	private boolean chaveRSArecebida = false;
	private boolean chaveDHrecebida = false;

    public static void main(String[] args) throws Exception {
        int port = args.length == 0 ? 8888 : Integer.parseInt(args[0]);
        new Receiver().run(port);
    }

    public void run(int port) throws Exception {    
      try {
        DatagramSocket serverSocket = new DatagramSocket(port);
        byte[] receiveData = new byte[16];

        System.out.printf("Listening on udp:%s:%d%n",
                InetAddress.getLocalHost().getHostAddress(), port);     
        DatagramPacket receivePacket = new DatagramPacket(receiveData,
                           receiveData.length);

      while(true) 
      {  
	      serverSocket.receive(receivePacket);
	      String sentence = new String( receivePacket.getData(), 0,
	                         receivePacket.getLength() );
	      
	      // now send acknowledgement packet back to sender     
	      InetAddress IPAddress = receivePacket.getAddress();
	      
	      KeyGenerator keyGenerator = new KeyGenerator();
	      
	      /* Pega chave pública do Cliente. */
	      try {
	    	  if (!chaveRSArecebida) {
		    	  publicKeyClient = getPublicKeyClient(sentence);
		    	  iv = getIv(sentence);
		    	  
		    	  chaveRSArecebida = true;
		    	  
		    	  /* Envia chave pública e iv. */
		    	  String sendString = keyGenerator.getPublicKey() + "#" + handleIv(iv);
		    	  byte[] sendData = sendString.getBytes("UTF-8");
		    	  DatagramPacket sendPacket = new DatagramPacket(sendData, sendData.length, IPAddress, receivePacket.getPort());
		    	  serverSocket.send(sendPacket);
	    	  }
	    	  
	    	  else if (!chaveDHrecebida) {
	    		  keyGenerator.setP(getPClient(sentence));
	    		  keyGenerator.setG(getGClient(sentence));
	    		  
	    		  chaveDHrecebida = true;
	    		  
	    		  /* Envia chave Diffie-Hellman e IV. */
	    		  String sendString = keyGenerator.getKey() + "";
	    		  byte[] sendData = sendString.getBytes("UTF-8");
	    		  DatagramPacket sendPacket = new DatagramPacket(sendData, sendData.length, IPAddress, receivePacket.getPort());
	    		  serverSocket.send(sendPacket);
	    	  }
	    	  /* Recebendo apenas dados... */
	    	  else {
	    		  /* Neste caso nao eh troca de chaves, mas apenas dados criptografados. */
		    	  System.out.println("Texto recebido em HEXA: " + convertByteToHex(receivePacket.getData()));
		    	  byte[] array = new byte[receivePacket.getData().length];
		    	  array = receivePacket.getData();
		    	  ModoCBC modoCBC = new ModoCBC();
		    	  String keyHex = Integer.toHexString(keyGenerator.getKey());
		    	  String keyString = "";
		    	  
		    	  for (int i = 0; i < 16; i++) { keyString += keyHex; }
		    	  String str = convertByteToHex(receivePacket.getData());
		    	  System.out.println("Texto decifrado: " + modoCBC.decipher(keyString, str));
	    	  }
      /*****************************************************/
	      } catch (IOException e) {
	              System.out.println(e);
	      }
      // should close serverSocket in finally block
      	}
      } catch (IOException e) {
    	  System.out.println(e);
      }
    }
    
    private String convertByteToHex(byte[] data) {
    	StringBuilder sb = new StringBuilder();
	    for (byte b : data) {
	        sb.append(String.format("%02x", b));
	    }
	    
	    return sb.toString();

    }
    
    private int getDHKey(String sentence) {
    	char[] charArray = sentence.toCharArray();
    	char[] DHKeyClient = new char[32];
    	for (int i = 0; i < charArray.length; i++) {
    		if (charArray[i] != '#')
    			DHKeyClient[i] = charArray[i];
    	}
    	
    	return Integer.parseInt(DHKeyClient.toString());
    }
    
    private int getPClient(String sentence) {
    	char[] charArray = sentence.toCharArray();
    	char[] PClient = new char[32];
    	
    	int i;
    	for (i = 0; i < charArray.length; i++) {
    		if (charArray[i] == '#')
    			break;
    	}
    	i++;
    	
    	for (int j = 0; j < charArray.length-i; j++) {
    		if (charArray[i] != '#') {
	    		PClient[j] = charArray[i];
	    		i++;
    		}
    	}
    	
    	return Integer.parseInt(PClient.toString());
    }
    
    private int getGClient(String sentence) {
    	char[] charArray = sentence.toCharArray();
    	char[] GClient = new char[32];
    	
    	int i;
    	int posicao = 0;
    	for (i = 0; i < charArray.length; i++) {
    		if (charArray[i] == '#')
    			posicao++;
    		
    		if (posicao == 2)
    			break;
    		
    	}
    	i++;
    	
    	for (int j = 0; j < charArray.length-i; j++) {
    		if (charArray[i] != '#') {
	    		GClient[j] = charArray[i];
	    		i++;
    		}
    	}
    	
    	return Integer.parseInt(GClient.toString());
    }
    
    private int getIvDHClient(String sentence) {
    	char[] charArray = sentence.toCharArray();
    	char[] IVDHClient = new char[32];
    	
    	int i;
    	int posicao = 0;
    	for (i = 0; i < charArray.length; i++) {
    		if (charArray[i] == '#')
    			posicao++;
    		
    		if (posicao == 3)
    			break;
    		
    	}
    	i++;
    	
    	for (int j = 0; j < charArray.length-i; j++) {
    		if (charArray[i] != '#') {
	    		IVDHClient[j] = charArray[i];
	    		i++;
    		}
    	}
    	
    	return Integer.parseInt(IVDHClient.toString());
    }
    
    private int getPublicKeyClient(String sentence) {
    	char[] charArray = sentence.toCharArray();
    	char[] publicKeyClient = new char[32];
    	for (int i = 0; i < charArray.length; i++) {
    		if (charArray[i] != '#')
    			publicKeyClient[i] = charArray[i];
    	}
    	
    	return Integer.parseInt(publicKeyClient.toString());
    }
    
    private int getIv(String sentence) {
    	char[] charArray = sentence.toCharArray();
    	char[] iv = new char[32];
    	int i = 0;
    	for (i = 0; i < charArray.length; i++) {
    		if (charArray[i] == '#')
    			break;
    	}
    	
    	i++;
    	
    	for (int j = 0; j < charArray.length-i; j++) {
    		iv[j] = charArray[i];
    		i++;
    	}
    	
    	return Integer.parseInt(iv.toString());
    }
    
    private int handleIv(int iv) {
    	return iv+1;
    }
}