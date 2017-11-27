package receiver;

import java.io.IOException;
import java.net.*;
import java.util.Base64;


public class Receiver {
	
	private int publicKeyClient;
	private int iv;
	private int key;
	private int dhKeyClient;
	private String keyString;
	private boolean chaveRSArecebida = false;
	private boolean chaveDHrecebida = false;

    public static void main(String[] args) throws Exception {
        int port = args.length == 0 ? 8887 : Integer.parseInt(args[0]);
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
	    		  System.out.println("Chave RSA recebida: " + sentence);
		    	  publicKeyClient = getPublicKeyClient(sentence);
		    	  iv = getIv(sentence);
		    	  
		    	  chaveRSArecebida = true;
		    	  System.out.println("\n*** Chave pública RSA recebida! ***");
		    	  System.out.println("Chave pública do cliente: " + publicKeyClient);
		    	  System.out.println("Iv: " + iv);
		    	  System.out.println("***********************************");
		    	  
		    	  /* Envia chave pública e iv. */
		    	  String sendString = keyGenerator.getPublicKey() + "#" + handleIv(iv);
		    	  byte[] sendData = sendString.getBytes("UTF-8");
		    	  DatagramPacket sendPacket = new DatagramPacket(sendData, sendData.length, IPAddress, receivePacket.getPort());
		    	  serverSocket.send(sendPacket);
		    	  
		    	  System.out.println("\n*** Chave pública RSA enviada! ***");
		    	  System.out.println("Chave pública do server: " + keyGenerator.getPublicKey());
		    	  System.out.println("Iv: " + handleIv(iv));
		    	  System.out.println("**********************************");
	    	  }
	    	  
	    	  else if (!chaveDHrecebida) {
	    		  keyGenerator.setP(getPClient(sentence));
	    		  keyGenerator.setG(getGClient(sentence));
	    		  keyGenerator.setSimpleKey(keyGenerator.getKeyG(getDHKeyClient(sentence)));
	    		  iv = getIvDHClient(sentence);
	    		  
	    		  chaveDHrecebida = true;
	    		  System.out.println("\n*** Chave Diffie-Hellman recebida! ***");
	    		  System.out.println("Chave Diffie-Hellman do Client: " + getDHKeyClient(sentence));
	    		  System.out.println("Simple key calculada: " + keyGenerator.getSimpleKey());
	    		  System.out.println("p: " + getPClient(sentence));
	    		  System.out.println("g: " + getGClient(sentence));
	    		  System.out.println("iv: " + getIvDHClient(sentence));
	    		  System.out.println("****************************************");
	    		  
	    		  /* Envia chave Diffie-Hellman e IV. */
	    		  String sendString = keyGenerator.getKey() + "#" + iv;
	    		  System.out.println("Iv enviado: " + iv);
	    		  byte[] sendData = sendString.getBytes("UTF-8");
	    		  DatagramPacket sendPacket = new DatagramPacket(sendData, sendData.length, IPAddress, receivePacket.getPort());
	    		  serverSocket.send(sendPacket);
	    		  
	    		  System.out.println("\n*** Chave Diffie-Hellman enviada! ***");
	    		  System.out.println("Chave Diffie-Hellman do Server: " + keyGenerator.getKey());
	    		  System.out.println("*************************************");
	    	  }
	    	  /* Recebendo apenas dados... */
	    	  else {
	    		  /* Neste caso nao eh troca de chaves, mas apenas dados criptografados. */
		    	  System.out.println("Texto recebido em HEXA: " + convertByteToHex(receivePacket.getData()));
//		    	  byte[] array = new byte[receivePacket.getData().length];
//		    	  array = receivePacket.getData();
//		    	  ModoCBC modoCBC = new ModoCBC();
//		    	  String keyHex = Integer.toHexString(keyGenerator.getKey());
//		    	  String keyString = "";
//		    	  
//		    	  for (int i = 0; i < 16; i++) { keyString += keyHex; }
//		    	  String str = convertByteToHex(receivePacket.getData());
//		    	  System.out.println("Texto decifrado: " + modoCBC.decipher(keyString, str));
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
    
    private int getDHKeyClient(String sentence) {
    	String dhKeyClient = "";
    	
    	for (int i = 0; i < sentence.length(); i++) {
    		if (sentence.charAt(i) == '#')
    			break;
    
    		dhKeyClient += sentence.charAt(i);
    	}
    	
    	return Integer.parseInt(dhKeyClient);
    }
    
    private int getPClient(String sentence) {
    	String pClient = "";
    	
    	/* Avança até o primeiro divisor (#) da cadeia. */
    	int i;
    	for (i = 0; i < sentence.length(); i++) {
    		if (sentence.charAt(i) == '#')
    			break;
    	}
    	i++;
    	
    	/* Recupera tudo o que está entre o primeiro e o segundo divisor (#). */
    	for (int j = 0; j < sentence.length()-i; j++) {
    		if (sentence.charAt(i) != '#') {
	    		pClient += sentence.charAt(i);
	    		i++;
    		}
    	}
    	
    	return Integer.parseInt(pClient);
    }
    
    private int getGClient(String sentence) {
    	String gClient = "";
    	
    	/* Avança até o segundo divisor (#). */
    	int i;
    	int divisor = 0;
    	for (i = 0; i < sentence.length(); i++) {
    		if (sentence.charAt(i) == '#')
    			divisor++;
    		
    		if (divisor == 2)
    			break;
    		
    	}
    	i++;
    	
    	
    	for (int j = 0; j < sentence.length()-i; j++) {
    		if (sentence.charAt(i) != '#') {
	    		gClient += sentence.charAt(i);
	    		i++;
    		}
    	}
    	
    	return Integer.parseInt(gClient);
    }
    
    private int getIvDHClient(String sentence) {
    	String ivDHClient = "";
    	
    	/* Avança até o terceiro divisor (#). */
    	int i;
    	int divisor = 0;
    	for (i = 0; i < sentence.length(); i++) {
    		if (sentence.charAt(i) == '#')
    			divisor++;
    		
    		if (divisor == 3)
    			break;
    	}
    	i++;
    	
    	/* Recupera o iv do Client após o terceiro divisor (#). */
    	for (int k = i; k < sentence.length(); k++) {
    		if (sentence.charAt(k) != '#') {
	    		ivDHClient += sentence.charAt(k);
    		}
    	}
    	
    	return Integer.parseInt(ivDHClient);
    }
    
    private int getPublicKeyClient(String sentence) {
    	String publicKeyClient = "";
    	
    	for (int i = 0; i < sentence.length(); i++) {
    		if (sentence.charAt(i) == '#')
    			break;
    	
    		publicKeyClient += sentence.charAt(i);
    	}
    	
    	
    	return Integer.parseInt(publicKeyClient);
    }
    
    private int getIv(String sentence) {
    	String iv = "";
    	
    	/* Avança até o primeiro divisor (#). */
    	int i = 0;
    	for (i = 0; i < sentence.length(); i++) {
    		if (sentence.charAt(i) == '#')
    			break;
    	}
    	
    	i++;
    	
    	/* Recupera tudo aquilo que está depois do divisor (#). */
    	for (int j = 0; j < sentence.length()-i; j++) {
    		iv += sentence.charAt(i);
    		i++;
    	}
    	
    	return Integer.parseInt(iv);
    }
    
    private int handleIv(int iv) {
    	return iv+1;
    }
}