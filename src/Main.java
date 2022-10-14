import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;

public class Main {	

	public static void main(String[] args) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException 
	{
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(1024);
		KeyPair kp = kpg.generateKeyPair();
		
		
		Base64.Encoder encoder = Base64.getEncoder();
		

		Writer in = new FileWriter("private.txt");
		in.write("-----BEGIN RSA PRIVATE KEY-----\n");
		in.write(encoder.encodeToString(kp.getPrivate().getEncoded()));
		in.write("\n-----END RSA PRIVATE KEY-----\n");
		in.close();
				
		Writer out = new FileWriter("public.txt");
		out.write("-----BEGIN RSA PUBLIC KEY-----\n");
		out.write(encoder.encodeToString(kp.getPublic().getEncoded()));
		out.write("\n-----END RSA PUBLIC KEY-----\n");
		out.close();
		
		KeyFactory kf = KeyFactory.getInstance(ALGORITHM);
		
		String publicKeyString = new String(Files.readAllBytes(Paths.get("public.txt")));
		String privateKeyString = new String(Files.readAllBytes(Paths.get("private.txt")));	
		
		byte[] publicKey = Base64.getDecoder().decode(publicKeyString.replace("-----BEGIN RSA PUBLIC KEY-----", "").replace("-----END RSA PUBLIC KEY-----", "").trim());
		
		byte[] privateKey = Base64.getDecoder().decode(privateKeyString.replace("-----BEGIN RSA PRIVATE KEY-----", "").replace("-----END RSA PRIVATE KEY-----","").trim());
		
			
		
		PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(privateKey);
        PrivateKey privKey = kf.generatePrivate(keySpecPKCS8);

        X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(publicKey);
        RSAPublicKey pubKey = (RSAPublicKey) kf.generatePublic(keySpecX509);       
        
        final String msgOriginal = "Exemplo de mensagem";		
	    final byte[] textoCriptografado = criptografa(msgOriginal, pubKey);		
	 	final String textoPuro = decriptografa(textoCriptografado, privKey);
	 	
		System.out.println("Mensagem Original: " + msgOriginal);
		System.out.println("Mensagem Criptografada: " +textoCriptografado.toString());
		System.out.println("Mensagem Decriptografada: " + textoPuro);		
	}
	
	public static final String ALGORITHM = "RSA";
	
	// Criptografa o texto puro usando chave pública.
		public static byte[] criptografa(String texto, PublicKey chave) {
			byte[] cipherText = null;
			try {
				final Cipher cipher = Cipher.getInstance(ALGORITHM);
				// Criptografa o texto puro usando a chave Púlica
				cipher.init(Cipher.ENCRYPT_MODE, chave);
				cipherText = cipher.doFinal(texto.getBytes());
			} catch (Exception e) {
				e.printStackTrace();
			}
			return cipherText;
		}

		// Decriptografa o texto puro usando chave privada.

		public static String decriptografa(byte[] texto, PrivateKey chave) {
			byte[] dectyptedText = null;
			try {
				final Cipher cipher = Cipher.getInstance(ALGORITHM);
				// Decriptografa o texto puro usando a chave Privada
				cipher.init(Cipher.DECRYPT_MODE, chave);
				dectyptedText = cipher.doFinal(texto);
			} catch (Exception ex) {
				ex.printStackTrace();
			}	
			return new String(dectyptedText);
		}
}
