package es.uji.security.keystore;


import java.io.*;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;

/**
 * 
 * Got from:
 *     http://forum.java.sun.com/thread.jspa?forumID=60&tstart=30&threadID=484622&trange=15
 *  
 *  First insert the certificate:
 *    keytool -import  -keystore keystore  -file cert.pem  -storepass "pasword" -alias certAndKeyAlias
 *  
 *  We must reencode the key to before try to putin the keystore
 *    openssl pkcs8 -topk8 -inform PEM -in cert-codigo.key  -outform DER -nocrypt -out rsapriv.der
 *  
 * */

public class ImportPrivateKey {

	/**
	 * @param args
	 */
	
	public static void main(String [] args) {

		if (args.length != 4) {
			System.out.println("Usage: KStool <keystore> "
					+ "<key alias> <keystore password> <key file>");
			System.exit(-1);
		}

		String ksFile = args[0];
		String keyAlias = args[1];
		char[] ksPass = args[2].toCharArray();
		String keyFile = args[3];

		try {

			// read keystore file
			FileInputStream fis = new FileInputStream(ksFile);
			KeyStore ks = KeyStore.getInstance("JKS");
			ks.load(fis, ksPass);
	
			// extract the Certificate Chain from the keystore
			java.security.cert.Certificate[] certChain =
				new java.security.cert.Certificate[1];

			certChain[0] = ks.getCertificate(keyAlias);

			// read in the key file
			FileInputStream fis2 = new FileInputStream(keyFile);

			int b = 0;
			ByteArrayOutputStream baos = new ByteArrayOutputStream();

			while ((b = fis2.read()) != -1) {
				baos.write(b);
			}
			baos.flush();
			byte[] keyBytes = baos.toByteArray();

			// create PKCS8 key spec using key file
			PKCS8EncodedKeySpec eks = new PKCS8EncodedKeySpec(keyBytes);

			// use PKCS8 keyspec to generate a privatekey
			KeyFactory kf = KeyFactory.getInstance("RSA");
			PrivateKey pk = kf.generatePrivate(eks);

			// add the key to the keystore and save keystore
			ks.setKeyEntry(keyAlias, pk, ksPass, certChain);

			ks.store(new FileOutputStream(ksFile), ksPass);

			System.out.println("Successfully added Private Key to KeyStore!");
		} catch(InvalidKeySpecException e) {
			System.out.println("InvalidKeySpecException: " + e.getMessage());
			System.out.println("\nThe PrivateKey you attempted\nto load from \""
					+ keyFile + "\"\nis not in PKCS8 format.");
		} catch(Exception e) {
			System.out.println("ERROR: " + e.getMessage());
		}

	}
}
