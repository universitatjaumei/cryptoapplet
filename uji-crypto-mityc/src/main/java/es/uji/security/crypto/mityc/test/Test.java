package es.uji.security.crypto.mityc.test;

import java.io.FileInputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import es.uji.security.crypto.ISignFormatProvider;
import es.uji.security.crypto.SignatureOptions;
import es.uji.security.crypto.mityc.MitycXAdESSignatureFactory;
import es.uji.security.crypto.mityc.MitycXAdESSignatureValidator;
import es.uji.security.util.OS;

public class Test 
{
	public static void main(String[] args) throws Exception 
	{
        BouncyCastleProvider bcp = new BouncyCastleProvider();
        Security.addProvider(bcp);

        // Cargando certificado de aplicación
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(new FileInputStream("../uji.keystore"), "cryptoapplet".toCharArray());

        // Recuperando clave privada para firmar
        Certificate certificate = keystore.getCertificate("uji");
        Key key = keystore.getKey("uji", "cryptoapplet".toCharArray());

		byte[] data = OS.inputStreamToByteArray(new FileInputStream("src/main/resources/in.xml"));
		
		ISignFormatProvider s = new MitycXAdESSignatureFactory();
		
		SignatureOptions signatureOptions = new SignatureOptions();
		signatureOptions.setToSignByteArray(data);
		signatureOptions.setCertificate((X509Certificate) certificate);
		signatureOptions.setPrivateKey((PrivateKey) key);
		signatureOptions.setProvider(new BouncyCastleProvider());
		
		byte[] signedData = s.formatSignature(signatureOptions);
		
		OS.dumpToFile("src/main/resources/out.xml", signedData);
				
		MitycXAdESSignatureValidator v = new MitycXAdESSignatureValidator();		
		System.out.println((v.verify(signedData)) ? "OK" : "MAL");
	}
}