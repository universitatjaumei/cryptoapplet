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

		byte[] signedData = OS.inputStreamToByteArray(new FileInputStream("/tmp/test.xml"));
				
		MitycXAdESSignatureValidator v = new MitycXAdESSignatureValidator();		
		System.out.println((v.verify(signedData)) ? "OK" : "MAL");
	}
}