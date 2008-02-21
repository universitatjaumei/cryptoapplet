package es.uji.dsign.crypto.test;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.io.*;
import java.math.BigInteger;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateFactory;
import es.uji.dsign.util.HexDump;

public class RawSignatureTest {
	public static void Mydecrypt(byte[] data, RSAPublicKey key) throws Exception
	{
		HexDump h= new HexDump();
		BigInteger msj= new BigInteger(1,data);
		BigInteger mod= key.getModulus();
		BigInteger exp=key.getPublicExponent();

		BigInteger aux= msj.modPow(exp,mod);

		System.out.println("Descifrado: " + h.xdump(aux.toByteArray()) + "   len: " + aux.toByteArray().length);
	
	}	
	
	/**
	 * @param args
	 */
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		try{	
			if (Security.getProvider("BC") == null)
			{
				BouncyCastleProvider bcp = new BouncyCastleProvider();
				Security.addProvider(bcp);
			}
									 
			InputStream inStream = new FileInputStream("/tmp/mio.cer");
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			X509Certificate cert = (X509Certificate)cf.generateCertificate(inStream);
			inStream.close();
						
			FileInputStream fis = new FileInputStream("/tmp/sign");
			byte[] b= new byte[fis.available()];
			fis.read(b);
			
			Signature rsa = Signature.getInstance( "SHA1withRSA");
			rsa.initVerify(cert);
			rsa.initVerify(cert.getPublicKey());
			System.out.println("Resultado: " + rsa.verify(b));
			
			Mydecrypt(b, (RSAPublicKey)cert.getPublicKey());
			
		}
		catch (Exception e){
		
			e.printStackTrace();
		
		}
	}

}
