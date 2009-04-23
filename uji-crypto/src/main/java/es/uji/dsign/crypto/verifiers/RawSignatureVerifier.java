package es.uji.dsign.crypto.verifiers;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class RawSignatureVerifier {
	
	public static boolean verify(InputStream dataStream, InputStream signature, InputStream certStream)
	throws CertificateException,
	IOException,
	NoSuchAlgorithmException,
	InvalidKeyException,
	SignatureException {

		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		X509Certificate cert = (X509Certificate)cf.generateCertificate(certStream);
		
		byte[] datos= new byte[dataStream.available()];
		dataStream.read(datos);
		
		Signature rsa_vfy = Signature.getInstance( "SHA1withRSA");
		rsa_vfy.initVerify(cert.getPublicKey());
		rsa_vfy.update(datos);

		byte[] b= new byte[signature.available()];
		signature.read(b);

		return rsa_vfy.verify(b);

	}
	
	public static void main(String args[]){
		 
	        try{
	          if (args.length != 3){
	             System.err.println("Modo de uso: rawVerifier datos_originales certificado firma");
	             System.exit(-1);
	          }
	          else{
	             //Lectura de datos:
	             System.out.println("\n    Cargando certificado desde: " + args[1]);
	             InputStream inStream = new FileInputStream(args[1]);
	             
	 
	             System.out.println("    Cargando firma desde: " + args[2]);
	             FileInputStream fis = new FileInputStream(args[2]);
	            
	 
	             System.out.println("    Cargando datos originales desde: " + args[0]);
	             FileInputStream datafis = new FileInputStream(args[0]);
	             
	 
	             //Verification:
	             System.out.println("Verificando la firma ...");
	             System.out.println("El resultado es: " + RawSignatureVerifier.verify(datafis, fis, inStream));
	             
	          }
	        }
	        catch(Exception e ){
	           e.printStackTrace();
	        }
	 
	  }
}
