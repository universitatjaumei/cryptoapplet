package es.mityc.firmaJava.ejemplos.xades;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import es.mityc.firmaJava.configuracion.Configuracion;
import es.mityc.firmaJava.libreria.xades.FirmaXML;

public class EjemploXADESFirma2 
{
	public static void main(String[] args) throws Exception 
	{
		KeyStore keyStore = KeyStore.getInstance("PKCS12");
		keyStore.load(new FileInputStream("/home/borillo/todos.p12"), "Heroes2000".toCharArray());

		X509Certificate cert = (X509Certificate) keyStore.getCertificate("cifrado");
		PrivateKey key = (PrivateKey) keyStore.getKey("cifrado", "Heroes2000".toCharArray());

		Configuracion configuracion = new Configuracion();
		configuracion.cargarConfiguracion();

		FirmaXML sxml = new FirmaXML(configuracion);
		sxml.signFile(cert.getSerialNumber(), cert.getIssuerDN().toString(), cert, new FileInputStream("in.xml"),
				"documento", "Certificate1,fichero", key, new FileOutputStream("out.xml"), false);
	}
}