/*
 * OCSPCertFinder.java
 * PROJECT: JDigiDoc
 * DESCRIPTION: Reads users keys from PKCS#12
 * container and lists the certificates and keys found 
 * AUTHOR:  Veiko Sinivee, S|E|B IT Partner Estonia
 *==================================================
 * Copyright (C) AS Sertifitseerimiskeskus
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * GNU Lesser General Public Licence is available at
 * http://www.gnu.org/copyleft/lesser.html
 *==================================================
 */
 package es.uji.dsign.crypto.test.digidoc;
 
//import java.security.cert.X509Certificate;
//import java.security.PrivateKey;
//import java.security.PublicKey;
import java.security.Provider;
import java.security.Security;

import java.security.KeyStore;

//import java.math.BigInteger;

/*import iaik.x509.ocsp.OCSPRequest;
import iaik.x509.ocsp.OCSPResponse;
import iaik.x509.ocsp.Request;
import iaik.x509.ocsp.CertID;
import iaik.x509.ocsp.ReqCert;
import iaik.x509.ocsp.BasicOCSPResponse;
import iaik.x509.ocsp.SingleResponse;
import iaik.x509.ocsp.CertStatus;
*/
import java.io.*;

public class OCSPCertFinder
{
	
	
	public static void main(String[] args) 
	{
		try {
		if(args.length != 2) {
			System.out.println("USAGE: OCSPCertFinder <pkcs12-file-name> <password>");
			System.exit(0);
		}
		String file = args[0];
		String passwd = args[1];
		Provider prv = (Provider)Class.
			forName("org.bouncycastle.jce.provider.BouncyCastleProvider").newInstance();
        Security.addProvider(prv);
        System.out.println("Reading file: " + file);
        FileInputStream fi = new FileInputStream(file);
        KeyStore store = KeyStore.getInstance("PKCS12", "BC");
        store.load(fi, passwd.toCharArray());
        java.util.Enumeration en = store.aliases();
        // find the key alias
        String      pName = null;
        while(en.hasMoreElements()) {
          String  n = (String)en.nextElement();
          if (store.isKeyEntry(n)) {
              pName = n;
          }
       }
	   java.security.cert.Certificate[] certs = store.getCertificateChain(pName);
	   for(int i = 0; (certs != null) && (i < certs.length); i++) {
			java.security.cert.X509Certificate cert = (java.security.cert.X509Certificate)certs[i];
			System.out.println("Cert " + i + " subject: " + cert.getSubjectDN());
            System.out.println("Cert " + i + " issuer: " + cert.getIssuerDN());                    
            System.out.println("Cert " + i + " serial: " + cert.getSerialNumber());
       }  
	   } catch(Exception ex) {
	   	System.err.println("Error: " + ex);
	   	ex.printStackTrace(System.err);
	   }
	}
	
}
