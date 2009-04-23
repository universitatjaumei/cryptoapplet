/*
 * Test8.java
 * PROJECT: JDigiDoc
 * DESCRIPTION: Test programm for JDigiDoc library 
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
import java.io.*;
import java.security.cert.X509Certificate;
//import ee.sk.digidoc.factory.*;
//import java.util.*;
import es.uji.dsign.crypto.digidoc.*;
import es.uji.dsign.crypto.digidoc.utils.*;

/**
 * Test checking a certificate using OCSP
 * @author  Veiko Sinivee
 * @version 1.0
 */
public class Test8 {
    public static void main(String[] args) 
    {
    	/*if(args.length != 2) {
    		System.out.println("USAGE: Test8 <config-file> <cert>");
    		return;
    	}*/
        try {
        	String cfg = "c:\\JDigiDoc\\JDigiDoc.cfg";
        	String certFile = "C:\\veiko\\work\\sk\\JDigiDoc\\hansa.cer";
        	System.out.println("Using config: " + cfg);
            ConfigManager.init(cfg);
            
            // Do card login and get certificate
            System.out.println("Reading cert: " + certFile);
            X509Certificate cert = SignedDoc.readCertificate(new File(certFile));
            
            System.out.println("Cert: " + cert);
            
            /*
            System.out.println("Init NotaryFactory");
            NotaryFactory notFac = ConfigManager.
                instance().getNotaryFactory();
            System.out.println("Checking certificate");
            notFac.checkCertificate(cert);
            
            System.out.println("Certificate is OK!");
            */
            
        } catch(DigiDocException ex) {
            System.out.println("Certificate is not valid!");
            System.err.println(ex);
            ex.printStackTrace(System.err);
        } catch(Exception ex) {
            System.err.println(ex);
            ex.printStackTrace(System.err);
        }
    }
}


