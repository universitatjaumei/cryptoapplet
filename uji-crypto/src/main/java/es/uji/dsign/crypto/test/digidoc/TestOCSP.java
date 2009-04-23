/*
 * TestOCSP.java
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
import es.uji.dsign.crypto.digidoc.factory.NotaryFactory;

import java.io.*;
import es.uji.dsign.crypto.digidoc.*;
import es.uji.dsign.crypto.digidoc.utils.*;

import java.security.cert.X509Certificate;


/**
 * Test reading a DigiDoc file
 * @author  Veiko Sinivee
 * @version 1.0
 */
public class TestOCSP {
    public static String config_file = "/home/veiko/workspace/JDigiDoc/jdigidoc.cfg";
    public static String certfile = "/home/veiko/workspace/37102230096s.crt";
    
    public static void main(String[] args) 
    {
        SignedDoc sdoc = null;
        try {
        	System.out.println("Reading config file" + config_file);
            ConfigManager.init(config_file);
            
           // read from file           
            System.out.println("Reading file" + certfile);
            X509Certificate cert = SignedDoc.readCertificate(new File(certfile));
            System.out.println("CERT: " + ((cert != null) ? cert.toString() : "NULL"));
            if(cert != null) {
            	NotaryFactory notFac = ConfigManager.
            		instance().getNotaryFactory();
            	notFac.init();
            	notFac.checkCertificate(cert);
            	System.out.println("cert verified ok!");
            }
            System.out.println("Done!");            
        } catch(DigiDocException ex) {
            System.err.println(ex);
            ex.printStackTrace(System.err);
        } catch(Exception ex) {
            System.err.println(ex);
            ex.printStackTrace(System.err);
        }
    }
}
