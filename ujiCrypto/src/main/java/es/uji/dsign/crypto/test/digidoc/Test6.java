/*
 * Test6.java
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
import es.uji.dsign.crypto.digidoc.factory.DigiDocFactory;
import es.uji.dsign.crypto.digidoc.factory.SignatureFactory;

import java.io.*;
import java.security.cert.X509Certificate;
import es.uji.dsign.crypto.digidoc.*;
import es.uji.dsign.crypto.digidoc.utils.*;

import java.util.*;

/**
 * Test creating a SignedDoc, adding some data files
 * and storing to a file
 * @author  Veiko Sinivee
 * @version 1.0
 */
public class Test6 
{
    
    public static String file1 = "C:\\veiko\\work\\sk\\JDigiDoc\\tere.txt";
    public static String mime1 = "text/plain";
    public static String pin = "99661";
    public static String ddoc_file = "C:\\veiko\\work\\sk\\JDigiDoc\\test20.ddoc";
    
    public static void main(String[] args) 
    {
        SignedDoc sdoc = null;
        try {
            ConfigManager.init("jar://JDigiDoc.cfg");
            
            // create a new SignedDoc
            sdoc = new SignedDoc(SignedDoc.FORMAT_DIGIDOC_XML, SignedDoc.VERSION_1_1);
            DataFile df = sdoc.addDataFile(new File(file1), mime1, DataFile.CONTENT_EMBEDDED_BASE64);
            
            // Do card login and get certificate
            SignatureFactory sigFac = ConfigManager.
                instance().getSignatureFactory();
            System.out.println("GET Cert");
            
            
            // add a Signature
            for(int i = 0; i < 3; i++) {
            System.out.println("Prepare signature");
            X509Certificate cert = sigFac.getCertificate(0, pin);
            Signature sig = sdoc.prepareSignature(cert, null, null);
            byte[] sidigest = sig.calculateSignedInfoDigest();              
            byte[] sigval = sigFac.sign(sidigest, 0, pin);
            System.out.println("Finalize signature");
            sig.setSignatureValue(sigval);
            sigFac.reset();
            }
            /*
            // get confirmation
            System.out.println("Get confirmation");
            sig.getConfirmation();
            System.out.println("Confirmation OK!");
            //System.out.println("Signature: " + sig);
             */
            // write it in a file
            System.out.println("Writing in file: " + ddoc_file);
            sdoc.writeToFile(new File(ddoc_file));  
            
            DigiDocFactory digFac = ConfigManager.
                instance().getDigiDocFactory();
            sdoc = digFac.readSignedDoc(ddoc_file);
            //System.out.println("GOT: " + sdoc.toXML());
            
            // verify signature
            Signature sig = null;
            for(int i = 0; i < sdoc.countSignatures(); i++) {
                sig = sdoc.getSignature(i);
                System.out.println("Signature: " + sig.getId() + " - " +
                    sig.getKeyInfo().getSubjectLastName() + "," +
                    sig.getKeyInfo().getSubjectFirstName() + "," +
                    sig.getKeyInfo().getSubjectPersonalCode());
                ArrayList errs = sig.verify(sdoc, false, false);
                if(errs.size() == 0)
                    System.out.println("OK");
                for(int j = 0; j < errs.size(); j++) 
                    System.out.println((DigiDocException)errs.get(i));                
                System.out.println("");
            }
             
            
        } catch(DigiDocException ex) {
            System.err.println(ex);
            ex.printStackTrace(System.err);
        } catch(Exception ex) {
            System.err.println(ex);
            ex.printStackTrace(System.err);
        }
    }
}
