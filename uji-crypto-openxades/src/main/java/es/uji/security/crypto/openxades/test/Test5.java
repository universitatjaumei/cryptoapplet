/*
 * Test5.java
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

package es.uji.security.crypto.openxades.test;

import es.uji.security.crypto.openxades.digidoc.factory.DigiDocFactory;
import es.uji.security.crypto.openxades.digidoc.factory.SignatureFactory;

import java.io.*;
import java.security.cert.X509Certificate;
import es.uji.security.crypto.openxades.digidoc.*;
import es.uji.security.crypto.openxades.digidoc.utils.*;

import java.util.*;

//import javax.xml.parsers.*;
//import org.xml.sax.*;
//import org.xml.sax.helpers.*;
//import org.w3c.dom.*;

/**
 * Test creating a SignedDoc, adding some data files and storing to a file
 * 
 * @author Veiko Sinivee
 * @version 1.0
 */
public class Test5
{

    public static String ddoc_file1 = "C:\\veiko\\work\\sk\\JDigiDoc\\rahumae1.ddoc";
    public static String ddoc_file2 = "C:\\veiko\\work\\sk\\JDigiDoc\\rahumae2.ddoc";
    public static String pin = "99661";

    public static void main(String[] args)
    {
        SignedDoc sdoc = null;
        try
        {
            // ConfigManager.init("jar://JDigiDoc.cfg");
            ConfigManager.init("C:\\veiko\\work\\sk\\JDigiDoc\\test1\\JDigiDoc.cfg");

            System.out.println("Reading file: " + ddoc_file1);
            DigiDocFactory digFac = ConfigManager.instance().getDigiDocFactory();
            sdoc = digFac.readSignedDoc(ddoc_file1);

            // Do card login and get certificate
            SignatureFactory sigFac = ConfigManager.instance().getSignatureFactory();
            System.out.println("GET Cert");
            X509Certificate cert = sigFac.getCertificate(0, pin);

            // add a Signature
            System.out.println("Prepare signature");
            Signature sig = sdoc.prepareSignature(cert, null, null);
            byte[] sidigest = sig.calculateSignedInfoDigest();

            byte[] sigval = sigFac.sign(sidigest, 0, pin);
            System.out.println("Finalize signature");
            sig.setSignatureValue(sigval);

            // get confirmation
            System.out.println("Get confirmation");
            sig.getConfirmation();
            System.out.println("Confirmation OK!");
            // System.out.println("Signature: " + sig);

            // write it in a file
            System.out.println("Writing in file: " + ddoc_file2);
            sdoc.writeToFile(new File(ddoc_file2));

            sdoc = digFac.readSignedDoc(ddoc_file2);
            // System.out.println("GOT: " + sdoc.toXML());

            // verify signature
            // Signature sig = null;
            for (int i = 0; i < sdoc.countSignatures(); i++)
            {
                sig = sdoc.getSignature(i);
                System.out.println("Signature: " + sig.getId() + " - "
                        + sig.getKeyInfo().getSubjectLastName() + ","
                        + sig.getKeyInfo().getSubjectFirstName() + ","
                        + sig.getKeyInfo().getSubjectPersonalCode());
                ArrayList errs = sig.verify(sdoc, false, false);
                if (errs.size() == 0)
                    System.out.println("OK");
                for (int j = 0; j < errs.size(); j++)
                    System.out.println((DigiDocException) errs.get(i));
                System.out.println("");
            }

        }
        catch (DigiDocException ex)
        {
            System.err.println(ex);
            ex.printStackTrace(System.err);
        }
        catch (Exception ex)
        {
            System.err.println(ex);
            ex.printStackTrace(System.err);
        }
    }
}
