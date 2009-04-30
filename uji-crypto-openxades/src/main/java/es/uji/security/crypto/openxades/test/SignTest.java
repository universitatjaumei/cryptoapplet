/*
 * SignTest.java
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

import es.uji.security.crypto.openxades.digidoc.factory.SignatureFactory;

import java.io.*;
import java.security.cert.X509Certificate;
import es.uji.security.crypto.openxades.digidoc.*;
import es.uji.security.crypto.openxades.digidoc.utils.*;

import java.util.*;

/**
 * SignTest creating a SignedDoc, adding some data files and storing to a file
 * 
 * @author Veiko Sinivee
 * @version 1.0
 */
public class SignTest
{
    public static String config_file = null;
    public static String ddocfile = null;
    public static String inputfile = null;
    public static String mime = "application/binary";
    public static String outputfile = null;
    public static String pin = null;
    public static Date d1, d2;

    public static void main(String[] args)
    {
        SignedDoc sdoc = null;
        if (args.length < 4)
        {
            System.err.println("USAGE: SignTest <config-file> <input-file> <pin2> <outputfile>");
            return;
        }
        config_file = args[0];
        inputfile = args[1];
        pin = args[2];
        ddocfile = args[3];

        try
        {
            d1 = new Date();
            System.out.println("Reading config file: " + config_file);
            ConfigManager.init(config_file);

            // create a new SignedDoc
            sdoc = new SignedDoc(SignedDoc.FORMAT_DIGIDOC_XML, SignedDoc.VERSION_1_3);
            System.out.println("Adding file: " + inputfile);
            DataFile df = sdoc.addDataFile(new File(inputfile), mime,
                    DataFile.CONTENT_EMBEDDED_BASE64);
            // test adding data from memory
            String myBody = "Eesti Vabariigi põhiseadus Põhilehekülg | Määrangud | Otsing Eesti Vabariigi põhiseadus rahvahääletuse seadus nr 1";
            // byte[] u8b = Base64Util.encode(ConvertUtils.str2data(myBody)).getBytes();
            byte[] u8b = ConvertUtils.str2data(myBody);
            System.out.println("UTF8 body: " + Base64Util.encode(u8b));
            df.setBody(u8b, "UTF8");

            // Do card login and get certificate
            SignatureFactory sigFac = ConfigManager.instance().getSignatureFactory();
            System.out.println("GET Cert");
            X509Certificate cert = sigFac.getCertificate(0, pin);

            // add a Signature
            System.out.println("Prepare signature");

            Signature sig = sdoc.prepareSignature(cert, null, null);
            byte[] sidigest = sig.calculateSignedInfoDigest();

            d2 = new Date();
            System.out.println("Preparing complete, time: "
                    + ((d2.getTime() - d1.getTime()) / 1000) + " [sek]");

            byte[] sigval = sigFac.sign(sidigest, 0, pin);
            System.out.println("Finalize signature");
            sig.setSignatureValue(sigval);

            // get confirmation
            System.out.println("Get confirmation");
            sig.getConfirmation();
            System.out.println("Confirmation OK!");
            // System.out.println("Signature: " + sig);

            // write it in a file
            System.out.println("Writing in file: " + ddocfile);
            sdoc.writeToFile(new File(ddocfile));

            d2 = new Date();
            System.out.println("Composing complete, time: "
                    + ((d2.getTime() - d1.getTime()) / 1000) + " [sek]");

            // System.out.println("Done!");

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
