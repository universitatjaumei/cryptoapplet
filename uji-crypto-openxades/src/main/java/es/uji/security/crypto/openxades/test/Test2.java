/*
 * Test2.java
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

import java.io.*; //import java.security.cert.X509Certificate;
import es.uji.security.crypto.openxades.digidoc.*;
import es.uji.security.crypto.openxades.digidoc.factory.*;
import es.uji.security.crypto.openxades.digidoc.utils.*;

import java.util.ArrayList;

//import java.util.Date;

/**
 * Test reading a DigiDoc file
 * 
 * @author Veiko Sinivee
 * @version 1.0
 */
public class Test2
{
    public static String config_file = "./jdigidoc.cfg";
    public static String inp_file1 = "./test1.txt";
    public static String ddoc_file1 = "./test1.ddoc";
    public static String mime1 = "text/txt";

    public static void main(String[] args)
    {
        SignedDoc sdoc = null;
        try
        {
            ConfigManager.init(config_file);

            // read from file
            System.out.println("Reading file" + ddoc_file1);
            sdoc = new SignedDoc(SignedDoc.FORMAT_DIGIDOC_XML, SignedDoc.VERSION_1_3);
            System.out.println("Adding file" + inp_file1);
            DataFile df = sdoc.addDataFile(new File(inp_file1), mime1,
                    DataFile.CONTENT_EMBEDDED_BASE64);

            System.out.println("Writing in file" + ddoc_file1);
            sdoc.writeToFile(new File(ddoc_file1));

            // read in again
            /*
             * DigiDocFactory digFac = ConfigManager. instance().getDigiDocFactory(); sdoc =
             * digFac.readSignedDoc(ddoc_file1);
             */

            System.out.println("Done!");
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
