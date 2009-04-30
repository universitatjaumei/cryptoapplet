/*
 * ParseTest.java
 * PROJECT: JDigiDoc
 * DESCRIPTION: Test programm for JDigiDoc library. Program
 * parses a jdigidoc file, verifies signatures and prints elapsed time
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
import es.uji.security.crypto.openxades.digidoc.*;
import es.uji.security.crypto.openxades.digidoc.utils.*;

import java.util.ArrayList;
import java.util.Date;

/**
 * Test reading a DigiDoc file
 * 
 * @author Veiko Sinivee
 * @version 1.0
 */
public class ParseTest
{
    public static String config_file = null;
    public static String ddoc_file1 = null;

    public static void main(String[] args)
    {
        SignedDoc sdoc = null;
        Date d1, d2;
        if (args.length < 2)
        {
            System.err.println("USAGE: ParseTest <config-file> <input-file>");
            return;
        }
        config_file = args[0];
        ddoc_file1 = args[1];
        try
        {
            d1 = new Date();
            System.out.println("Reading config file: " + config_file);
            ConfigManager.init(config_file);

            // read from file
            System.out.println("Reading file" + ddoc_file1);
            DigiDocFactory digFac = ConfigManager.instance().getDigiDocFactory();
            sdoc = digFac.readSignedDoc(ddoc_file1);
            d2 = new Date();
            System.out.println("Parsing complete, time: " + ((d2.getTime() - d1.getTime()) / 1000)
                    + " [sek]");

            // verify signature
            ArrayList errs = sdoc.verify(false, false);
            if (errs.size() == 0)
                System.out.println("Document is OK");
            for (int j = 0; j < errs.size(); j++)
                System.out.println((DigiDocException) errs.get(j));
            // display signature
            for (int i = 0; i < sdoc.countSignatures(); i++)
            {
                Signature sig = sdoc.getSignature(i);
                System.out.print("Signature: " + sig.getId() + " - ");
                KeyInfo keyInfo = sdoc.getSignature(i).getKeyInfo();
                String userId = keyInfo.getSubjectPersonalCode();
                String firstName = keyInfo.getSubjectFirstName();
                String familyName = keyInfo.getSubjectLastName();
                // String timeStamp =
                // sdoc.getSignature(i).getSignedProperties().getSigningTime().toString();
                System.out.println("Signature: " + userId + "," + firstName + "," + familyName);
                errs = sig.verify(sdoc, false, false);
                if (errs.size() == 0)
                    System.out.print("OK");
                for (int j = 0; j < errs.size(); j++)
                    System.out.println((DigiDocException) errs.get(i));
                System.out.println("");
            }
            /*
             * for(int i = 0; i < sdoc.countDataFiles(); i++) { DataFile df = sdoc.getDataFile(i);
             * System.out.println("DataFile: " + df.getFileName() + " -> " + df.getBodyAsString());
             * }
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
