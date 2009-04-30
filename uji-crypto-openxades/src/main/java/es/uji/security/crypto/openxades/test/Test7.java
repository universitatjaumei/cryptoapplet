/*
 * Test7.java
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

import es.uji.security.crypto.openxades.digidoc.factory.NotaryFactory;
import es.uji.security.crypto.openxades.digidoc.factory.SignatureFactory;
import es.uji.security.crypto.openxades.digidoc.*;
import es.uji.security.crypto.openxades.digidoc.utils.*;

import java.security.cert.X509Certificate;

/**
 * Test checking a certificate using OCSP
 * 
 * @author Veiko Sinivee
 * @version 1.0
 */
public class Test7
{
    private static String pin = "6132";

    public static void main(String[] args)
    {
        try
        {
            ConfigManager.init("c:\\jdigidoc\\JDigiDoc.cfg");

            // Do card login and get certificate
            SignatureFactory sigFac = ConfigManager.instance().getSignatureFactory();
            System.out.println("GET Cert");
            X509Certificate cert = sigFac.getCertificate(0, pin);

            NotaryFactory notFac = ConfigManager.instance().getNotaryFactory();
            System.out.println("Checking certificate");
            notFac.checkCertificate(cert);

            System.out.println("Certificate is OK!");
        }
        catch (DigiDocException ex)
        {
            System.out.println("Certificate is not valid!");
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
