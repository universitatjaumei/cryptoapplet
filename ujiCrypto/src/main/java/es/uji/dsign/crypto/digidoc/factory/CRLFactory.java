/*
 * CRLFactory.java
 * PROJECT: JDigiDoc
 * DESCRIPTION: Digi Doc functions for handling CRL-s
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

package es.uji.dsign.crypto.digidoc.factory;
import es.uji.dsign.crypto.digidoc.DigiDocException;

import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * Interface for handling CRL-s
 * DigiDoc files
 * @author  Veiko Sinivee
 * @version 1.0
 */
public interface CRLFactory 
{
    /** 
     * initializes the implementation class 
     */
    public void init()
        throws DigiDocException;

   /**
    * Checks the cert
    * @return void
    * @param cert cert to be verified
    * @param checkDate java.util.Date
    * @throws DigiDocException for all errors
    */
  public void checkCertificate(X509Certificate cert, Date checkDate) 
        throws DigiDocException;
        
   /**
    * Checks the cert
    * @return void
    * @param b64cert Certificate in base64 form
    * @param checkDate java.util.Date
    */
  //public void checkCertificateBase64(String b64cert, Date checkDate) 
   //     throws DigiDocException;
        
        
}




