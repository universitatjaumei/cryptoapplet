/*
 * DigiDocFactory.java
 * PROJECT: JDigiDoc
 * DESCRIPTION: Digi Doc functions for creating
 *	and reading signed documents. 
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

package es.uji.security.crypto.openxades.digidoc.factory;

import java.io.InputStream;
import java.security.cert.X509Certificate;

import es.uji.security.crypto.openxades.digidoc.DigiDocException;
import es.uji.security.crypto.openxades.digidoc.SignedDoc;

/**
 * Interface for reading and writing DigiDoc files
 * 
 * @author Veiko Sinivee
 * @version 1.0
 */
public interface DigiDocFactory
{
    /**
     * initializes the implementation class
     */
    public void init() throws DigiDocException;

    /**
     * Reads in a DigiDoc file
     * 
     * @param fileName
     *            file name
     * @return signed document object if successfully parsed
     */
    public SignedDoc readSignedDoc(String fileName) throws DigiDocException;

    /**
     * Reads in a DigiDoc file
     * 
     * @param digiDocStream
     *            opened stream with DigiDoc data The use must open and close it.
     * @return signed document object if successfully parsed
     */
    public SignedDoc readSignedDoc(InputStream digiDocStream) throws DigiDocException;

    /**
     * Verifies that the signers cert has been signed by at least one of the known root certs
     * 
     * @param cert
     *            certificate to check
     */
    public boolean verifyCertificate(X509Certificate cert) throws DigiDocException;

    /**
     * Finds the CA for this certificate if the root-certs table is not empty
     * 
     * @param cert
     *            certificate to search CA for
     * @return CA certificate
     */
    public X509Certificate findCAforCertificate(X509Certificate cert);
}
