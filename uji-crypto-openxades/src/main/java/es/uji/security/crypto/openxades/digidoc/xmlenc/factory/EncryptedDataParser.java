/*
 * EncryptedDataParser.java
 * PROJECT: JDigiDoc
 * DESCRIPTION: Digi Doc functions for creating
 *	and reading encrypted documents. 
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

package es.uji.security.crypto.openxades.digidoc.xmlenc.factory;

import es.uji.security.crypto.openxades.digidoc.DigiDocException;
import es.uji.security.crypto.openxades.digidoc.xmlenc.EncryptedData;

import java.io.InputStream;

/**
 * Interface for reading encrypted files
 * 
 * @author Veiko Sinivee
 * @version 1.0
 */
public interface EncryptedDataParser
{
    /**
     * initializes the implementation class
     */
    public void init() throws DigiDocException;

    /**
     * Reads in a EncryptedData file
     * 
     * @param fileName
     *            file name
     * @return EncryptedData document object if successfully parsed
     */
    public EncryptedData readEncryptedData(String fileName) throws DigiDocException;

    /**
     * Reads in a EncryptedData file (.cdoc)
     * 
     * @param dencStream
     *            opened stream with EncrypyedData data The user must open and close it.
     * @return EncryptedData object if successfully parsed
     */
    public EncryptedData readEncryptedData(InputStream dencStream) throws DigiDocException;

}
