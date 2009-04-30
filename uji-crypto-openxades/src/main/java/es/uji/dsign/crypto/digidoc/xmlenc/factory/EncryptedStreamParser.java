/*
 * EncryptedStreamParser.java
 * PROJECT: JDigiDoc
 * DESCRIPTION: Digi Doc functions for parsing encrypted
 * data from streams. Designed to parse large encrypted
 * files. Uses PKCS#11 driver to decrypt the transport key.
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

package es.uji.dsign.crypto.digidoc.xmlenc.factory;

import es.uji.dsign.crypto.digidoc.DigiDocException;

import java.io.InputStream;
import java.io.OutputStream;

/**
 * Interface for parsing large encrypted files
 * 
 * @author Veiko Sinivee
 * @version 1.0
 */
public interface EncryptedStreamParser
{
    /**
     * initializes the implementation class
     */
    public void init() throws DigiDocException;

    /**
     * Reads in a EncryptedData file (.cdoc)
     * 
     * @param dencStream
     *            opened stream with EncrypyedData data The user must open and close it.
     * @param outs
     *            output stream for decrypted data
     * @param token
     *            index of PKCS#11 token used
     * @param pin
     *            pin code to decrypt transport key using PKCS#11
     * @param recipientName
     *            Recipient atribute value of <EncryptedKey> used to locate the correct transport
     *            key to decrypt with
     * @return number of bytes successfully decrypted
     * @throws DigiDocException
     *             for decryption errors
     */
    public int decryptStreamUsingRecipientName(InputStream dencStream, OutputStream outs,
            int token, String pin, String recipientName) throws DigiDocException;

}
