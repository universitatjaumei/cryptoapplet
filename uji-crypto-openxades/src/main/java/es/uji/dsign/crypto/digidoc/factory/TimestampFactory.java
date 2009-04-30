/*
 * TimestampFactory.java
 * PROJECT: JDigiDoc
 * DESCRIPTION: Digi Doc functions for handling timestamps
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
import es.uji.dsign.crypto.digidoc.Signature;
import es.uji.dsign.crypto.digidoc.TimestampInfo;

import java.security.cert.X509Certificate;
import java.util.ArrayList;

/**
 * Interface for timestamp functions
 * 
 * @author Veiko Sinivee
 * @version 1.0
 */
public interface TimestampFactory
{

    /**
     * initializes the implementation class
     */
    public void init() throws DigiDocException;

    /**
     * Verifies this one timestamp
     * 
     * @param ts
     *            TimestampInfo object
     * @param tsaCert
     *            TSA certificate
     * @returns result of verification
     */
    public boolean verifyTimestamp(TimestampInfo ts, X509Certificate tsaCert)
            throws DigiDocException;

    /**
     * Verifies all timestamps in this signature and return a list of errors.
     * 
     * @param sig
     *            signature to verify timestamps
     * @return list of errors. Empty if no errors.
     * @throws DigiDocException
     */
    public ArrayList verifySignaturesTimestamps(Signature sig);
    // throws DigiDocException;

}
