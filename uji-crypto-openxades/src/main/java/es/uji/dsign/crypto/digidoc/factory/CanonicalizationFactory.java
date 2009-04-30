/*
 * CanonicalizationFactory.java
 * PROJECT: JDigiDoc
 * DESCRIPTION: Digi Doc functions for canonicalizing
 * XML fragments
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

/**
 * Interface for canonicalization functions
 * 
 * @author Veiko Sinivee
 * @version 1.0
 */
public interface CanonicalizationFactory
{

    /**
     * initializes the implementation class
     */
    public void init() throws DigiDocException;

    /**
     * Canonicalizes XML fragment using the xml-c14n-20010315 algorithm
     * 
     * @param data
     *            input data
     * @param uri
     *            canonicalization algorithm
     * @returns canonicalized XML
     * @throws DigiDocException
     *             for all errors
     */
    byte[] canonicalize(byte[] data, String uri) throws DigiDocException;

}
