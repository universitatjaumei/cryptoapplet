/*
 * DOMCanonicalizationFactory.java
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

package es.uji.security.crypto.openxades.digidoc.factory;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import com.sun.org.apache.xml.internal.security.Init;
import com.sun.org.apache.xml.internal.security.c14n.Canonicalizer;

import es.uji.security.crypto.openxades.digidoc.DigiDocException;

/**
 * Canonicalizes XML using DOM and XPath
 * 
 * @author Veiko Sinivee
 * @version 1.0
 */
public class DOMCanonicalizationFactory implements CanonicalizationFactory
{
    private static Canonicalizer m_c14n;

    /**
     * Creates new DOMCanonicalizationFactory
     */
    public DOMCanonicalizationFactory()
    {
    }

    /**
     * initializes the implementation class
     */
    public void init() throws DigiDocException
    {
        try
        {
            Init.init();
            // Canonicalizer.register(Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS,
            // "org.apache.xml.security.c14n.implementations.Canonicalizer20010315OmitComments");
        }
        catch (Exception ex)
        {
            DigiDocException.handleException(ex, DigiDocException.ERR_CAN_FAC_INIT);
        }
    }

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
    public byte[] canonicalize(byte[] data, String uri) throws DigiDocException
    {
        Level lvl = Logger.getRootLogger().getLevel();
        Logger.getRootLogger().setLevel(Level.OFF);
        byte[] result = null;
        try
        {
            Init.init();
            Canonicalizer c14n = Canonicalizer
                    .getInstance("http://www.w3.org/TR/2001/REC-xml-c14n-20010315");
            result = c14n.canonicalize(data);
        }
        catch (Exception ex)
        {
            DigiDocException.handleException(ex, DigiDocException.ERR_CAN_ERROR);
        }
        Logger.getRootLogger().setLevel(lvl);
        return result;
    }
}
