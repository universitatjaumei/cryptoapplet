/*
 * FactoryManager.java
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

import org.apache.log4j.Logger;

import es.uji.security.crypto.config.ConfigManager;
import es.uji.security.crypto.openxades.digidoc.DigiDocException;

/**
 * Configuration reader for JDigiDoc
 */
public class FactoryManager
{
    private static NotaryFactory m_notFac = null;
    /** canonicalization factory instance */
    private static CanonicalizationFactory m_canFac = null;
    /** timestamp factory implementation */
    private static TimestampFactory m_tsFac = null;
    /** CRL factory instance */
    private static CRLFactory m_crlFac = null;
    /** loh4j logger */
    private Logger m_logger = null;

     /**
     * Returns the SignatureFactory instance
     * 
     * @return SignatureFactory implementation
     */
    public static SignatureFactory getSignatureFactory() throws DigiDocException
    {
        SignatureFactory sigFac = null;
        try
        {
            sigFac = (SignatureFactory) Class.forName(ConfigManager.getProperty("DIGIDOC_SIGN_IMPL"))
                    .newInstance();
            sigFac.init();
        }
        catch (DigiDocException ex)
        {
            throw ex;
        }
        catch (Exception ex)
        {
            DigiDocException.handleException(ex, DigiDocException.ERR_INIT_SIG_FAC);
        }
        return sigFac;
    }

    /**
     * Returns the SignatureFactory instance
     * 
     * @param type
     *            type of signature factory
     * @return SignatureFactory implementation
     */
    public static SignatureFactory getSignatureFactory(String type) throws DigiDocException
    {
        SignatureFactory sigFac = null;
        try
        {
            String strClass = ConfigManager.getProperty("DIGIDOC_SIGN_IMPL_" + type);
            if (strClass != null)
            {
                sigFac = (SignatureFactory) Class.forName(strClass).newInstance();
                if (sigFac != null)
                    sigFac.init();
            }
            if (sigFac == null)
                throw new DigiDocException(DigiDocException.ERR_INIT_SIG_FAC,
                        "No signature factory of type: " + type, null);
        }
        catch (DigiDocException ex)
        {
            throw ex;
        }
        catch (Exception ex)
        {
            DigiDocException.handleException(ex, DigiDocException.ERR_INIT_SIG_FAC);
        }
        return sigFac;
    }

    /**
     * Returns the NotaryFactory instance
     * 
     * @return NotaryFactory implementation
     */
    public static NotaryFactory getNotaryFactory() throws DigiDocException
    {
        try
        {
            if (m_notFac == null)
            {
                m_notFac = (NotaryFactory) Class.forName(ConfigManager.getProperty("DIGIDOC_NOTARY_IMPL"))
                        .newInstance();
                m_notFac.init();
            }
        }
        catch (DigiDocException ex)
        {
            throw ex;
        }
        catch (Exception ex)
        {
            DigiDocException.handleException(ex, DigiDocException.ERR_NOT_FAC_INIT);
        }
        return m_notFac;
    }

    /**
     * Returns the TimestampFactory instance
     * 
     * @return TimestampFactory implementation
     */
    public static TimestampFactory getTimestampFactory() throws DigiDocException
    {
        try
        {
            if (m_tsFac == null)
            {
                m_tsFac = (TimestampFactory) Class.forName(ConfigManager.getProperty("DIGIDOC_TIMESTAMP_IMPL"))
                        .newInstance();
                m_tsFac.init();
            }
        }
        catch (DigiDocException ex)
        {
            throw ex;
        }
        catch (Exception ex)
        {
            DigiDocException.handleException(ex, DigiDocException.ERR_TIMESTAMP_FAC_INIT);
        }
        return m_tsFac;
    }

    /**
     * Returns the DigiDocFactory instance
     * 
     * @return DigiDocFactory implementation
     */
    public static DigiDocFactory getDigiDocFactory() throws DigiDocException
    {
        DigiDocFactory digFac = null;
        try
        {
            digFac = (DigiDocFactory) Class.forName(ConfigManager.getProperty("DIGIDOC_FACTORY_IMPL"))
                    .newInstance();
            digFac.init();
        }
        catch (DigiDocException ex)
        {
            throw ex;
        }
        catch (Exception ex)
        {
            DigiDocException.handleException(ex, DigiDocException.ERR_DIG_FAC_INIT);
        }
        return digFac;
    }

    /**
     * Returns the CanonicalizationFactory instance
     * 
     * @return CanonicalizationFactory implementation
     */
    public static CanonicalizationFactory getCanonicalizationFactory() throws DigiDocException
    {
        try
        {
            if (m_canFac == null)
            {
                m_canFac = (CanonicalizationFactory) Class.forName(
                        ConfigManager.getProperty("CANONICALIZATION_FACTORY_IMPL")).newInstance();
                m_canFac.init();
            }
        }
        catch (DigiDocException ex)
        {
            throw ex;
        }
        catch (Exception ex)
        {
            DigiDocException.handleException(ex, DigiDocException.ERR_CAN_FAC_INIT);
        }
        return m_canFac;
    }

    /**
     * Returns the CRLFactory instance
     * 
     * @return CRLFactory implementation
     */
    public static CRLFactory getCRLFactory() throws DigiDocException
    {
        try
        {
            if (m_crlFac == null)
            {
                m_crlFac = (CRLFactory) Class.forName(ConfigManager.getProperty("CRL_FACTORY_IMPL"))
                        .newInstance();
                m_crlFac.init();
            }
        }
        catch (DigiDocException ex)
        {
            throw ex;
        }
        catch (Exception ex)
        {
            DigiDocException.handleException(ex, DigiDocException.ERR_INIT_CRL_FAC);
        }
        return m_crlFac;
    }
}