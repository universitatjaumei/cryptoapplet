/*
 * ConfigManager.java
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

package es.uji.dsign.crypto.digidoc.utils;

import java.util.Properties;
import java.util.Hashtable;
import java.io.InputStream;
import java.io.FileInputStream;
import java.net.URL;
import es.uji.dsign.crypto.digidoc.DigiDocException;
import es.uji.dsign.crypto.digidoc.factory.CRLFactory;
import es.uji.dsign.crypto.digidoc.factory.CanonicalizationFactory;
import es.uji.dsign.crypto.digidoc.factory.DigiDocFactory;
import es.uji.dsign.crypto.digidoc.factory.NotaryFactory;
import es.uji.dsign.crypto.digidoc.factory.SignatureFactory;
import es.uji.dsign.crypto.digidoc.factory.TimestampFactory;
import es.uji.dsign.crypto.digidoc.xmlenc.factory.EncryptedDataParser;
import es.uji.dsign.crypto.digidoc.xmlenc.factory.EncryptedStreamParser;

// Logging classes
import org.apache.log4j.PropertyConfigurator;
import org.apache.log4j.Logger;

/**
 * Configuration reader for JDigiDoc
 */
public class ConfigManager {
    /** Resource bundle */
    private static Properties m_props = null;
    /** singleton instance */
    private static ConfigManager m_instance = null;
    /** notary factory instance */
    private static NotaryFactory m_notFac = null;
    /** canonicalization factory instance */
    private static CanonicalizationFactory m_canFac = null;
    /** timestamp factory implementation */
    private static TimestampFactory m_tsFac = null;
    /** CRL factory instance */
    private static CRLFactory m_crlFac = null;
    /** XML-ENC parser factory instance */
    private static EncryptedDataParser m_dencFac = null;
    /** XML-ENC parses for large encrypted files */
    private static EncryptedStreamParser m_dstrFac = null;
    /** loh4j logger */
    private Logger m_logger = null;
    
    /**
     * Singleton accessor
     */
    public static ConfigManager instance() {
        if(m_instance == null)
            m_instance = new ConfigManager();
        return m_instance;
    }
    
    /**
     * ConfigManager default constructor
     */
    private ConfigManager() {
    	// initialize logging
    	if(getProperty("DIGIDOC_LOG4J_CONFIG") != null)
    		PropertyConfigurator.configure(getProperty("DIGIDOC_LOG4J_CONFIG"));
    	m_logger = Logger.getLogger(ConfigManager.class);
    }
    
    /**
     * Resets the configuration table
     */
    public void reset() {
    	m_props = new Properties();
    }
         
    /**
     * Init method for reading the config data
     * from a properties file. Note that this method
     * doesn't reset the configuration table held in
     * memory. Thus you can use it multpile times and
     * add constantly new configuration entries. Use the
     * reset() method to reset the configuration table.
     * @param cfgFileName config file anme or URL
     * @return success flag
     */
    public static boolean init(String cfgFileName) {
    	boolean bOk = false;
        try {
        	if(m_props == null)
        		m_props = new Properties();
            InputStream isCfg = null;
            URL url = null;
            if(cfgFileName.startsWith("http")) {
                url = new URL(cfgFileName);
                isCfg = url.openStream();
            } else if(cfgFileName.startsWith("jar://")) {
            	ClassLoader cl = ConfigManager.class.getClassLoader();
                isCfg = cl.getResourceAsStream(cfgFileName.substring(6));
            } else {
                isCfg = new FileInputStream(cfgFileName);
            }
            m_props.load(isCfg);
            isCfg.close();
            url = null; 
			bOk = true;
        } catch (Exception ex) {            
            System.err.println("Cannot read config file: " + 
                cfgFileName + " Reason: " + ex.toString());
        }
        // initialize
        return bOk;
    }
         
    /**
     * Init method for settings the config data
     * from a any user defined source
     * @param hProps config data
     */
    public static void init(Hashtable hProps) {
    	m_props = new Properties();
      	m_props.putAll(hProps);
    }
    
    /**
     * Returns the SignatureFactory instance
     * @return SignatureFactory implementation
     */
    public SignatureFactory getSignatureFactory()
        throws DigiDocException
    {
    	SignatureFactory sigFac = null;
        try {
        	sigFac = (SignatureFactory)Class.
                    forName(getProperty("DIGIDOC_SIGN_IMPL")).newInstance();
            sigFac.init();
        } catch(DigiDocException ex) {
            throw ex;
        } catch(Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_INIT_SIG_FAC);
        }
        return sigFac;
    }
    
    /**
     * Returns the SignatureFactory instance
     * @param type type of signature factory
     * @return SignatureFactory implementation
     */
    public SignatureFactory getSignatureFactory(String type)
        throws DigiDocException
    {
    	SignatureFactory sigFac = null;
        try {
        	String strClass = getProperty("DIGIDOC_SIGN_IMPL_" + type);
        	if(strClass != null) {
        		sigFac = (SignatureFactory)Class.
                    forName(strClass).newInstance();
                if(sigFac != null)
            		sigFac.init();
        	}
        	if(sigFac == null)
        		throw new DigiDocException(DigiDocException.ERR_INIT_SIG_FAC, "No signature factory of type: " + type, null);
        } catch(DigiDocException ex) {
            throw ex;
        } catch(Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_INIT_SIG_FAC);
        }
        return sigFac;
    }

    /**
     * Returns the NotaryFactory instance
     * @return NotaryFactory implementation
     */
    public NotaryFactory getNotaryFactory()
        throws DigiDocException
    {
        try {
            if(m_notFac == null) {
                m_notFac = (NotaryFactory)Class.
                    forName(getProperty("DIGIDOC_NOTARY_IMPL")).newInstance();
                m_notFac.init();
            }
        } catch(DigiDocException ex) {
            throw ex;
        } catch(Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_NOT_FAC_INIT);
        }
        return m_notFac;
    }

    /**
     * Returns the TimestampFactory instance
     * @return TimestampFactory implementation
     */
    public TimestampFactory getTimestampFactory()
        throws DigiDocException
    {
        try {
            if(m_tsFac == null) {
            	m_tsFac = (TimestampFactory)Class.
                    forName(getProperty("DIGIDOC_TIMESTAMP_IMPL")).newInstance();
            	m_tsFac.init();
            }
        } catch(DigiDocException ex) {
            throw ex;
        } catch(Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_TIMESTAMP_FAC_INIT);
        }
        return m_tsFac;
    }

    /**
     * Returns the DigiDocFactory instance
     * @return DigiDocFactory implementation
     */
    public DigiDocFactory getDigiDocFactory()
        throws DigiDocException
    {
    	DigiDocFactory digFac = null;
        try {
            digFac = (DigiDocFactory)Class.
                    forName(getProperty("DIGIDOC_FACTORY_IMPL")).newInstance();
            digFac.init();            
        } catch(DigiDocException ex) {
            throw ex;
        } catch(Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_DIG_FAC_INIT);
        }
        return digFac;
    }
    
    /**
     * Returns the CanonicalizationFactory instance
     * @return CanonicalizationFactory implementation
     */
    public CanonicalizationFactory getCanonicalizationFactory()
        throws DigiDocException
    {
        try {
            if(m_canFac == null) {
                m_canFac = (CanonicalizationFactory)Class.
                    forName(getProperty("CANONICALIZATION_FACTORY_IMPL")).newInstance();
                m_canFac.init();
            }
        } catch(DigiDocException ex) {
            throw ex;
        } catch(Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_CAN_FAC_INIT);
        }
        return m_canFac;
    }

	/**
	 * Returns the EncryptedDataParser instance
	 * @return EncryptedDataParser implementation
	 */
	public EncryptedDataParser getEncryptedDataParser()
		throws DigiDocException
	{
		try {
			if(m_dencFac == null)
				m_dencFac = (EncryptedDataParser)Class.
					forName(getProperty("ENCRYPTED_DATA_PARSER_IMPL")).newInstance();
			m_dencFac.init();            
		} catch(DigiDocException ex) {
			throw ex;
		} catch(Exception ex) {
			DigiDocException.handleException(ex, DigiDocException.ERR_DIG_FAC_INIT);
		}
		return m_dencFac;
	}

	/**
	 * Returns the EncryptedStreamParser instance
	 * @return EncryptedStreamParser implementation
	 */
	public EncryptedStreamParser getEncryptedStreamParser()
		throws DigiDocException
	{
		try {
			if(m_dstrFac == null)
				m_dstrFac = (EncryptedStreamParser)Class.
					forName(getProperty("ENCRYPTED_STREAM_PARSER_IMPL")).newInstance();
			m_dstrFac.init();            
		} catch(DigiDocException ex) {
			throw ex;
		} catch(Exception ex) {
			DigiDocException.handleException(ex, DigiDocException.ERR_DIG_FAC_INIT);
		}
		return m_dstrFac;
	}

    /**
     * Returns the CRLFactory instance
     * @return CRLFactory implementation
     */
    public CRLFactory getCRLFactory()
        throws DigiDocException
    {
        try {
            if(m_crlFac == null) {
                m_crlFac = (CRLFactory)Class.
                    forName(getProperty("CRL_FACTORY_IMPL")).newInstance();
                m_crlFac.init();
            }
        } catch(DigiDocException ex) {
            throw ex;
        } catch(Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_INIT_CRL_FAC);
        }
        return m_crlFac;
    }
   
    /**
     * Retrieves the value for the spcified key
     * @param key property name
     */
    public String getProperty(String key) {
        return m_props.getProperty(key);        
    }
   
    /**
     * Retrieves a string value for the spcified key
     * @param key property name
     * @param def default value
     */
    public String getStringProperty(String key, String def) {
        return m_props.getProperty(key, def);        
    }
   
    /**
     * Retrieves an int value for the spcified key
     * @param key property name
     * @param def default value
     */
    public int getIntProperty(String key, int def) {
        int rc = def;
        try {
            rc = Integer.parseInt(m_props.getProperty(key));    
        } catch(NumberFormatException ex) {
            m_logger.error("Error parsing number: " + key, ex);
        }
        return rc;
    }

}