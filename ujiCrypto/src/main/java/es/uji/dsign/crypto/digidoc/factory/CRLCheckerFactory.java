/*
 * CRLCheckerFactory.java
 * PROJECT: JDigiDoc
 * DESCRIPTION: Digi Doc functions for downloading
 * CRL-s from SK thorough HTTP and LDAP connection
 * and using them for checking certificates
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

import es.uji.dsign.crypto.digidoc.factory.CRLCheckerFactory;
import es.uji.dsign.crypto.digidoc.factory.CRLFactory;
import es.uji.dsign.crypto.digidoc.DigiDocException;
import es.uji.dsign.crypto.digidoc.utils.ConfigManager;

import javax.naming.Context;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.Control;
import javax.naming.NamingEnumeration;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.directory.Attributes;
import javax.naming.directory.Attribute;

import java.util.Date;
import java.util.Hashtable;
import java.util.Properties;
import java.io.File;
import java.io.ByteArrayInputStream;
import java.io.BufferedInputStream;
import java.io.InputStream;
import java.io.IOException;
import java.io.FileOutputStream;

import java.security.cert.X509Certificate;
import java.security.cert.X509CRL;
import java.security.cert.CertificateFactory;

import java.net.HttpURLConnection;
import java.net.URL;

import org.apache.log4j.Logger;


/**
 * Handles CRL download from SK server using
 * LDAP or HTTP connection and uses it for 
 * verifying certificates. HTTP connection
 * has the advatage of offering download only
 * if a new version of CRL exists.
 * @author  Veiko Sinivee
 * @version 1.0
 */
public class CRLCheckerFactory implements CRLFactory
{
	/**Connection Timeout just in case it has to download the CRL from an HTTP**/
	private static int CONN_TIMEOUT= 5000;  
	/** current/last CRL object downloaded from SK site */
    private X509CRL m_crl = null;
    /** URL timestamp to known when to get a fresh CRL (timestamp) */
  	private long m_urlLastModified = 0;
  	/** flag - use LDP connection or not */
  	private boolean m_useLdap = false;
  	/** last/fresh CRL local filename */
  	private String m_crlFile;
  	/** CRL URL */
  	private String m_crlUrl;
  	private String m_crlSearchBase;
  	private String m_crlFilter;
  	private String m_ldapDriver;
  	private String m_ldapUrl;
  	private String m_ldapAttr;
  	private String m_proxyHost;
  	private String m_proxyPort;
  	/** log4j logger */
    private Logger m_logger = null;

    /** 
     * Creates new CRLCheckerFactory 
     */
    public CRLCheckerFactory() {
    	m_logger = Logger.getLogger(CRLCheckerFactory.class);
    }
    
    /**
     * initializes the implementation class
     */
    public void init()
        throws DigiDocException 
    {
    	
    	try {
        	m_useLdap = ConfigManager.instance().getStringProperty("CRL_USE_LDAP", "false").equals("true");
      		m_crlFile = ConfigManager.instance().getProperty("CRL_FILE");
      		m_crlUrl = ConfigManager.instance().getProperty("CRL_URL");
      		m_crlSearchBase = ConfigManager.instance().getProperty("CRL_SEARCH_BASE");
      		m_crlFilter = ConfigManager.instance().getProperty("CRL_FILTER");
      		m_ldapDriver = ConfigManager.instance().getProperty("CRL_LDAP_DRIVER");
      		m_ldapUrl = ConfigManager.instance().getProperty("CRL_LDAP_URL");
      		m_ldapAttr = ConfigManager.instance().getProperty("CRL_LDAP_ATTR");
      		m_proxyHost = ConfigManager.instance().getProperty("CRL_PROXY_HOST");
      		m_proxyPort = ConfigManager.instance().getProperty("CRL_PROXY_PORT");
        } catch(Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_INIT_CRL_FAC);
        }
    }

	/**
    * Checks the cert
    * @return void
    * @param cert cert to be verified
    * @param checkDate java.util.Date
    * @throws DigiDocException for all errors
    */
  	public void checkCertificate(X509Certificate cert, Date checkDate) 
        throws DigiDocException
    {
        if(m_logger.isInfoEnabled())
       		m_logger.info("Checking cert");
       	if (getCRL().isRevoked(cert)) {
      		System.out.println("Cert revoked!");
      		throw new DigiDocException(DigiDocException.ERR_CERT_REVOKED, "Certificate has been revoked!", null);
    	} else {
    		if(m_logger.isInfoEnabled())
       			m_logger.info("Cert OK!");
       	}
    }
    
    

   /**
    * Checks if the certificate was valid on a given date
    * @return void
    * @param b64cert Certificate in base64 form
    * @param checkDate java.util.Date
    */
  /*public void checkCertificateBase64(String b64cert, Date checkDate) throws SignatureException {
    X509Certificate cert = null;
    try {
      byte[] cdata = Base64Util.decode(b64cert);
      ByteArrayInputStream inStream = new ByteArrayInputStream(cdata);
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      cert = (X509Certificate)cf.generateCertificate(inStream);
      inStream.close();
    } catch(Exception ex) {
      SignatureException.handleException(ex, SignatureException.ERR_CERT_UNREADABLE);
    }
    checkCertificate(cert, checkDate);
  }*/



  	private X509CRL getCRL() 
  		throws DigiDocException 
  	{
        if(m_useLdap) {
            if(m_logger.isInfoEnabled())
       			m_logger.info("Get CRL from LDAP");
            try {
                SearchControls constraints = new SearchControls();
                constraints.setSearchScope(SearchControls.OBJECT_SCOPE);
                Hashtable env = new Hashtable();
                env.put(Context.INITIAL_CONTEXT_FACTORY, m_ldapDriver);
                env.put(Context.PROVIDER_URL, m_ldapUrl);
                InitialLdapContext ctx = new InitialLdapContext(env, new Control[0]);
                NamingEnumeration ne = ctx.search(m_crlSearchBase, m_crlFilter, constraints);
                if (ne.hasMore()) {
                    SearchResult sr = (SearchResult) ne.next();
                    Attributes attrs = sr.getAttributes();
                    Attribute subatt = attrs.get(m_ldapAttr);
                    byte[] byteCrl = (byte[]) subatt.get();
                    ByteArrayInputStream bais = new ByteArrayInputStream(byteCrl);
                    m_crl = (X509CRL)CertificateFactory.getInstance("X.509").generateCRL(bais);
                }
            } catch (Exception ex) {
                DigiDocException.handleException(ex, DigiDocException.ERR_INIT_CRL);
            }
        } else {
            if(m_logger.isInfoEnabled())
       			m_logger.info("Get CRL from HTTP");
            BufferedInputStream bis = null;
            try {
                if(m_proxyHost != null && m_proxyPort != null) {
                    Properties sysProps = System.getProperties();
                    sysProps.put( "proxySet", "true" );
                    sysProps.put( "proxyHost", m_proxyHost);
                    sysProps.put( "proxyPort", m_proxyPort);
                }
                HttpURLConnection conn =
                (HttpURLConnection) new URL(m_crlUrl).openConnection();
                conn.setDoInput(true);
                conn.setConnectTimeout(CONN_TIMEOUT);
                long lastmodif = conn.getLastModified();
                //System.out.println("URL time: " + lastmodif + " cache time: " + m_urlLastModified);
                if (m_urlLastModified == 0 || lastmodif >= m_urlLastModified) {
                    InputStream is = conn.getInputStream();
                    bis = new BufferedInputStream(is);
                    m_crl = (X509CRL)CertificateFactory.getInstance("X.509").generateCRL(bis);
                    m_urlLastModified = lastmodif;
                    if(m_logger.isInfoEnabled())
       					m_logger.info("Got CRL -> save");
                    //System.out.println("M_CRL vale: "  + m_crl);
                    saveCRL(m_crl);
                }
                
            } catch (Exception ex) {
                DigiDocException.handleException(ex, DigiDocException.ERR_INIT_CRL);
            } finally {
                try {
                    if (bis != null) bis.close();
                } catch (IOException e) {}
            }
        }
        return m_crl;
  }

  private void saveCRL(X509CRL crl) 
  	throws DigiDocException
  {
        try {
        	if (m_crlFile!=null){
        		if(m_logger.isInfoEnabled())
        			m_logger.info("Writing CRL to: " + m_crlFile);
        		File f = new File(m_crlFile);
        		FileOutputStream fos = new FileOutputStream(f);
        		fos.write(crl.getEncoded());
        		fos.close();
        		if(m_logger.isInfoEnabled())
        			m_logger.info("CRL file saved!");
        	}
        	else{
        		if(m_logger.isInfoEnabled())
        			m_logger.info("Not saving CRL, filename not specified!");
        	}
        } catch(Exception ex) {
            m_logger.error("Error writing CRL to file: " + m_crlFile);
            DigiDocException.handleException(ex, DigiDocException.ERR_SAVE_CRL);
        }
  }    
}




