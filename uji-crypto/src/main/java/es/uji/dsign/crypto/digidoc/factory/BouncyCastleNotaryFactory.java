/*
 * BouncyCastleNotaryFactory.java
 * PROJECT: JDigiDoc
 * DESCRIPTION: Digi Doc functions for creating
 *	handling OCSP requests and responses. 
 * AUTHOR:  Sander Aiaots <saiaots@itcollege.ee>
 *  Adopted from Sanders version and converted to
 *  latest level of service by Veiko Sinivee
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

import es.uji.dsign.crypto.digidoc.factory.CRLFactory;
import es.uji.dsign.crypto.digidoc.factory.DigiDocFactory;
import es.uji.dsign.crypto.digidoc.factory.NotaryFactory;
import es.uji.dsign.crypto.digidoc.Base64Util;
import es.uji.dsign.crypto.digidoc.DigiDocException;
import es.uji.dsign.crypto.digidoc.Notary;
import es.uji.dsign.crypto.digidoc.Signature;
import es.uji.dsign.crypto.digidoc.SignedDoc;
import es.uji.dsign.crypto.digidoc.utils.ConfigManager;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateEncodingException;

import java.security.cert.X509Certificate;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.KeyStore;

import java.math.BigInteger;
import java.util.Date;
import java.util.Hashtable;
import java.net.*;
import java.io.*;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.BERConstructedOctetString;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.ocsp.CertID;
import org.bouncycastle.asn1.ocsp.ResponderID;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.PrincipalUtil;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.ocsp.CertificateID;
import org.bouncycastle.ocsp.OCSPReq;
import org.bouncycastle.ocsp.OCSPReqGenerator;
import org.bouncycastle.ocsp.OCSPResp;
import org.bouncycastle.ocsp.OCSPRespStatus;
import org.bouncycastle.ocsp.SingleResp;
import org.bouncycastle.ocsp.RevokedStatus;
import org.bouncycastle.ocsp.UnknownStatus;

// Logging classes
import org.apache.log4j.Logger;

/**
 * Implements the NotaryFactory by using
 * BouncyCastle JCE toolkit
 * @author  Sander Saiaots, Veiko Sinivee
 * @version 1.0
 */
public class BouncyCastleNotaryFactory implements NotaryFactory 
{
	/** NONCE extendion oid */
    public static final String nonceOid = "1.3.6.1.5.5.7.48.1.2";
    /** cert used to sign to all OCSP requests */
    private X509Certificate m_signCert;
    /** key used to sign all OCSP requests */
    private PrivateKey m_signKey;
    private boolean m_bSignRequests;
    private Logger m_logger = null;
    private Hashtable m_ocspCerts;
    private Hashtable m_ocspCACerts;
    private boolean m_useNonce= true;
    
    /** Creates new BouncyCastleNotaryFactory */
    public BouncyCastleNotaryFactory() {
        m_signCert = null;
        m_signKey = null;
        m_ocspCerts = new Hashtable();
        m_ocspCACerts = new Hashtable();
        m_bSignRequests = false;
        m_logger = Logger.getLogger(BouncyCastleNotaryFactory.class);

	String aux= ConfigManager.instance().getProperty("DIGIDOC_USE_NONCE");
	if (aux != null)
		m_useNonce = aux.toLowerCase().equals("true");
    }
    
    /**
     * Returns the n-th OCSP responders certificate if there are many
     * certificates registered for this responder.
     * @param responderCN responder-id's CN
     * @param idx certificate index starting with 0
     * @returns OCSP responders certificate or null if not found
     */
    public X509Certificate findNotaryCertByIndex(String responderCN, int idx)
    {
    	X509Certificate cert = null;
    	
    	if(m_logger.isInfoEnabled())
    		m_logger.info("Find responder for: " + responderCN + " index: " + idx);
    	String certKey = null;
    	if(idx == 0)
    		certKey = responderCN;
    	else
    		certKey = responderCN + "-" + idx;
    	if(m_logger.isInfoEnabled())
        	m_logger.info("Searching responder: " + certKey);
    	cert = (X509Certificate)m_ocspCerts.get(certKey);
    	if(m_logger.isInfoEnabled() && cert != null && certKey != null)
    		m_logger.info("Selecting cert " + cert.getSerialNumber().toString() +
    				" key: " + certKey + " valid until: " + cert.getNotAfter().toString());
    	return cert;
    }
    
    /**
     * Returns the OCSP responders certificate
     * @param responderCN responder-id's CN
     * @param specificCertNr specific cert number that we search.
     * If this parameter is null then the newest cert is seleced (if many exist)
     * @returns OCSP responders certificate
     */
    public X509Certificate getNotaryCert(String responderCN, String specificCertNr)
    {
    	//System.out.println("Responder: " + responderCN + " specificCertNr: " + specificCertNr);
      	X509Certificate cert1 = null, cert2 = null;
    	Date d1 = null;
    	String key = null;
    	
    	if(m_logger.isInfoEnabled())
    		m_logger.info("Find responder for: " + responderCN + " cert: " + 
    			((specificCertNr != null) ? specificCertNr : "NEWEST"));
    	int i = 0;
    	do {
    		cert2 = null;
    		String certKey = null;
    		if(i == 0)
    			certKey = responderCN;
    		else
    			certKey = responderCN + "-" + i;
    		//System.out.println("certKey: " + certKey);
    		if(m_logger.isInfoEnabled())
        		m_logger.info("Searching responder: " + certKey);
    		
    		//for (Enumeration e= m_ocspCerts.keys();e.hasMoreElements();)
    		//	System.out.println("Element key: " + e.nextElement());
    		
    		cert2 = (X509Certificate)m_ocspCerts.get(certKey);
    		if(cert2 != null) {
    			if(specificCertNr != null) { // specific cert
    				String certNr = cert2.getSerialNumber().toString();
    				if(certNr.equals(specificCertNr)) {
    					if(m_logger.isInfoEnabled())
    		        		m_logger.info("Found specific responder: " + specificCertNr);
    					return cert2;
    				}
    			} else { // just the freshest
    				Date d2 = cert2.getNotAfter();
    				if(cert1 == null || d1 == null || d1.before(d2)) {
    					d1 = d2;
    					key = certKey;
    					cert1 = cert2;
    					if(m_logger.isDebugEnabled())
    		        		m_logger.debug("Newer cert valid until: " + d2);
    				}
    			}
    		}
    		i++;
    	} while(cert2 != null || i < 2);
    	if(m_logger.isInfoEnabled() && cert1 != null && key != null)
    		m_logger.info("Selecting cert " + cert1.getSerialNumber().toString() +
    				" key: " + key + " valid until: " + cert1.getNotAfter().toString());
    	return cert1;
    }
    
    
    /**
     * Returns the OCSP responders CA certificate
     * @param responderCN responder-id's CN
     * @returns OCSP responders CA certificate
     */
    public X509Certificate getCACert(String responderCN)
    {
    	return (responderCN != null) ? (X509Certificate)m_ocspCACerts.get(responderCN) : null;
    }

	/**
     * Get confirmation from AS Sertifitseerimiskeskus
     * by creating an OCSP request and parsing the returned
     * OCSP response
     * @param nonce signature nonce
     * @param signersCert signature owners cert
     * @param notId new id for Notary object
     * @returns Notary object
     */
    public Notary getConfirmation(byte[] nonce, 
        X509Certificate signersCert, String notId) 
        throws DigiDocException
    {        
        return getConfirmation(nonce, signersCert, 
        	getCACert(SignedDoc.getCommonName(signersCert.getIssuerDN().getName())),         
        	getNotaryCert(SignedDoc.getCommonName(signersCert.getIssuerDN().getName()), null), 
        	notId);
    }
    
    /**
     * Get confirmation from AS Sertifitseerimiskeskus
     * by creating an OCSP request and parsing the returned
     * OCSP response
     * @param nonce signature nonce
     * @param signersCert signature owners cert
     * @param caCert CA cert for this signer
     * @param notaryCert notarys own cert
     * @param notId new id for Notary object
     * @returns Notary object
     */
    public Notary getConfirmation(byte[] nonce, 
        X509Certificate signersCert, X509Certificate caCert,
        X509Certificate notaryCert, String notId) // TODO: remove param notaryCert
        throws DigiDocException 
    {
        Notary not = null;
        try {        
/*        	if(m_logger.isDebugEnabled())
                m_logger.debug("getConfirmation, nonce " + Base64Util.encode(nonce, 0) +
                " cert: " + ((signersCert != null) ? signersCert.getSerialNumber().toString() : "NULL") + 
                " CA: " + ((caCert != null) ? caCert.getSerialNumber().toString() : "NULL") +
                " responder: " + ((notaryCert != null) ? notaryCert.getSerialNumber().toString() : "NULL") +
                " notId: " + notId + " signRequest: " + m_bSignRequests);
            if(m_logger.isDebugEnabled()) {
            	m_logger.debug("Check cert: " + ((signersCert != null) ? signersCert.getSubjectDN().getName() : "NULL"));            	
            	m_logger.debug("Check CA cert: " + ((caCert != null) ? caCert.getSubjectDN().getName() : "NULL"));
        	}*/
            // create the request - sign the request if necessary
        	OCSPReq req = createOCSPRequest(nonce, signersCert, caCert, m_bSignRequests);
            //debugWriteFile("req.der", req.getEncoded());
        	
        	if(m_logger.isDebugEnabled())
                m_logger.debug("REQUEST:\n" + Base64Util.encode(req.getEncoded(), 0));
            // send it

            Integer nResps=new Integer(ConfigManager.instance().
            getProperty("DIGIDOC_OCSP_RESPONDER_COUNT"));
           // System.out.println("COUNT: " + ConfigManager.instance().getProperty("DIGIDOC_OCSP_RESPONDER_COUNT"));
           // System.out.println("nResps: " + nResps );
            for (int i=1; i<=nResps;i++)
            {
            	try
            	{
            	
            		String ocspResponder=ConfigManager.instance().
            		getProperty("DIGIDOC_OCSP_RESPONDER_URL" + i);
            		
                   	OCSPResp resp = sendRequest(req,ocspResponder);
            		//debugWriteFile("resp.der", resp.getEncoded());
            		if(m_logger.isDebugEnabled())
            			m_logger.debug("RESPONSE:\n" + Base64Util.encode(resp.getEncoded(), 0));
            		// check response status
            		verifyRespStatus(resp);
            		
            		// check the result
            		not = parseAndVerifyResponse(notId, signersCert, resp, nonce);
            		
            		if(m_logger.isDebugEnabled())
            			m_logger.debug("Confirmation OK!");
            		
            		break;
            	}
            	catch(DigiDocException e)
            	{
            		//If it is the last unverifiable,
            		// Throw the exception again
            		if (i==nResps) throw e;
            	}
            	
            }
        } catch(DigiDocException ex) {
        	ex.printStackTrace();
        	throw ex;
        } catch(Exception ex) {
        	DigiDocException.handleException(ex, DigiDocException.ERR_OCSP_GET_CONF);
        	ex.printStackTrace();
        }
        return not;
    }


    
    /**
     * Get confirmation from AS Sertifitseerimiskeskus
     * by creating an OCSP request and parsing the returned
     * OCSP response
     * @param sig Signature object. 
     * @param signersCert signature owners cert
     * @param caCert CA cert for this signer
     * @returns Notary object
     */
    public Notary getConfirmation(Signature sig, 
        X509Certificate signersCert, X509Certificate caCert) 
        throws DigiDocException 
    {
    	
        Notary not = null;
        try {
        	String notId = sig.getId().replace('S', 'N');
            // calculate the nonce
            byte[] nonce = SignedDoc.digest(sig.getSignatureValue().getValue());
            X509Certificate notaryCert = null;
            if(sig.getUnsignedProperties() != null)
            	notaryCert = sig.getUnsignedProperties().getRespondersCertificate();
            // check the result
            not = getConfirmation(nonce, signersCert, caCert, notaryCert, notId);
            // add cert to signature
            if(notaryCert == null && sig != null && sig.getUnsignedProperties() != null) {
            	OCSPResp resp = new OCSPResp(sig.getUnsignedProperties().getNotary().getOcspResponseData()); 
            	if(resp != null && resp.getResponseObject() != null) {
            	String respId = responderIDtoString((BasicOCSPResp)resp.getResponseObject());
            	notaryCert = getNotaryCert(SignedDoc.getCommonName(respId), null);
            	sig.getUnsignedProperties().setRespondersCertificate(notaryCert);
            	}
            }
        } catch(DigiDocException ex) {
            throw ex;
        } catch(Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_OCSP_GET_CONF);        
        }
        return not;
    }

    /**
     * Get confirmation from AS Sertifitseerimiskeskus
     * by creating an OCSP request and parsing the returned
     * OCSP response. CA and reponders certs are read 
     * using paths in the config file or maybe from
     * a keystore etc.
     * @param sig Signature object
     * @param signersCert signature owners cert
     * @returns Notary object
     */
    public Notary getConfirmation(Signature sig, X509Certificate signersCert) 
        throws DigiDocException 
    {
    	String notId = sig.getId().replace('S', 'N');
    	byte[] nonce = SignedDoc.digest(sig.getSignatureValue().getValue());
        return getConfirmation(nonce, signersCert, 
        	getCACert(SignedDoc.getCommonName(signersCert.getIssuerDN().getName())), null,
        	//((sig.getUnsignedProperties() != null) ? sig.getUnsignedProperties().getRespondersCertificate() : null),
        	notId);
    }
    
    /*private String ocspFileName(X509Certificate cert)
    {
    	StringBuffer sb = new StringBuffer(cert.getSerialNumber().toString());
    	sb.append("_");
    	Date dtNow = new Date();
    	SimpleDateFormat df = new SimpleDateFormat("HHmmss");
    	sb.append(df.format(dtNow));    	
    	return sb.toString();	
    }*/
    
    
    
    /**
     * Verifies the certificate by creating an OCSP request
     * and sending it to SK server.
     * @param cert certificate to verify
     * @throws DigiDocException if the certificate is not valid
     */   
    public void checkCertificate(X509Certificate cert) 
        throws DigiDocException 
    {
        try {
        	String verifier = ConfigManager.instance().
                getStringProperty("DIGIDOC_CERT_VERIFIER", "OCSP");
            if(verifier != null && verifier.equals("OCSP")) {
        	// create the request
            DigiDocFactory ddocFac = ConfigManager.instance().getDigiDocFactory();
            X509Certificate caCert = ddocFac.findCAforCertificate(cert);
        	if(m_logger.isDebugEnabled()) {
        		m_logger.debug("Find CA for: " + SignedDoc.getCommonName(cert.getIssuerDN().getName()));
            	m_logger.debug("Check cert: " + cert.getSubjectDN().getName());            	
            	m_logger.debug("Check CA cert: " + caCert.getSubjectDN().getName());
        	}
        	String strTime = new java.util.Date().toString();
            byte[] nonce1 = SignedDoc.digest(strTime.getBytes());
            OCSPReq req = createOCSPRequest(nonce1, cert, caCert, m_bSignRequests);
            //debugWriteFile("req1.der", req.getEncoded());
            if(m_logger.isDebugEnabled()) {
            	m_logger.debug("Sending ocsp request: " + req.getEncoded().length + " bytes");
                m_logger.debug("REQUEST:\n" + Base64Util.encode(req.getEncoded(), 0));
            }    
            // send it
            String ocspResponder=ConfigManager.instance().
    		getProperty("DIGIDOC_OCSP_RESPONDER_URL1");
            
            OCSPResp resp = sendRequest(req,ocspResponder);
            //debugWriteFile("resp1.der", resp.getEncoded());
            if(m_logger.isDebugEnabled()) {
                m_logger.debug("Got ocsp response: " + resp.getEncoded().length + " bytes");
                m_logger.debug("RESPONSE:\n" + Base64Util.encode(resp.getEncoded(), 0));
            }
            // check response status
            verifyRespStatus(resp);
            // now read the info from the response
            BasicOCSPResp basResp = 
                (BasicOCSPResp)resp.getResponseObject();
            
 	    if ( m_useNonce ){
	      byte[] nonce2 = getNonce(basResp);
              if(!SignedDoc.compareDigests(nonce1, nonce2)) 
              	  throw new DigiDocException(DigiDocException.ERR_OCSP_UNSUCCESSFULL,
                    "Invalid nonce value! Possible replay attack!", null); 
	    }
            // verify the response
            try {
            	String respId = responderIDtoString(basResp);
            	X509Certificate notaryCert = getNotaryCert(SignedDoc.getCommonName(respId), null);
            	basResp.verify(notaryCert.getPublicKey(), "BC");
            } catch (Exception ex) {
                m_logger.error("OCSP Signature verification error!!!", ex); 
                DigiDocException.handleException(ex, DigiDocException.ERR_OCSP_VERIFY);
            } 
            // check the response about this certificate
            checkCertStatus(cert, basResp);
            } else if(verifier != null && verifier.equals("CRL")) {
            	CRLFactory crlFac = ConfigManager.instance().getCRLFactory();
            	crlFac.checkCertificate(cert, new Date());
            }
        } catch(DigiDocException ex) {
            throw ex;
        } catch(Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_OCSP_GET_CONF);        
        }
    }

    /**
     * Verifies the certificate.
     * @param cert certificate to verify
     * @param bUseOcsp flag: use OCSP to verify cert. If false then use CRL instead
     * @throws DigiDocException if the certificate is not valid
     */   
    public void checkCertificateOcspOrCrl(X509Certificate cert, boolean bUseOcsp) 
        throws DigiDocException 
    {
        try {
        	if(bUseOcsp)  {
        	// create the request
            DigiDocFactory ddocFac = ConfigManager.instance().getDigiDocFactory();
            X509Certificate caCert = ddocFac.findCAforCertificate(cert);
        	if(m_logger.isDebugEnabled()) {
        		m_logger.debug("Find CA for: " + SignedDoc.getCommonName(cert.getIssuerDN().getName()));
            	m_logger.debug("Check cert: " + cert.getSubjectDN().getName());            	
            	m_logger.debug("Check CA cert: " + caCert.getSubjectDN().getName());
        	}
        	String strTime = new java.util.Date().toString();
            byte[] nonce1 = SignedDoc.digest(strTime.getBytes());
            OCSPReq req = createOCSPRequest(nonce1, cert, caCert, m_bSignRequests);
            //debugWriteFile("req1.der", req.getEncoded());
            if(m_logger.isDebugEnabled()) {
            	m_logger.debug("Sending ocsp request: " + req.getEncoded().length + " bytes");
                m_logger.debug("REQUEST:\n" + Base64Util.encode(req.getEncoded(), 0));
            }    
            
            // send it
            String ocspResponder=ConfigManager.instance().
    		getProperty("DIGIDOC_OCSP_RESPONDER_URL1");
            OCSPResp resp = sendRequest(req,ocspResponder);
            
            //debugWriteFile("resp1.der", resp.getEncoded());
            if(m_logger.isDebugEnabled()) {
                m_logger.debug("Got ocsp response: " + resp.getEncoded().length + " bytes");
                m_logger.debug("RESPONSE:\n" + Base64Util.encode(resp.getEncoded(), 0));
            }
            // check response status
            verifyRespStatus(resp);
            // now read the info from the response
            BasicOCSPResp basResp = 
                (BasicOCSPResp)resp.getResponseObject();
            if ( m_useNonce ){
	      byte[] nonce2 = getNonce(basResp);
              if(!SignedDoc.compareDigests(nonce1, nonce2)) 
            	throw new DigiDocException(DigiDocException.ERR_OCSP_UNSUCCESSFULL,
                    "Invalid nonce value! Possible replay attack!", null); 
            }
            // verify the response
            try {
            	String respId = responderIDtoString(basResp);
            	X509Certificate notaryCert = getNotaryCert(SignedDoc.getCommonName(respId), null);
            	basResp.verify(notaryCert.getPublicKey(), "BC");
            } catch (Exception ex) {
                m_logger.error("OCSP Signature verification error!!!", ex); 
                DigiDocException.handleException(ex, DigiDocException.ERR_OCSP_VERIFY);
            } 
            // check the response about this certificate
            checkCertStatus(cert, basResp);
            } else  {
            	CRLFactory crlFac = ConfigManager.instance().getCRLFactory();
            	crlFac.checkCertificate(cert, new Date());
            }
        } catch(DigiDocException ex) {
            throw ex;
        } catch(Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_OCSP_GET_CONF);        
        }
    }    
    
    /**
     * Check the response and parse it's data.
     * @param sig Signature object
     * @param resp OCSP response
     * @param nonce1 nonve value used for request
     * @param notaryCert notarys own cert
     * @returns Notary object
     */
    private Notary parseAndVerifyResponse(Signature sig, OCSPResp resp, 
        byte[] nonce1/*, X509Certificate notaryCert*/)
        throws DigiDocException
    {
    	String notId = sig.getId().replace('S', 'N');
    	X509Certificate sigCert = sig.getKeyInfo().getSignersCertificate();
    	return parseAndVerifyResponse(notId, sigCert, resp, nonce1);
    }
    

    /**
     * Check the response and parse it's data
     * @param notId new id for Notary object
     * @param signersCert signature owners certificate
     * @param resp OCSP response
     * @param nonce1 nonve value used for request
     * @returns Notary object
     */
    private Notary parseAndVerifyResponse(String notId, 
    	X509Certificate signersCert, OCSPResp resp, byte[] nonce1)
        throws DigiDocException
    {
        Notary not = null;
        X509Certificate notaryCert = null;
        
        // check the result
        if(resp == null || resp.getStatus() != OCSPRespStatus.SUCCESSFUL)
            throw new DigiDocException(DigiDocException.ERR_OCSP_UNSUCCESSFULL,
                "OCSP response unsuccessfull!", null);
        try {            
            // now read the info from the response
            BasicOCSPResp basResp = 
                (BasicOCSPResp)resp.getResponseObject();
            // find real notary cert suitable for this response
            int nNotIdx = 0;
            String respondIDstr = responderIDtoString(basResp); 
            String notIdCN = SignedDoc.getCommonName(respondIDstr);
            Exception exVerify = null;
            boolean bOk = false;
            do {
            	exVerify = null;
            	if(m_logger.isInfoEnabled())
            		m_logger.info("Find notary cert for: " + notIdCN + " index: " + nNotIdx);
            	notaryCert = findNotaryCertByIndex(notIdCN, nNotIdx);
				if(notaryCert != null) {
					try {
						bOk = basResp.verify(notaryCert.getPublicKey(), "BC"); 
						if(m_logger.isInfoEnabled())
	                		m_logger.info("Verification with cert: " + notaryCert.getSerialNumber().toString() + " idx: " + nNotIdx + " RC: " + bOk);
	            	} catch (Exception ex) {
	            		exVerify = ex; 
	            		if(m_logger.isInfoEnabled())
	                		m_logger.info("Notary cert index: " + nNotIdx + " is not usable for this response!");
	            	} 
				}
            	nNotIdx++;
            } while(notaryCert != null && (exVerify != null || !bOk));
            // if no suitable found the report error
            if(exVerify != null) {
            	m_logger.error("OCSP verification error!!!", exVerify); 
        		DigiDocException.handleException(exVerify, DigiDocException.ERR_OCSP_VERIFY);
            }
            if(m_logger.isInfoEnabled() && notaryCert != null)
        		m_logger.info("Using responder cert: " + notaryCert.getSerialNumber().toString());
            // done't care about SingleResponses because we have
            // only one response and the whole response was successfull
            // but we should verify that the nonce hasn't changed
            if ( m_useNonce ){
	      byte[] nonce2 = getNonce(basResp);
              boolean ok = true;
              if(nonce1.length != nonce2.length)
                  ok = false;
              for(int i = 0; i < nonce1.length; i++)
                  if(nonce1[i] != nonce2[i])
                      ok = false;
              if(!ok /*&& !sig.getSignedDoc().getVersion().equals(SignedDoc.VERSION_1_4)*/) {
                          throw new DigiDocException(DigiDocException.ERR_OCSP_NONCE,
                    "OCSP response's nonce doesn't match the requests nonce!", null);
              }
	    }  
            // check the response on our cert
            checkCertStatus(signersCert, basResp);
            // create notary            
            not = new Notary(notId, resp.getEncoded(), respondIDstr, 
            	basResp.getResponseData().getProducedAt()); 
            if(notaryCert != null)
            	not.setCertNr(notaryCert.getSerialNumber().toString());
        } catch(DigiDocException ex) {
            throw ex;
        } catch(Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_OCSP_PARSE);
        }
        return not;
    }


    /**
     * Verifies that the OCSP response is about our signers
     * cert and the response status is successfull
     * @param sig Signature object
     * @param basResp OCSP Basic response
     * @throws DigiDocException if the response is not successfull
     */
    private void checkCertStatus(Signature sig, BasicOCSPResp basResp)
        throws DigiDocException
    {
        checkCertStatus(sig.getKeyInfo().getSignersCertificate(), basResp);
    }
    
    
    /**
     * Verifies that the OCSP response is about our signers
     * cert and the response status is successfull
     * @param sig Signature object
     * @param basResp OCSP Basic response
     * @throws DigiDocException if the response is not successfull
     */
    private void checkCertStatus(X509Certificate cert, BasicOCSPResp basResp)
        throws DigiDocException
    {
        try {
        	if(m_logger.isDebugEnabled())
            	m_logger.debug("Checking response status, CERT: " + cert.getSubjectDN().getName() + 
            		" SEARCH: " + SignedDoc.getCommonName(cert.getIssuerDN().getName()));
            // check the response on our cert
            DigiDocFactory ddocFac = ConfigManager.instance().getDigiDocFactory();
        	X509Certificate caCert = ddocFac.findCAforCertificate(cert);
            //X509Certificate caCert = (X509Certificate)m_ocspCACerts.
            //	get(SignedDoc.getCommonName(cert.getIssuerDN().getName()));
            if(m_logger.isDebugEnabled()) {
            	m_logger.debug("CA cert: " + ((caCert == null) ? "NULL" : "OK"));
            	m_logger.debug("RESP: " + basResp);
            	m_logger.debug("CERT: " + cert.getSubjectDN().getName() + 
            				" ISSUER: " + cert.getIssuerDN().getName());
            	m_logger.debug("CA CERT: " + caCert.getSubjectDN().getName());
            }
            SingleResp[] sresp = basResp.getResponseData().getResponses();
            CertificateID rc = creatCertReq(cert, caCert);
            //ertificateID certId = creatCertReq(signersCert, caCert);
            if(m_logger.isDebugEnabled())
                m_logger.debug("Search alg: " + rc.getHashAlgOID() + 
            	" serial: " + rc.getSerialNumber() + " issuer: " + Base64Util.encode(rc.getIssuerKeyHash()) +
            	" subject: " + Base64Util.encode(rc.getIssuerNameHash()));
            boolean ok = false;
            for(int i=0;i < sresp.length;i++) {
            	CertificateID id = sresp[i].getCertID();
            	if(id != null) {
            		if(m_logger.isDebugEnabled())
                		m_logger.debug("Got alg: " + id.getHashAlgOID() + 
            			" serial: " + id.getSerialNumber() + 
            			" issuer: " + Base64Util.encode(id.getIssuerKeyHash()) +
            			" subject: " + Base64Util.encode(id.getIssuerNameHash()));
            		if(rc.getHashAlgOID().equals(id.getHashAlgOID()) &&
            			rc.getSerialNumber().equals(id.getSerialNumber()) &&
            			SignedDoc.compareDigests(rc.getIssuerKeyHash(), id.getIssuerKeyHash()) &&
            			SignedDoc.compareDigests(rc.getIssuerNameHash(), id.getIssuerNameHash())) {
            			if(m_logger.isDebugEnabled())
                			m_logger.debug("Found it!");
            			ok = true;
            			Object status = sresp[i].getCertStatus();
            			if(status != null) {
            				if(m_logger.isDebugEnabled())
                				m_logger.debug("CertStatus: " + status.getClass().getName());
            			   	if(status instanceof RevokedStatus) {
            			   		m_logger.error("Certificate has been revoked!");
            					throw new DigiDocException(DigiDocException.ERR_OCSP_RESP_STATUS,
                    				"Certificate has been revoked!", null);
            			   	}
            			   	if(status instanceof UnknownStatus) {
            			   		m_logger.error("Certificate status is unknown!");
            					throw new DigiDocException(DigiDocException.ERR_OCSP_RESP_STATUS,
                    				"Certificate status is unknown!", null);
            			   	}
            			   	   	
            			}
            			break;
            		}
            	}
            }

            if(!ok) {
            	if(m_logger.isDebugEnabled())
                	m_logger.debug("Error checkCertStatus - not found ");
                throw new DigiDocException(DigiDocException.ERR_OCSP_RESP_STATUS,
                    "Bad OCSP response status!", null);
            }
            //System.out.println("Response status OK!");
        } catch(DigiDocException ex) {
        	throw ex;
        } catch(Exception ex) {
        	//System.out.println("Error checkCertStatus: " + ex);
            throw new DigiDocException(DigiDocException.ERR_OCSP_RESP_STATUS,
                    "Error checking OCSP response status!", null);
        }
    }
    
	/*   System.out.println("Writing debug file: " + str);
            FileOutputStream fos = new FileOutputStream(str);
            fos.write(data);
            fos.close();
        } catch(Exception ex) {
            System.out.println("Error: " + ex);
            ex.printStackTrace(System.out);
        }
    }*/
    
    /**
     * Check the response and parse it's data
     * Used by UnsignedProperties.verify()
     * @param not initial Notary object that contains only the
     * raw bytes of an OCSP response
     * @returns Notary object with data parsed from OCSP response
     */
    public Notary parseAndVerifyResponse(Signature sig, Notary not)
        throws DigiDocException
    {
        try {     
        	// DEBUG
        	//debugWriteFile("respin.resp", not.getOcspResponseData());
            OCSPResp  resp = new OCSPResp(not.getOcspResponseData());
            // now read the info from the response
            BasicOCSPResp basResp = (BasicOCSPResp)resp.getResponseObject();
            // verify the response
            try {
            	//X509Certificate notaryCert = sig.getUnsignedProperties().getRespondersCertificate();
            	String respondIDstr = responderIDtoString(basResp);
               	String ddocRespCertNr = sig.getUnsignedProperties().
					getRespondersCertificate().getSerialNumber().toString();
            	X509Certificate notaryCert = getNotaryCert(SignedDoc.
            			getCommonName(respondIDstr), ddocRespCertNr);
            	if(notaryCert == null)
            		throw new DigiDocException(DigiDocException.ERR_OCSP_RECPONDER_NOT_TRUSTED, 
            				"No certificate for responder: \'" + respondIDstr + "\' found in local certificate store!", null);
            	if(m_logger.isDebugEnabled())
                	m_logger.debug("Verify using responders cert: " +
                		((notaryCert != null) ? "OK" : "NULL"));
            	//X509Certificate notaryCert = getNotaryCert(SignedDoc.getCommonName(respondIDstr));
                basResp.verify(notaryCert.getPublicKey(), "BC"); 
                
            } catch (Exception ex) {
                m_logger.error("Signature verification error: " + ex); 
                DigiDocException.handleException(ex, DigiDocException.ERR_OCSP_VERIFY);
            } 
            // done't care about SingleResponses because we have
            // only one response and the whole response was successfull
            // but we should verify that the nonce hasn't changed
            // calculate the nonce
            byte[] nonce1 = SignedDoc.digest(sig.getSignatureValue().getValue());
            if ( m_useNonce ){ 
		byte[] nonce2 = getNonce(basResp);
            	boolean ok = true;
            	if(nonce1.length != nonce2.length)
                	ok = false;
            	for(int i = 0; i < nonce1.length; i++)
                	if(nonce1[i] != nonce2[i])
                    		ok = false;
            		if(!ok && !sig.getSignedDoc().getVersion().equals(SignedDoc.VERSION_1_4)) {
            		  //System.out.println("Real nonce:\n" + Base64Util.encode(nonce2, 0));
            		  //System.out.println("My nonce:\n" + Base64Util.encode(nonce1, 0));
                	  throw new DigiDocException(DigiDocException.ERR_OCSP_NONCE,
                    	  "OCSP response's nonce doesn't match the requests nonce!", null);
            		}
	    }
            // check the response on our cert
            checkCertStatus(sig, basResp);
            not.setProducedAt(basResp.getResponseData().getProducedAt());
            not.setResponderId(responderIDtoString(basResp));
        } catch(DigiDocException ex) {
            throw ex;
        } catch(Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_OCSP_PARSE);
        }
        return not;
    }
    
    
    /**
	 * Get String represetation of ResponderID
	 * @param basResp
	 * @return stringified responder ID
	 */
	private String responderIDtoString(BasicOCSPResp basResp) {
		if(basResp != null) {
			ResponderID respid = basResp.getResponseData().getResponderId().toASN1Object();
			Object o = ((DERTaggedObject)respid.toASN1Object()).getObject();
			X509Name name = new X509Name((ASN1Sequence)o);
			return "byName: " + name.toString();
		}
		else
			return null;
	}
	
	/**
	 * Method to get NONCE array from responce
	 * @param basResp
	 * @return OCSP nonce value
	 */
	private byte[] getNonce(BasicOCSPResp basResp) {
		if(basResp != null) {
			X509Extensions ext = basResp.getResponseData().getResponseExtensions();
			X509Extension ex1 = ext.getExtension(new DERObjectIdentifier(nonceOid));
			byte[] nonce2 = ex1.getValue().getOctets();
		
			return nonce2;
		}
		else
			return null;
	}

	/**
	 * Helper method to verify response status
	 * @param resp OCSP response
	 * @throws DigiDocException if the response status is not ok
	 */
	private void verifyRespStatus(OCSPResp resp) 
		throws DigiDocException 
	{
		int status = resp.getStatus();
			switch (status) {
				case OCSPRespStatus.INTERNAL_ERROR: m_logger.error("An internal error occured in the OCSP Server!"); break;
				case OCSPRespStatus.MALFORMED_REQUEST: m_logger.error("Your request did not fit the RFC 2560 syntax!"); break;
				case OCSPRespStatus.SIGREQUIRED: m_logger.error("Your request was not signed!"); break;
				case OCSPRespStatus.TRY_LATER: m_logger.error("The server was too busy to answer you!"); break;
				case OCSPRespStatus.UNAUTHORIZED: m_logger.error("The server could not authenticate you!"); break;
				case OCSPRespStatus.SUCCESSFUL: break;
				default: m_logger.error("Unknown OCSPResponse status code! "+status);
			}
		if(resp == null || resp.getStatus() != OCSPRespStatus.SUCCESSFUL)
		    throw new DigiDocException(DigiDocException.ERR_OCSP_UNSUCCESSFULL,
		        "OCSP response unsuccessfull! ", null);
	}

    
    /**
	 * Method for creating CertificateID for OCSP request
	 * @param signersCert
	 * @param caCert
	 * @param provider
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws CertificateEncodingException
	 */
	private CertificateID creatCertReq(X509Certificate signersCert, X509Certificate caCert)
		throws NoSuchAlgorithmException, NoSuchProviderException, 
		CertificateEncodingException, DigiDocException
	{
		
		MessageDigest digest = MessageDigest.getInstance("1.3.14.3.2.26", "BC");
		if(m_logger.isDebugEnabled())
        	m_logger.debug("CA cert: " + ((caCert != null) ? caCert.toString() : "NULL"));
		
		if (caCert==null)
			throw new DigiDocException(DigiDocException.ERR_OCSP_ISSUER_CA_NOT_FOUND, "Issuer CA not Found", null);
		
		X509Principal issuerName = PrincipalUtil.getSubjectX509Principal(caCert);
		if(m_logger.isDebugEnabled())
        	m_logger.debug("CA issuer: " + ((issuerName != null) ? issuerName.getName() : "NULL"));
		//Issuer name hash
		digest.update(issuerName.getEncoded());
		ASN1OctetString issuerNameHash = new BERConstructedOctetString(digest.digest());
		
		//Issuer key hash will be readed out from X509extendions
		// 4 first bytes are not useful for me, oid 2.5.29.15 contains keyid
		byte[] arr = caCert.getExtensionValue("2.5.29.14");
		if(m_logger.isDebugEnabled())
        	m_logger.debug("Issuer key hash: " + ((arr != null) ? arr.length : 0));
        if(arr == null || arr.length == 0)
        	throw new DigiDocException(DigiDocException.ERR_CA_CERT_READ, "CA certificate has no SubjectKeyIdentifier extension!", null);
		byte[] arr2 = new byte[arr.length - 4];
		System.arraycopy(arr, 4, arr2, 0, arr2.length);
		ASN1OctetString issuerKeyHash = new BERConstructedOctetString(arr2);
			
		CertID cerid = new CertID(new AlgorithmIdentifier("1.3.14.3.2.26"), 
				issuerNameHash, issuerKeyHash, new DERInteger(signersCert.getSerialNumber()));
		return new CertificateID(cerid);
	}

    
    
    /**
     * Creates a new OCSP request
     * @param nonce 128 byte RSA+SHA1 signatures digest
     * Use null if you want to verify only the certificate
     * and this is not related to any signature
     * @param signersCert signature owners cert
     * @param caCert CA cert for this signer
     * @param bSigned flag signed request or not
     */
    private OCSPReq createOCSPRequest(byte[] nonce, X509Certificate signersCert, 
    	X509Certificate caCert, boolean bSigned)
        throws DigiDocException 
    {
    	OCSPReq req = null;
        OCSPReqGenerator ocspRequest = new OCSPReqGenerator();
        try {
        	//Create certificate id, for OCSP request
        	CertificateID certId = creatCertReq(signersCert, caCert);
        	if(m_logger.isDebugEnabled())
    		m_logger.debug("Request for: " + certId.getHashAlgOID() + 
			" serial: " + certId.getSerialNumber() + 
			" issuer: " + Base64Util.encode(certId.getIssuerKeyHash()) +
			" subject: " + Base64Util.encode(certId.getIssuerNameHash()));
			ocspRequest.addRequest(certId);
			
			if(nonce!=null){
				ASN1OctetString ocset = new BERConstructedOctetString(nonce);
				X509Extension ext = new X509Extension(false, ocset);
				//nonce Identifier
				DERObjectIdentifier nonceIdf = new DERObjectIdentifier(nonceOid);
				Hashtable tbl = new Hashtable(1);
				tbl.put(nonceIdf, ext);
				// create extendions, with one extendion(NONCE)
				X509Extensions extensions = new X509Extensions(tbl);
				ocspRequest.setRequestExtensions(extensions);
			}
			//X509Name n = new X509Name()
			GeneralName name = null;
			if(bSigned) {
				if(m_logger.isDebugEnabled())
					m_logger.debug("SignCert: " + ((m_signCert != null) ? m_signCert.toString() : "NULL"));
				name = new GeneralName(PrincipalUtil.getSubjectX509Principal(m_signCert));
			} else {
				name = new GeneralName(PrincipalUtil.getSubjectX509Principal(signersCert));
				// VS: Mihhails patch for accepting Hansa's cert
				/*
				Hashtable myLookUp=new Hashtable(X509Name.DefaultLookUp);
    			DERObjectIdentifier SERIALNUMBER = new DERObjectIdentifier("2.5.4.5");
    			myLookUp.put(SERIALNUMBER, "SERIALNUMBER");
    			name = new GeneralName(new X509Name(X509Name.DefaultReverse, 
    				myLookUp,signersCert.getSubjectDN().toString()));
    				*/
			}
    
			ocspRequest.setRequestorName(name);
			
			if(bSigned) {
				// lets generate signed request
				X509Certificate[] chain = {m_signCert};
				req = ocspRequest.generate("SHA1WITHRSA", m_signKey, chain, "BC");
				if(!req.verify(m_signCert.getPublicKey(), "BC")){
					m_logger.error("Verify failed");
				}
			} else { // unsigned request
				req = ocspRequest.generate();
			}
                
        }
        catch (DigiDocException d_ex){
        	throw d_ex;
        }
        catch(Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_OCSP_REQ_CREATE);
        }
        return req;
    }

    
    /**
     * Sends the OCSP request to Notary and
     * retrieves the response
     * @param req OCSP request
     * @returns OCSP response
     */
    private OCSPResp sendRequest(OCSPReq req, String ocspResponder)
        throws DigiDocException 
    {
        OCSPResp resp = null;
        try {
            
            byte[] breq = req.getEncoded();
            //	debugWriteFile("request-bc.req", breq);
            String responderUrl = ocspResponder;/*ConfigManager.instance().
                getProperty("DIGIDOC_OCSP_RESPONDER_URL");*/
            URL url = new URL(responderUrl);
            URLConnection con = url.openConnection();
            con.setReadTimeout(10000);
            con.setConnectTimeout(10000);
            con.setAllowUserInteraction(false);
            con.setUseCaches(false);
            con.setDoOutput(true);
            con.setDoInput(true);
            // send the OCSP request
            con.setRequestProperty("Content-Type", "application/ocsp-request");
            OutputStream os = con.getOutputStream();
            os.write(breq);
            os.close();
            // read the response
            InputStream is = con.getInputStream();
            int cl = con.getContentLength();
            byte[] bresp = null;
            //System.out.println("Content: " + cl + " bytes");
            if(cl > 0) {
                int avail = 0;
                do {
                    avail = is.available();
                    byte[] data = new byte[avail];
                    int rc = is.read(data);
                    if(bresp == null) {
                        bresp = new byte[rc];
                        System.arraycopy(data, 0, bresp, 0, rc);
                    } else {
                        byte[] tmp = new byte[bresp.length + rc];
                        System.arraycopy(bresp, 0, tmp, 0, bresp.length);
                        System.arraycopy(data, 0, tmp, bresp.length, rc);
                        bresp = tmp;
                    }
                    //System.out.println("Got: " + avail + "/" + rc + " bytes!");
                    cl -= rc;
                } while(cl > 0);
            }
            is.close();
            if(bresp != null) {
            	//debugWriteFile("response-bc.resp", bresp);
                resp = new OCSPResp(bresp);     
                //System.out.println("Response: " + resp.toString());
            }
        } catch(Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_OCSP_REQ_SEND);        
        }
        return resp;
    }
    
    
    /**
     * initializes the implementation class
     */
    public void init()
        throws DigiDocException 
    {
        try {
            String proxyHost = ConfigManager.instance().
                getProperty("DIGIDOC_PROXY_HOST");
            String proxyPort = ConfigManager.instance().
                getProperty("DIGIDOC_PROXY_PORT");
            if(proxyHost != null && proxyPort != null) {
                System.setProperty("http.proxyHost", proxyHost);
                System.setProperty("http.proxyPort", proxyPort);
            }
            String sigFlag = ConfigManager.
                instance().getProperty("SIGN_OCSP_REQUESTS");
        	m_bSignRequests = (sigFlag != null && sigFlag.equals("true"));
        	// only need this if we must sign the requests
            Provider prv = (Provider)Class.forName(ConfigManager.
                instance().getProperty("DIGIDOC_SECURITY_PROVIDER")).newInstance();
            //System.out.println("Provider");
            //prv.list(System.out);
            Security.addProvider(prv);
            
            
        	if(m_bSignRequests) {
            	// load the cert & private key for OCSP signing
            	String p12file = ConfigManager.instance().
                	getProperty("DIGIDOC_PKCS12_CONTAINER");
            	String p12paswd = ConfigManager.instance().
                	getProperty("DIGIDOC_PKCS12_PASSWD");
            	// PKCS#12 container has 2 certs
            	// so use this serial to find the necessary one
            	String p12serial = ConfigManager.instance().
                	getProperty("DIGIDOC_OCSP_SIGN_CERT_SERIAL");
            	//System.out.println("Looking for cert: " + p12serial);
            
            
            	if(p12file != null && p12paswd != null) {
                	FileInputStream fi = new FileInputStream(p12file);
                	KeyStore store = KeyStore.getInstance("PKCS12", "BC");
                	store.load(fi, p12paswd.toCharArray());
                	java.util.Enumeration en = store.aliases();
                	// find the key alias
            		String      pName = null;
            		while(en.hasMoreElements()) {
                		String  n = (String)en.nextElement();
                		if (store.isKeyEntry(n)) {
                    		pName = n;
                		}
            		}
					m_signKey = (PrivateKey)store.getKey(pName, null);
					java.security.cert.Certificate[] certs = store.getCertificateChain(pName);
					for(int i = 0; (certs != null) && (i < certs.length); i++) {
						java.security.cert.X509Certificate cert = (java.security.cert.X509Certificate)certs[i];
						if(m_logger.isInfoEnabled()) {
                    		m_logger.info("Cert " + i + " subject: " + cert.getSubjectDN());
                    		m_logger.info("Cert " + i + " issuer: " + cert.getIssuerDN());                    
                    		m_logger.info("Cert " + i + " serial: " + cert.getSerialNumber());
						}
                    	if(cert.getSerialNumber().equals(new BigInteger(p12serial)))
                        	m_signCert = (X509Certificate)certs[i];
                	}                   
            	}
        	}
        	
        	// OCSP certs
            int nCerts = ConfigManager.instance().
            	getIntProperty("DIGIDOC_OCSP_COUNT", 0);
            for(int i = 1; i <= nCerts; i++) {
            	String ocspCN = ConfigManager.instance().getProperty("DIGIDOC_OCSP" + i + "_CN");
            	String ocspCertFile = ConfigManager.instance().getProperty("DIGIDOC_OCSP" + i + "_CERT");
            	String ocspCAFile = ConfigManager.instance().getProperty("DIGIDOC_OCSP" + i + "_CA_CERT");
            	String ocspCACN = ConfigManager.instance().getProperty("DIGIDOC_OCSP" + i + "_CA_CN");
            	if(m_logger.isDebugEnabled())
                    	m_logger.debug("Responder: " + ocspCN + " cert: " + 
                    	ocspCertFile + " ca-cert: " + ocspCAFile);
            	//System.out.println("OCSP CERTFILE: " + ocspCertFile);
            	if(ocspCertFile != null)
            		m_ocspCerts.put(ocspCN, SignedDoc.readCertificate(ocspCertFile));
            	m_ocspCACerts.put(ocspCACN, SignedDoc.readCertificate(ocspCAFile));
            	// read any further certs if they exist
            	int j = 1;
            	String certFile = null;
            	do {
            		certFile = ConfigManager.instance().getProperty("DIGIDOC_OCSP" + i + "_CERT_" + j);
            		if(certFile != null) {
            			if(m_logger.isDebugEnabled())
                        	m_logger.debug("Responder: " + ocspCN + " cert: " + 
                        	ocspCertFile + " ca-cert: " + ocspCAFile);
            			m_ocspCerts.put(ocspCN + "-" + j, SignedDoc.readCertificate(certFile));            			
            		}
            		j++;
            	} while(certFile != null);
            }
                     
        } 
        catch (DigiDocException d_ex){
        	if (d_ex.getCode()== DigiDocException.ERR_READ_FILE)
        		throw new DigiDocException(DigiDocException.ERR_OCSP_READ_FILE, "Reading OCSP config", d_ex);
        	else
        		throw d_ex;
        }
        catch(Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_NOT_FAC_INIT);
        }
    }
}

