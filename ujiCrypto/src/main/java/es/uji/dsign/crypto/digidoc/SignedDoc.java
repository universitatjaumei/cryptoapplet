/*
 * SignedDoc.java
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 * GNU Lesser General Public Licence is available at
 * http://www.gnu.org/copyleft/lesser.html
 *==================================================
 */

package es.uji.dsign.crypto.digidoc;
import java.io.Serializable;
import java.util.ArrayList;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.DataInputStream;
import java.io.InputStream;
//import java.io.DataOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.net.URL;
import java.security.cert.X509Certificate;
//import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
//import java.util.Date;
import javax.crypto.Cipher;

import org.apache.log4j.Logger;

import es.uji.dsign.crypto.digidoc.utils.ConfigManager;

/**
 * Represents an instance of signed doc
 * in DIGIDOC format. Contains one or more
 * DataFile -s and zero or more Signature -s.
 * @author  Veiko Sinivee
 * @version 1.0
 */
public class SignedDoc implements Serializable
{
    /** digidoc format */
    private String m_format;
    /** format version */
    private String m_version;
    /** DataFile objects */
    private ArrayList m_dataFiles;
    /** Signature objects */
    private ArrayList m_signatures;
    
    /** the only supported formats are SK-XML and DIGIDOC-XML */
    public static final String FORMAT_SK_XML = "SK-XML";
    public static final String FORMAT_DIGIDOC_XML = "DIGIDOC-XML";
    /** supported versions are 1.0 and 1.1 */
    public static final String VERSION_1_0 = "1.0";
    public static final String VERSION_1_1 = "1.1";
    public static final String VERSION_1_2 = "1.2";
    public static final String VERSION_1_3 = "1.3";
    public static final String VERSION_1_4 = "1.4";
    /** the only supported algorithm is SHA1 */
    public static final String SHA1_DIGEST_ALGORITHM = "http://www.w3.org/2000/09/xmldsig#sha1";
    /** SHA1 digest data is allways 20 bytes */
    public static final int SHA1_DIGEST_LENGTH = 20;
    /** the only supported canonicalization method is 20010315 */
    public static final String CANONICALIZATION_METHOD_20010315 = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
    /** the only supported signature method is RSA-SHA1 */
    public static final String RSA_SHA1_SIGNATURE_METHOD = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
    /** the only supported transform is digidoc detatched transform */
    public static final String DIGIDOC_DETATCHED_TRANSFORM = "http://www.sk.ee/2002/10/digidoc#detatched-document-signature";
    /** XML-DSIG namespace */
    public static String xmlns_xmldsig = "http://www.w3.org/2000/09/xmldsig#";
	/** ETSI namespace */
	public static String xmlns_etsi = "http://uri.etsi.org/01903/v1.1.1#";
	/** DigiDoc namespace */
	public static String xmlns_digidoc = "http://www.sk.ee/DigiDoc/v1.3.0#";
	/** program & library name */
	public static final String LIB_NAME = "JDigiDoc";
	/** program & library version */
	public static final String LIB_VERSION = "2.3.7";
	
	private static 	Logger log= Logger.getLogger(SignedDoc.class);
	
    
    /** 
     * Creates new SignedDoc 
     * Initializes everything to null
     */
    public SignedDoc() {
        m_format = null;
        m_version = null;
        m_dataFiles = null;
        m_signatures = null;
    }
    
    /** 
     * Creates new SignedDoc 
     * @param format file format name
     * @param version file version number
     * @throws DigiDocException for validation errors
     */
    public SignedDoc(String format, String version) 
        throws DigiDocException
    {
        setFormat(format);
        setVersion(version);
        m_dataFiles = null;
        m_signatures = null;
    }

    /**
     * Accessor for format attribute
     * @return value of format attribute
     */
    public String getFormat() {
        return m_format;
    }
    
    /**
     * Mutator for format attribute
     * @param str new value for format attribute
     * @throws DigiDocException for validation errors
     */    
    public void setFormat(String str) 
        throws DigiDocException
    {
        DigiDocException ex = validateFormat(str);
        if(ex != null)
            throw ex;
        m_format = str;
    }
    
    /**
     * Helper method to validate a format
     * @param str input data
     * @return exception or null for ok
     */
    private DigiDocException validateFormat(String str)
    {
        DigiDocException ex = null;
        if(str == null || 
          (!str.equals(FORMAT_SK_XML) && !str.equals(FORMAT_DIGIDOC_XML)) ||
          (str.equals(FORMAT_SK_XML) && m_version != null && !m_version.equals(VERSION_1_0)) ||
          (str.equals(FORMAT_DIGIDOC_XML) && m_version != null && 
            !m_version.equals(VERSION_1_1) && 
            !m_version.equals(VERSION_1_2) &&
            !m_version.equals(VERSION_1_3)))
            ex = new DigiDocException(DigiDocException.ERR_DIGIDOC_FORMAT, 
                "Currently supports only SK-XML and DIGIDOC-XML formats", null);
        return ex;
    }

    /**
     * Accessor for version attribute
     * @return value of version attribute
     */
    public String getVersion() {
        return m_version;
    }
    
    /**
     * Mutator for version attribute
     * @param str new value for version attribute
     * @throws DigiDocException for validation errors
     */    
    public void setVersion(String str) 
        throws DigiDocException
    {
        DigiDocException ex = validateVersion(str);
        if(ex != null)
            throw ex;
        m_version = str;
    }
    
    /**
     * Helper method to validate a version
     * @param str input data
     * @return exception or null for ok
     */
    private DigiDocException validateVersion(String str)
    {
        DigiDocException ex = null;
        if(str == null || 
          (!str.equals(VERSION_1_0) && !str.equals(VERSION_1_1) && 
           !str.equals(VERSION_1_2) && !str.equals(VERSION_1_3) &&
		   !str.equals(VERSION_1_4)) ||
          (str.equals(VERSION_1_0) && m_format != null && !m_format.equals(FORMAT_SK_XML)) ||
          ((str.equals(VERSION_1_1) || str.equals(VERSION_1_2) || 
          	str.equals(VERSION_1_3) || str.equals(VERSION_1_4)) 
            && m_format != null && !m_format.equals(FORMAT_DIGIDOC_XML))) 
            ex = new DigiDocException(DigiDocException.ERR_DIGIDOC_VERSION, 
                "Currently supports only versions 1.0, 1.1, 1.2, 1.3 and 1.4", null);
        return ex;
    }

    /**
     * return the count of DataFile objects
     * @return count of DataFile objects
     */
    public int countDataFiles()
    {
        return ((m_dataFiles == null) ? 0 : m_dataFiles.size());
    }
    
    /**
     * return a new available DataFile id
     * @retusn new DataFile id
     */
    public String getNewDataFileId()
    {
        int nDf = 0;
        String id = "D" + nDf;
        boolean bExists = false;
        do {
            bExists = false;
            for(int d = 0; d < countDataFiles(); d++) {
                DataFile df = getDataFile(d);
                if(df.getId().equals(id)) {
                    nDf++;
                    id = "D" + nDf;
                    bExists = true;
                    continue;
                }
            }
        } while(bExists);
        return id;
    }
    
    /**
     * Adds a new DataFile to signed doc
     * @param inputFile input file name
     * @param mime files mime type
     * @param contentType DataFile's content type
     * @return new DataFile object
     */
    public DataFile addDataFile(File inputFile, String mime, String contentType)
        throws DigiDocException
    {
        DataFile df = new DataFile(getNewDataFileId(), contentType, inputFile.getAbsolutePath(), mime, this);
        addDataFile(df); 
        return df;
    }
    
    /**
     * Writes the SignedDoc to an output file
     * and automatically calculates DataFile sizes
     * and digests
     * @param outputFile output file name
     * @throws DigiDocException for all errors
     */
    public void writeToFile(File outputFile)
        throws DigiDocException
    {
        // TODO read DataFile elements from old file
        
        try {
            //System.out.println("Write to file: " + outputFile.getAbsoluteFile());
            FileOutputStream fos = new FileOutputStream(outputFile);
            writeToStream(fos);
            fos.close();
            //System.out.println("Write complete!");
        } catch(DigiDocException ex) {
            throw ex; // already handled
        } catch(Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_READ_FILE);
        }
    }
    
    /**
     * Writes the SignedDoc to an output file
     * and automatically calculates DataFile sizes
     * and digests
     * @param outputFile output file name
     * @throws DigiDocException for all errors
     */
    public void writeToStream(OutputStream os)
        throws DigiDocException
    {
        // TODO read DataFile elements from old file
        
        try {
            os.write(xmlHeader().getBytes());
            for(int i = 0; i < countDataFiles(); i++) {
                DataFile df = getDataFile(i);
                df.writeToFile(os);
                os.write("\n".getBytes());
            }
            for(int i = 0; i < countSignatures(); i++) {
            	Signature sig = getSignature(i);
                os.write(sig.toXML());
                os.write("\n".getBytes());
            }
            os.write(xmlTrailer().getBytes());
        } catch(DigiDocException ex) {
            throw ex; // already handled
        } catch(Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_WRITE_FILE);
        }
    }
  
    /**
     * Adds a new DataFile object
     * @param attr DataFile object to add
     */
    public void addDataFile(DataFile df) 
        throws DigiDocException
    {
        if(countSignatures() > 0)
            throw new DigiDocException(DigiDocException.ERR_SIGATURES_EXIST,
                "Cannot add DataFiles when signatures exist!", null);
        if(m_dataFiles == null)
            m_dataFiles = new ArrayList();
        if(df.getId() == null)
        	df.setId(getNewDataFileId());
        m_dataFiles.add(df);        
    }
    
    /**
     * return the desired DataFile object
     * @param idx index of the DataFile object
     * @return desired DataFile object
     */
    public DataFile getDataFile(int idx) {
        return (DataFile)m_dataFiles.get(idx);
    }

    /**
     * return the latest DataFile object
     * @return desired DataFile object
     */
    public DataFile getLastDataFile() {
        return (DataFile)m_dataFiles.get(m_dataFiles.size()-1);
    }
    
    /**
     * Removes the datafile with the given index
     * @param idx index of the data file
     */
    public void removeDataFile(int idx) 
    	throws DigiDocException
    {
    	if(countSignatures() > 0)
        	throw new DigiDocException(DigiDocException.ERR_SIGATURES_EXIST,
               	"Cannot remove DataFiles when signatures exist!", null);
        m_dataFiles.remove(idx);
    }
    
    /**
     * return the count of Signature objects
     * @return count of Signature objects
     */
    public int countSignatures()
    {
        return ((m_signatures == null) ? 0 : m_signatures.size());
    }
    
    /**
     * return a new available Signature id
     * @return new Signature id
     */
    public String getNewSignatureId()
    {
        int nS = 0;
        String id = "S" + nS;
        boolean bExists = false;
        do {
            bExists = false;
            for(int i = 0; i < countSignatures(); i++) {
                Signature sig = getSignature(i);
                if(sig.getId().equals(id)) {
                    nS++;
                    id = "S" + nS;
                    bExists = true;
                    continue;
                }
            }
        } while(bExists);
        return id;
    }
    
    /**
     * Adds a new uncomplete signature to signed doc
     * @param cert signers certificate
     * @param claimedRoles signers claimed roles
     * @param adr signers address
     * @return new Signature object
     */
    public Signature prepareSignature(X509Certificate cert, 
        String[] claimedRoles, SignatureProductionPlace adr)
        throws DigiDocException
    {
        Signature sig = new Signature(this);
        sig.setId(getNewSignatureId());
        // create SignedInfo block
        SignedInfo si = new SignedInfo(sig, RSA_SHA1_SIGNATURE_METHOD, 
            CANONICALIZATION_METHOD_20010315);
        // add DataFile references
        for(int i = 0; i < countDataFiles(); i++) {
            DataFile df = getDataFile(i);
            Reference ref = new Reference(si, df);
            si.addReference(ref);
        }
        // create key info
        KeyInfo ki = new KeyInfo(cert);
        sig.setKeyInfo(ki);
        ki.setSignature(sig);
        CertValue cval = new CertValue();
        cval.setType(CertValue.CERTVAL_TYPE_SIGNER);
        cval.setCert(cert);
        sig.addCertValue(cval);
        CertID cid = new CertID(sig, cert, CertID.CERTID_TYPE_SIGNER);
        sig.addCertID(cid);
        // create signed properties
        SignedProperties sp = new SignedProperties(sig, cert, claimedRoles, adr);
        Reference ref = new Reference(si, sp);
        si.addReference(ref);
        sig.setSignedInfo(si);
        sig.setSignedProperties(sp);
        addSignature(sig);
        return sig;
    }
  
    /**
     * Adds a new Signature object
     * @param attr Signature object to add
     */
    public void addSignature(Signature sig) 
    {
        if(m_signatures == null)
            m_signatures = new ArrayList();
        m_signatures.add(sig);
    }
    
    /**
     * return the desired Signature object
     * @param idx index of the Signature object
     * @return desired Signature object
     */
    public Signature getSignature(int idx) {
        return (Signature)m_signatures.get(idx);
    }
    
    /**
     * Removes the desired Signature object
     * @param idx index of the Signature object
     */
    public void removeSignature(int idx)
    {
    	m_signatures.remove(idx);
    }
    
    /**
     * return the latest Signature object
     * @return desired Signature object
     */
    public Signature getLastSignature() {
        return (Signature)m_signatures.get(m_signatures.size()-1);
    }

	/** 
	 * Deletes last signature
	 */
	public void removeLastSiganture()
	{
		if(m_signatures.size() > 0)
			m_signatures.remove(m_signatures.size()-1);
	}
	
    /**
     * Helper method to validate the whole
     * SignedDoc object
     * @param bStrong flag that specifies if Id atribute value is to
     * be rigorously checked (according to digidoc format) or only
     * as required by XML-DSIG
     * @return a possibly empty list of DigiDocException objects
     */
    public ArrayList validate(boolean bStrong)
    {
        ArrayList errs = new ArrayList();
        DigiDocException ex = validateFormat(m_format);
        if(ex != null)
            errs.add(ex);
        ex = validateVersion(m_version);
        if(ex != null)
            errs.add(ex);
        for(int i = 0; i < countDataFiles(); i++) {
            DataFile df = getDataFile(i);
            ArrayList e = df.validate(bStrong);
            if(!e.isEmpty())
                errs.addAll(e);
        }
        for(int i = 0; i < countSignatures(); i++) {
            Signature sig = getSignature(i);
            ArrayList e = sig.validate();
            if(!e.isEmpty())
                errs.addAll(e);
        }                
        return errs;
    }

    /**
     * Helper method to verify the whole SignedDoc object. 
     * Use this method to verify all signatures
     * @param checkDate Date on which to check the signature validity
     * @param demandConfirmation true if you demand OCSP confirmation from
     * every signature
     * @return a possibly empty list of DigiDocException objects
     */
    public ArrayList verify(boolean checkDate, boolean demandConfirmation)
    {
        ArrayList errs = validate(false);
        for(int i = 0; i < countSignatures(); i++) {
            Signature sig = getSignature(i);
            ArrayList e = sig.verify(this, checkDate, demandConfirmation);
            if(!e.isEmpty())
                errs.addAll(e);
        }    
        if(countSignatures() == 0) {
        	errs.add(new DigiDocException(DigiDocException.ERR_NOT_SIGNED, "This document is not signed!", null));
        }            
        return errs;
    }
    

    /**
     * Helper method to verify the whole SignedDoc object. 
     * Use this method to verify all signatures
     * @param checkDate Date on which to check the signature validity
     * @param bUseOcsp true if you demand OCSP confirmation from
     * every signature. False if you want to check against CRL.
     * @return a possibly empty list of DigiDocException objects
     */
    public ArrayList verifyOcspOrCrl(boolean checkDate, boolean bUseOcsp)
    {
        ArrayList errs = validate(false);
        for(int i = 0; i < countSignatures(); i++) {
            Signature sig = getSignature(i);
            ArrayList e = sig.verifyOcspOrCrl(this, checkDate, bUseOcsp);
            if(!e.isEmpty())
                errs.addAll(e);
        }    
        if(countSignatures() == 0) {
        	errs.add(new DigiDocException(DigiDocException.ERR_NOT_SIGNED, "This document is not signed!", null));
        }            
        return errs;
    }

    /**
     * Helper method to create the xml header
     * @return xml header
     */
    private String xmlHeader()
    {
        StringBuffer sb = new StringBuffer("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        sb.append("<SignedDoc format=\""); 
        sb.append(m_format);
        sb.append("\" version=\"");
        sb.append(m_version);
        sb.append("\"");
        // namespace
        if(m_version.equals(VERSION_1_3)) {
        	sb.append(" xmlns=\"");
        	sb.append(xmlns_digidoc);
        	sb.append("\"");
        }
        sb.append(">\n");
        return sb.toString();
    }
    
    /**
     * Helper method to create the xml trailer
     * @return xml trailer
     */
    private String xmlTrailer()
    {
        return "\n</SignedDoc>";
    }
    
    /**
     * Converts the SignedDoc to XML form
     * @return XML representation of SignedDoc
     */
    public String toXML()
    throws DigiDocException
    {
    	//System.out.println("TO-XML:");
        StringBuffer sb = new StringBuffer(xmlHeader());
        //System.out.println("DFS: " + countDataFiles());
        for(int i = 0; i < countDataFiles(); i++) {
            DataFile df = getDataFile(i);
            String str = df.toString();
            //System.out.println("DF: " + df.getId() + " size: " + str.length());
            sb.append(str);
            sb.append("\n");
        }
        //System.out.println("SIGS: " + countSignatures());
        for(int i = 0; i < countSignatures(); i++) {
            Signature sig = getSignature(i);
            String str = sig.toString();
            //System.out.println("SIG: " + sig.getId() + " size: " + str.length());
            sb.append(str);
            sb.append("\n");
        }
        sb.append(xmlTrailer());        
        //System.out.println("Doc size: " + sb.toString().length());
        return sb.toString();
    }

    /**
     * return the stringified form of SignedDoc
     * @return SignedDoc string representation
     */
    public String toString() 
    {
        String str = null;
        try {
            str = toXML();
        } catch(Exception ex) {}
        return str;
    }   
    
    /**
     * Computes an SHA1 digest
     * @param data input data
     * @return SHA1 digest
     */
    public static byte[] digest(byte[] data)
        throws DigiDocException 
    {
        byte[] dig = null;
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-1");
            sha.update(data);
            dig = sha.digest();
        } catch(Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_CALCULATE_DIGEST);
        }
        return dig;
    }
    
    /**
     * Verifies the siganture
     * @param digest input data digest
     * @param signature signature value
     * @param cert certificate to be used on verify
     * @return true if signature verifies
     */
    public static boolean verify(byte[] digest, byte[] signature, X509Certificate cert) 
        throws DigiDocException
    {
        boolean rc = false;
        try {
        	// VS - for some reason this JDK internal method sometimes failes
        	
        	//System.out.println("Verify digest: " + bin2hex(digest) +
        	//	" signature: " + Base64Util.encode(signature, 0));
        	/*
            // check keystore...
            java.security.Signature sig = 
                java.security.Signature.getInstance("SHA1withRSA");
            sig.initVerify((java.security.interfaces.RSAPublicKey)cert.getPublicKey());
            sig.update(digest);
            rc = sig.verify(signature);
            */
            Cipher cryptoEngine = Cipher.getInstance(ConfigManager.
            	instance().getProperty("DIGIDOC_VERIFY_ALGORITHM"), "BC");
        	cryptoEngine.init(Cipher.DECRYPT_MODE, cert);
        	byte[] decryptedDigestValue = cryptoEngine.doFinal(signature);
        	byte[] cdigest = new byte[digest.length];
            System.arraycopy(decryptedDigestValue, 
              	decryptedDigestValue.length - digest.length,
              	cdigest, 0, digest.length);
        	//System.out.println("Decrypted digest: \'" + bin2hex(cdigest) + "\'");
        	// now compare the digests
            rc = compareDigests(digest, cdigest); 
                       
            //System.out.println("Result: " + rc);
            if(!rc)
            	throw new DigiDocException(DigiDocException.ERR_VERIFY, "Invalid signature value!", null);
        } catch(DigiDocException ex) {
        	throw ex; // pass it on, but check other exceptions
        } catch(Exception ex) {
        	//System.out.println("Exception: " + ex);
            DigiDocException.handleException(ex, DigiDocException.ERR_VERIFY);
        }
        return rc;
    }

    /**
     * return certificate owners first name
     * @return certificate owners first name or null
     */
    public static String getSubjectFirstName(X509Certificate cert) {
        String name = null;
        String dn = cert.getSubjectDN().getName();
        int idx1 = dn.indexOf("CN=");
        if(idx1 != -1) {
            while(idx1 < dn.length() && dn.charAt(idx1) != ',')
                idx1++;
            idx1++;
            int idx2 = idx1;
            while(idx2 < dn.length() && dn.charAt(idx2) != ',' && dn.charAt(idx2) != '/')
                idx2++;
            name = dn.substring(idx1, idx2);            
        }
        return name;
    }
    
    /**
     * return certificate owners last name
     * @return certificate owners last name or null
     */
    public static String getSubjectLastName(X509Certificate cert) {
        String name = null;
        String dn = cert.getSubjectDN().getName();
        int idx1 = dn.indexOf("CN=");
        if(idx1 != -1) {
            idx1 += 2;
            while(idx1 < dn.length() && !Character.isLetter(dn.charAt(idx1)))
                idx1++;
            int idx2 = idx1;
            while(idx2 < dn.length() && dn.charAt(idx2) != ',' && dn.charAt(idx2) != '/')
                idx2++;
            name = dn.substring(idx1, idx2);            
        }
        return name;
    }
    
    /**
     * return certificate owners personal code
     * @return certificate owners personal code or null
     */
    public static String getSubjectPersonalCode(X509Certificate cert) {
        String code = null;
        String dn = cert.getSubjectDN().getName();
        int idx1 = dn.indexOf("CN=");
        //System.out.println("DN: " + dn);
        if(idx1 != -1) {
            while(idx1 < dn.length() && !Character.isDigit(dn.charAt(idx1)))
                idx1++;
            int idx2 = idx1;
            while(idx2 < dn.length() && Character.isDigit(dn.charAt(idx2)))
                idx2++;
            code = dn.substring(idx1, idx2);            
        }
        //System.out.println("Code: " + code);
        return code;
    }
        
    /**
     * return CN part of DN
     * @return CN part of DN or null
     */
    public static String getCommonName(String dn) {
        String name = null;
        if(dn != null) {
        	int idx1 = dn.indexOf("CN=");
        	if(idx1 != -1) {
            	idx1 += 2;
            	while(idx1 < dn.length() && 
            		!Character.isLetter(dn.charAt(idx1)))
                	idx1++;
            	int idx2 = idx1;
            	while(idx2 < dn.length() && 
            		dn.charAt(idx2) != ',' && 
            		dn.charAt(idx2) != '/')
                	idx2++;
            	name = dn.substring(idx1, idx2);            
        	}
        }
        return name;
    }
    
    /**
     * Reads X509 certificate from a data stream
     * @param data input data in Base64 form
     * @return X509Certificate object
     * @throws EFormException for all errors
     */
    public static X509Certificate readCertificate(byte[] data)
        throws DigiDocException 
    {
        X509Certificate cert = null;
        try {
        //ByteArrayInputStream certStream = new ByteArrayInputStream(Base64Util.decode(data));
        ByteArrayInputStream certStream = new ByteArrayInputStream(data);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        cert = (X509Certificate)cf.generateCertificate(certStream);
        certStream.close();
        } catch(Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_READ_CERT);
        }
        return cert;        
    }    

    /**
     * Reads in data file
     * @param inFile input file
     */
    public static byte[] readFile(File inFile)
        throws IOException, FileNotFoundException
    {
        byte[] data = null;
        FileInputStream is = new FileInputStream(inFile);
        DataInputStream dis = new DataInputStream(is);
        data = new byte[dis.available()];
        dis.readFully(data);
        dis.close();
        is.close();
        return data;
    }

    /**
     * Reads the cert from a file
     * @param certFile certificates file name
     * @return certificate object
     */
    public static X509Certificate readCertificate(File certFile)
        throws DigiDocException
    {
        X509Certificate cert = null;
        try {
        	FileInputStream fis = new FileInputStream(certFile);
        	CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
      		cert = (X509Certificate)certificateFactory.generateCertificate(fis);
      		fis.close();
        	//byte[] data = readFile(certFile);
            //cert = readCertificate(data);
        } catch(Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_READ_FILE);
        }
        return cert;
    }
    
    /**
     * Reads the cert from a file, URL or from another
     * location somewhere in the CLASSPATH such as
     * in the librarys jar file.
     * @param certLocation certificates file name,
     * or URL. You can use url in form jar://<location> to read
     * a certificate from the car file or some other location in the
     * CLASSPATH
     * @return certificate object
     */
    public static X509Certificate readCertificate(String certLocation)
        throws DigiDocException
    {
        X509Certificate cert = null;
        try {
        	InputStream isCert = null;
            URL url = null;
            if(certLocation.startsWith("http")) {
                url = new URL(certLocation);
                isCert = url.openStream();
            } else if(certLocation.startsWith("jar://")) {
              ClassLoader cl = ConfigManager.instance().getClass().getClassLoader();
              isCert = cl.getResourceAsStream(certLocation.substring(6));
            } else {
            	isCert = new FileInputStream(certLocation);
            }
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
      		cert = (X509Certificate)certificateFactory.generateCertificate(isCert);
      		isCert.close();
        } catch(Exception ex) {
        	log.info("ERROR: Ca Certificate " + certLocation + " Not Found");
            DigiDocException.handleException(ex, DigiDocException.ERR_READ_FILE);
        }
        return cert;
    }
    
    /**
     * Helper method for comparing
     * digest values
     * @param dig1 first digest value
     * @param dig2 second digest value
     * @return true if they are equal
     */
    public static boolean compareDigests(byte[] dig1, byte[] dig2)
    {
        boolean ok = (dig1 != null) && (dig2 != null) && 
            (dig1.length == dig2.length);
        for(int i = 0; ok && (i < dig1.length); i++)
            if(dig1[i] != dig2[i])
                ok = false;
        return ok;
    }
    
    /** 
     * Converts a hex string to byte array
     * @param hexString input data
     * @return byte array
     */
    public static byte[] hex2bin(String hexString)
    {
    	//System.out.println("hex2bin: " + hexString);
    	ByteArrayOutputStream bos = new ByteArrayOutputStream();
    	try {
    		for(int i = 0; (hexString != null) && 
    			(i < hexString.length()); i += 2) {
				String tmp = hexString.substring(i, i+2);  
				//System.out.println("tmp: " + tmp);  		
    			Integer x = new Integer(Integer.parseInt(tmp, 16));
    			//System.out.println("x: " + x);
    			bos.write(x.byteValue());    			
    		}
    	} catch(Exception ex) {
    		System.err.println("Error converting hex string: " + ex);
    	}
    	return bos.toByteArray();
    }
    
    /**
     * Converts a byte array to hex string
     * @param arr byte array input data
     * @return hex string
     */
    public static String bin2hex(byte[] arr)
    {
    	StringBuffer sb = new StringBuffer();
    	for(int i = 0; i < arr.length; i++) {
    		String str = Integer.toHexString((int)arr[i]);
    		if(str.length() == 2)
    			sb.append(str);
    		if(str.length() < 2) {
    			sb.append("0");
    			sb.append(str);
    		}
    		if(str.length() > 2)
    			sb.append(str.substring(str.length()-2));
    	}
    	return sb.toString();
    }
}
