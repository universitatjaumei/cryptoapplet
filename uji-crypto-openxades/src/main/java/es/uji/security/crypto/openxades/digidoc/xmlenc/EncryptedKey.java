/*
 * EncryptedKey.java
 * PROJECT: JDigiDoc
 * DESCRIPTION: some property of an encrypted data object 
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
package es.uji.security.crypto.openxades.digidoc.xmlenc;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;

import javax.crypto.Cipher;

import org.apache.log4j.Logger;

import es.uji.security.crypto.config.ConfigManager;
import es.uji.security.crypto.openxades.ConfigHandler;
import es.uji.security.crypto.openxades.digidoc.Base64Util;
import es.uji.security.crypto.openxades.digidoc.DigiDocException;
import es.uji.security.crypto.openxades.digidoc.utils.ConvertUtils;

/**
 * Contains the data of an <EncryptedKey> subelement of an <EncryptedData> object
 * 
 * @author Veiko Sinivee
 * @version 1.0
 */
@SuppressWarnings("serial")
public class EncryptedKey implements Serializable
{
    /** Id atribute value (optional) */
    private String m_id;
    /** Recipient atribute value (optional) */
    private String m_recipient;
    /** <EncryptionMethod> sublements atribute Algorithm value (required) */
    private String m_encryptionMethod;
    /** <KeyName> sublements value (optional) */
    private String m_keyName;
    /** <CarriedKeyName> sublements value (optional) */
    private String m_carriedKeyName;
    /** recipients certificate (required) */
    private X509Certificate m_recipientsCert;
    /** transport key data */
    private byte[] m_transportKeyData;
    /** log4j logger */
    private Logger m_logger = null;

    /**
     * Simplified constructor for <EncryptedKey> object that takes only the required elements and
     * sets the EncryptionMethod to it's required value.
     * 
     * @param recvCert
     *            recipients certificate (required)
     * @throws DigiDocException
     *             for all errors
     */
    public EncryptedKey(X509Certificate recvCert) throws DigiDocException
    {
        m_logger = Logger.getLogger(EncryptedKey.class);
        setId(null);
        setRecipient(null);
        setEncryptionMethod(EncryptedData.DENC_ENC_METHOD_RSA1_5);
        setKeyName(null);
        setCarriedKeyName(null);
        setRecipientsCertificate(recvCert);
        m_transportKeyData = null;
    }

    /**
     * Default constructor for <EncryptedKey> object that takes initializes everything to default
     * values.
     * 
     * @throws DigiDocException
     *             for all errors
     */
    public EncryptedKey()
    {
        m_logger = Logger.getLogger(EncryptedKey.class);
        setId(null);
        setRecipient(null);
        m_encryptionMethod = null; // invalid state!
        setKeyName(null);
        setCarriedKeyName(null);
        m_recipientsCert = null; // invalid value
        m_transportKeyData = null;
    }

    /**
     * Constructor for <EncryptedKey> object
     * 
     * @param id
     *            Id atribute value (optional)
     * @param recipient
     *            Recipient atribute value (optional)
     * @param encryptionMethod
     *            <EncryptionMethod> sublements atribute Algorithm value (required). The only
     *            currently supported value is EncryptedData.DENC_ENC_METHOD_RSA1_5 !
     * @param keyName
     *            <KeyName> sublements value (optional)
     * @param carriedKeyName
     *            <CarriedKeyName> sublements value (optional)
     * @param recvCert
     *            recipients certificate (required)
     * @throws DigiDocException
     *             for all errors
     */
    public EncryptedKey(String id, String recipient, String encryptionMethod, String keyName,
            String carriedKeyName, X509Certificate recvCert) throws DigiDocException
    {
        m_logger = Logger.getLogger(EncryptedKey.class);
        setId(id);
        setRecipient(recipient);
        setEncryptionMethod(encryptionMethod);
        setKeyName(keyName);
        setCarriedKeyName(carriedKeyName);
        setRecipientsCertificate(recvCert);
        m_transportKeyData = null;
    }

    /**
     * Returns transport key data
     * 
     * @return transport key data
     */
    public byte[] getTransportKeyData()
    {
        return m_transportKeyData;
    }

    /**
     * Sets transport key data
     * 
     * @param key
     *            new transport key data
     */
    public void setTransportKeyData(byte[] key)
    {
        m_transportKeyData = key;
    }

    /**
     * Accessor for id attribute
     * 
     * @return value of Id attribute
     */
    public String getId()
    {
        return m_id;
    }

    /**
     * Mutator for Id attribute
     * 
     * @param str
     *            new value for Id attribute
     */
    public void setId(String str)
    {
        m_id = str;
    }

    /**
     * Accessor for Recipient attribute
     * 
     * @return value of Recipient attribute
     */
    public String getRecipient()
    {
        return m_recipient;
    }

    /**
     * Mutator for Recipient attribute
     * 
     * @param str
     *            new value for Recipient attribute
     */
    public void setRecipient(String str)
    {
        m_recipient = str;
    }

    /**
     * Accessor for EncryptionMethod attribute
     * 
     * @return value of EncryptionMethod attribute
     */
    public String getEncryptionMethod()
    {
        return m_encryptionMethod;
    }

    /**
     * Mutator for EncryptionMethod attribute
     * 
     * @param str
     *            new value for EncryptionMethod attribute
     * @throws DigiDocException
     *             for validation errors
     */
    public void setEncryptionMethod(String str) throws DigiDocException
    {
        String str2 = str;
        // fix this buggy URL problem
        if (str2 != null && str2.equals(EncryptedData.DENC_ENC_METHOD_RSA1_5_BUGGY))
            str2 = EncryptedData.DENC_ENC_METHOD_RSA1_5;
        DigiDocException ex = validateEncryptionMethod(str2);
        if (ex != null)
            throw ex;
        m_encryptionMethod = str2;
    }

    /**
     * Helper method to validate EncryptionMethod atribute
     * 
     * @param str
     *            input data
     * @return exception or null for ok
     */
    private DigiDocException validateEncryptionMethod(String str)
    {
        DigiDocException ex = null;
        if (str == null || !str.equals(EncryptedData.DENC_ENC_METHOD_RSA1_5))
            ex = new DigiDocException(DigiDocException.ERR_XMLENC_ENCKEY_ENCRYPTION_METHOD,
                    "EncryptionMethod atribute is required and currently the only supported value is: "
                            + EncryptedData.DENC_ENC_METHOD_RSA1_5, null);
        return ex;
    }

    /**
     * Accessor for KeyName attribute
     * 
     * @return value of KeyName attribute
     */
    public String getKeyName()
    {
        return m_keyName;
    }

    /**
     * Mutator for KeyName attribute
     * 
     * @param str
     *            new value for KeyName attribute
     */
    public void setKeyName(String str)
    {
        m_keyName = str;
    }

    /**
     * Accessor for CarriedKeyName attribute
     * 
     * @return value of CarriedKeyName attribute
     */
    public String getCarriedKeyName()
    {
        return m_carriedKeyName;
    }

    /**
     * Mutator for CarriedKeyName attribute
     * 
     * @param str
     *            new value for CarriedKeyName attribute
     */
    public void setCarriedKeyName(String str)
    {
        m_carriedKeyName = str;
    }

    /**
     * Accessor for RecipientsCertificate attribute
     * 
     * @return value of RecipientsCertificate attribute
     */
    public X509Certificate getRecipientsCertificate()
    {
        return m_recipientsCert;
    }

    /**
     * Mutator for RecipientsCertificate attribute
     * 
     * @param cert
     *            new value for RecipientsCertificate attribute
     * @throws DigiDocException
     *             for validation errors
     */
    public void setRecipientsCertificate(X509Certificate cert) throws DigiDocException
    {
        DigiDocException ex = validateRecipientsCertificate(cert);
        if (ex != null)
            throw ex;
        m_recipientsCert = cert;
    }

    /**
     * Helper method to validate RecipientsCertificate atribute
     * 
     * @param cert
     *            input data
     * @return exception or null for ok
     */
    private DigiDocException validateRecipientsCertificate(X509Certificate cert)
    {
        DigiDocException ex = null;
        if (cert == null)
            ex = new DigiDocException(DigiDocException.ERR_XMLENC_ENCKEY_CERT,
                    "RecipientsCertificate atribute is required", null);
        return ex;
    }

    /**
     * Encrypts the transport key
     * 
     * @param encData
     *            EncryptedData object containing the transport key
     * @throws DigiDocException
     *             for encryption errors
     */
    public void encryptKey(EncryptedData encData) throws DigiDocException
    {
        // check key status first - nothing to encrypt?
        if (encData.getTransportKey() == null)
            throw new DigiDocException(DigiDocException.ERR_XMLENC_KEY_STATUS,
                    "Transport key has not been initialized!", null);
        // check recipients cert - something to encrypt with?
        if (m_recipientsCert == null)
            throw new DigiDocException(DigiDocException.ERR_XMLENC_KEY_STATUS,
                    "Recipients certificate has not been initialized!", null);
        // now try to encrypt the key and keep only the encrypted data
        try
        {
            ConfigManager conf = ConfigManager.getInstance();

            Cipher alg = Cipher.getInstance(conf.getProperty("DIGIDOC_KEY_ALOGORITHM"), conf
                    .getProperty("DIGIDOC_SECURITY_PROVIDER_NAME"));
            if (m_logger.isDebugEnabled())
                m_logger.debug("EncryptKey - algorithm: " + alg.getAlgorithm());
            // alg.init(Cipher.ENCRYPT_MODE, m_recipientsCert.getPublicKey());
            alg.init(Cipher.WRAP_MODE, m_recipientsCert.getPublicKey());
            // m_transportKeyData = alg.doFinal(m_transportKey.getEncoded());
            m_transportKeyData = alg.wrap(encData.getTransportKey());
            if (m_logger.isDebugEnabled())
                m_logger.debug("EncryptKey - data: "
                        + ((m_transportKeyData == null) ? 0 : m_transportKeyData.length));
        }
        catch (Exception ex)
        {
            DigiDocException.handleException(ex, DigiDocException.ERR_XMLENC_KEY_ENCRYPT);
        }
    }

    /**
     * Converts the KeyInfo to XML form
     * 
     * @return XML representation of KeyInfo
     */
    public byte[] toXML() throws DigiDocException
    {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try
        {
            bos.write(ConvertUtils.str2data("<EncryptedKey"));
            if (m_id != null)
                bos.write(ConvertUtils.str2data(" Id=\"" + m_id + "\""));
            if (m_recipient != null)
                bos.write(ConvertUtils.str2data(" Recipient=\"" + m_recipient + "\""));
            bos.write(ConvertUtils.str2data(">"));
            bos.write(ConvertUtils.str2data("<denc:EncryptionMethod Algorithm=\""));
            bos.write(ConvertUtils.str2data(m_encryptionMethod));
            bos.write(ConvertUtils.str2data("\"></denc:EncryptionMethod>"));
            bos.write(ConvertUtils.str2data("<ds:KeyInfo xmlns:ds=\""
                    + EncryptedData.DENC_XMLNS_XMLDSIG + "\">"));
            if (m_keyName != null)
            {
                bos.write(ConvertUtils.str2data("<ds:KeyName>"));
                bos.write(ConvertUtils.str2data(m_keyName));
                bos.write(ConvertUtils.str2data("</ds:KeyName>"));
            }
            bos.write(ConvertUtils.str2data("</ds:KeyInfo>"));
            bos.write(ConvertUtils.str2data("<ds:X509Data><ds:X509Certificate>"));
            try
            {
                bos.write(ConvertUtils.str2data(Base64Util
                        .encode(m_recipientsCert.getEncoded(), 64)));
            }
            catch (CertificateEncodingException ex)
            {
                DigiDocException.handleException(ex, DigiDocException.ERR_ENCODING);
            }
            bos.write(ConvertUtils.str2data("</ds:X509Certificate></ds:X509Data>"));
            bos.write(ConvertUtils.str2data("<denc:CipherData><denc:CipherValue>"));
            if (m_transportKeyData != null)
            {
                bos.write(ConvertUtils.str2data(Base64Util.encode(m_transportKeyData, 64)));
            }
            else
                throw new DigiDocException(DigiDocException.ERR_XMLENC_KEY_STATUS,
                        "Invalid transport key status for transport!", null);
            bos.write(ConvertUtils.str2data("</denc:CipherValue></denc:CipherData>"));
            if (m_carriedKeyName != null)
            {
                bos.write(ConvertUtils.str2data("<denc:CarriedKeyName>"));
                bos.write(ConvertUtils.str2data(m_carriedKeyName));
                bos.write(ConvertUtils.str2data("</denc:CarriedKeyName>"));
            }
            bos.write(ConvertUtils.str2data("</EncryptedKey>"));
        }
        catch (IOException ex)
        {
            DigiDocException.handleException(ex, DigiDocException.ERR_XML_CONVERT);
        }
        return bos.toByteArray();
    }

    /**
     * Helper method to validate the whole EncryptedKey object
     * 
     * @return a possibly empty list of DigiDocException objects
     */
    public ArrayList<DigiDocException> validate()
    {
        ArrayList<DigiDocException> errs = new ArrayList<DigiDocException>();        
        DigiDocException ex = validateEncryptionMethod(m_encryptionMethod);
        
        if (ex != null)
        {
            errs.add(ex);
        }
        
        ex = validateRecipientsCertificate(m_recipientsCert);
        
        if (ex != null)
        {
            errs.add(ex);
        }
        
        return errs;
    }

    /**
     * Returns the stringified form of KeyInfo
     * 
     * @return KeyInfo string representation
     */
    public String toString()
    {
        String str = null;
        try
        {
            str = new String(toXML());
        }
        catch (Exception ex)
        {
        }
        return str;
    }
}
