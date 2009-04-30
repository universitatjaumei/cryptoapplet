/*
 * EncryptedData.java
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

import java.util.ArrayList;

import org.apache.log4j.Logger; //import org.bouncycastle.util.encoders.Base64;

import es.uji.security.crypto.openxades.digidoc.Base64Util;
import es.uji.security.crypto.openxades.digidoc.DataFile;
import es.uji.security.crypto.openxades.digidoc.DigiDocException;
import es.uji.security.crypto.openxades.digidoc.Signature;
import es.uji.security.crypto.openxades.digidoc.SignedDoc;
import es.uji.security.crypto.openxades.digidoc.factory.SignatureFactory;
import es.uji.security.crypto.openxades.digidoc.utils.ConfigManager;
import es.uji.security.crypto.openxades.digidoc.utils.ConvertUtils;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;
import java.security.Provider;
import java.security.Security;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.InflaterInputStream;
import java.util.zip.Deflater;
import java.util.zip.Inflater; //import java.security.cert.X509CertSelector;
import java.io.ByteArrayOutputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Contains the data of an <EncryptedData> object
 * 
 * @author Veiko Sinivee
 * @version 1.0
 */
public class EncryptedData
{
    /** Id atribute value (optional) */
    private String m_id;
    /** Type atribute value (optional) */
    private String m_type;
    /** MimeType atribute value (optional) */
    private String m_mimeType;
    /** xmlns atribute value. Must be http://www.w3.org/2001/04/xmlenc# */
    private String m_xmlns;
    /** <EncryptionMethod> sublements atribute Algorithm value (required) */
    private String m_encryptionMethod;
    /** payload data (encrypted or not encrypted) */
    private byte[] m_data;
    /** status of data */
    private int m_nDataStatus;
    /** array of <EncryptedKey> objects */
    private ArrayList m_arrEncryptedKeys;
    /** array of <EncryptionProperty> objects */
    private EncryptionProperties m_encProperties;
    /** log4j logger */
    private Logger m_logger = null;
    /** transport key */
    private SecretKey m_transportKey;

    /** use this value for Type atribute if you encrypt a digidoc */
    public static final String DENC_ENCDATA_TYPE_DDOC = "http://www.sk.ee/DigiDoc/v1.3.0/digidoc.xsd";
    /** mime type for xml data */
    public static final String DENC_ENCDATA_MIME_XML = "text/xml";
    /** the library will set mime type to this value if it packs data */
    public static final String DENC_ENCDATA_MIME_ZLIB = "http://www.isi.edu/in-noes/iana/assignments/media-types/application/zip";
    /** the only acceptable encryption method for EncryptedData for now */
    public static final String DENC_ENC_METHOD_AES128 = "http://www.w3.org/2001/04/xmlenc#aes128-cbc";
    /** the only acceptable encryption method for EncryptedKey for now */
    public static final String DENC_ENC_METHOD_RSA1_5 = "http://www.w3.org/2001/04/xmlenc#rsa-1_5";
    /** the only acceptable encryption method for EncryptedKey for now */
    public static final String DENC_ENC_METHOD_RSA1_5_BUGGY = "http://www.w3.org/2001/04/xmlenc#rsa-1-5";
    /** the only acceptable namespace for EncryptedData for now */
    public static final String DENC_XMLNS_XMLENC = "http://www.w3.org/2001/04/xmlenc#";
    /** we don't use this */
    public static final String DENC_XMLNS_XMLENC_ELEMENT = "http://www.w3.org/2001/04/xmlenc#Element";
    /** we don't use this */
    public static final String DENC_XMLNS_XMLENC_CONTENT = "http://www.w3.org/2001/04/xmlenc#Content";
    /** we don't use this */
    public static final String DENC_XMLNS_XMLENC_ENCPROP = "http://www.w3.org/2001/04/xmlenc#EncryptionProperties";
    /** we use this for <KeyInfo> and it's sublements */
    public static final String DENC_XMLNS_XMLDSIG = "http://www.w3.org/2000/09/xmldsig#";

    /** when there is no data not encrypted, not unencrypted */
    public static final int DENC_DATA_STATUS_UNINITIALIZED = 0;
    /** unencrypted and not compressed data */
    public static final int DENC_DATA_STATUS_UNENCRYPTED_AND_NOT_COMPRESSED = 1;
    /** unencrypted and compressed data */
    public static final int DENC_DATA_STATUS_UNENCRYPTED_AND_COMPRESSED = 2;
    /** encrypted and not compressed data */
    public static final int DENC_DATA_STATUS_ENCRYPTED_AND_NOT_COMPRESSED = 3;
    /** encrypted and compressed data */
    public static final int DENC_DATA_STATUS_ENCRYPTED_AND_COMPRESSED = 4;
    /** compression option - allways compress */
    public static final int DENC_COMPRESS_ALLWAYS = 0;
    /** compression option - never compress */
    public static final int DENC_COMPRESS_NEVER = 1;
    /** compression option - compress if it reduces the size of data */
    public static final int DENC_COMPRESS_BEST_EFFORT = 2;

    /** <EnryptionProperty> Name atribute for storing original filename */
    public static final String ENCPROP_FILENAME = "Filename";
    /** <EnryptionProperty> Name atribute for storing original file size */
    public static final String ENCPROP_ORIG_SIZE = "OriginalSize";
    /** <EnryptionProperty> Name atribute for storing original mime type */
    public static final String ENCPROP_ORIG_MIME = "OriginalMimeType";
    /** <EnryptionProperty> Name atribute for storing original digidoc content info */
    public static final String ENCPROP_ORIG_FILE = "orig_file";
    /** <EnryptionProperty> Name atribute for storing library version that generated it */
    public static final String ENCPROP_LIB_VER = "LibraryVersion";
    /** <EnryptionProperty> Name atribute for storing document format and version */
    public static final String ENCPROP_FORMAT_VER = "DocumentFormat";

    /** the only supported format is ENCDOC-XML */
    public static final String FORMAT_ENCDOC_XML = "ENCDOC-XML";
    /** supported version is 1.0 */
    public static final String VERSION_1_0 = "1.0";

    /**
     * Constructor for EncryptedData
     * 
     * @param id
     *            Id atribute value (optional)
     * @param type
     *            Type atribute value (optional)
     * @param mimeType
     *            MimeType atribute value (optional)
     * @param xmlns
     *            xmlns atribute value. Must be http://www.w3.org/2001/04/xmlenc#
     * @param encryptionMethod
     *            EncryptionMethod> sublements atribute Algorithm value (required)
     * @throws DigiDocException
     *             for validation errors
     */
    public EncryptedData(String id, String type, String mimeType, String xmlns,
            String encryptionMethod) throws DigiDocException
    {
        m_logger = Logger.getLogger(EncryptedData.class);
        setId(id);
        setType(type);
        setMimeType(mimeType);
        setXmlns(xmlns);
        setEncryptionMethod(encryptionMethod);
        m_data = null;
        m_transportKey = null;
        m_nDataStatus = DENC_DATA_STATUS_UNINITIALIZED;
        m_arrEncryptedKeys = null;
        m_encProperties = null;
        // create default porperties
        setPropLibraryNameAndVersion();
        setPropFormatNameAndVersion();
    }

    /**
     * Constructor for EncryptedData without parameters This is to be used only in SAX parser
     * because it initializes instance variables to default values.
     * 
     * @param xmlns
     *            xmlns atribute value. Must be http://www.w3.org/2001/04/xmlenc#
     * @throws DigiDocException
     *             for validation errors
     */
    public EncryptedData(String xmlns) throws DigiDocException
    {
        m_logger = Logger.getLogger(EncryptedData.class);
        m_id = null;
        m_type = null;
        m_mimeType = null;
        setXmlns(xmlns);
        m_encryptionMethod = null; // invalid state!
        m_data = null;
        m_transportKey = null;
        m_nDataStatus = DENC_DATA_STATUS_UNINITIALIZED;
        m_arrEncryptedKeys = null;
        m_encProperties = null;
    }

    /**
     * Returns the data's current status
     * 
     * @return data's current status
     */
    public int getDataStatus()
    {
        return m_nDataStatus;
    }

    /**
     * sets data status
     * 
     * @param status
     *            new status for data
     */
    public void setDataStatus(int status)
    {
        m_nDataStatus = status;
    }

    /**
     * Retrieves data
     * 
     * @return data
     */
    public byte[] getData()
    {
        return m_data;
    }

    /**
     * sets data
     * 
     * @param data
     *            new data
     */
    public void setData(byte[] data)
    {
        m_data = data;
    }

    /**
     * Accessor for secret key
     * 
     * @return SecretKey object
     */
    public SecretKey getTransportKey()
    {
        return m_transportKey;
    }

    /**
     * Mutator for secret key
     * 
     * @param key
     *            new secret key
     */
    public void setTransportKey(SecretKey key)
    {
        m_transportKey = key;
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
     * Accessor for Type attribute
     * 
     * @return value of Type attribute
     */
    public String getType()
    {
        return m_type;
    }

    /**
     * Mutator for Type attribute
     * 
     * @param str
     *            new value for Type attribute
     */
    public void setType(String str)
    {
        m_type = str;
    }

    /**
     * Accessor for MimeType attribute
     * 
     * @return value of MimeType attribute
     */
    public String getMimeType()
    {
        return m_mimeType;
    }

    /**
     * Mutator for MimeType attribute
     * 
     * @param str
     *            new value for MimeType attribute
     */
    public void setMimeType(String str)
    {
        m_mimeType = str;
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
        DigiDocException ex = validateEncryptionMethod(str);
        if (ex != null)
            throw ex;
        m_encryptionMethod = str;
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
        if (str == null || !str.equals(EncryptedData.DENC_ENC_METHOD_AES128))
            ex = new DigiDocException(DigiDocException.ERR_XMLENC_ENCDATA_ENCRYPTION_METHOD,
                    "EncryptionMethod atribute is required and currently the only supported value is: "
                            + EncryptedData.DENC_ENC_METHOD_AES128, null);
        return ex;
    }

    /**
     * Accessor for Xmlns attribute
     * 
     * @return value of Xmlns attribute
     */
    public String getXmlns()
    {
        return m_xmlns;
    }

    /**
     * Mutator for Xmlns attribute
     * 
     * @param str
     *            new value for Xmlns attribute
     * @throws DigiDocException
     *             for validation errors
     */
    public void setXmlns(String str) throws DigiDocException
    {
        DigiDocException ex = validateXmlns(str);
        if (ex != null)
            throw ex;
        m_xmlns = str;
    }

    /**
     * Helper method to validate Xmlns atribute
     * 
     * @param str
     *            input data
     * @return exception or null for ok
     */
    private DigiDocException validateXmlns(String str)
    {
        DigiDocException ex = null;
        if (str == null || !str.equals(EncryptedData.DENC_XMLNS_XMLENC))
            ex = new DigiDocException(DigiDocException.ERR_XMLENC_ENCDATA_XMLNS,
                    "xmlns atribute is required and currently the only supported value is: "
                            + EncryptedData.DENC_XMLNS_XMLENC, null);
        return ex;
    }

    /**
     * Retrieves the Id atribute value on <EncryptionProperties> child element
     * 
     * @return id value of Id atribute
     */
    public String getEncryptionPropertiesId()
    {
        if (m_encProperties != null)
            return m_encProperties.getId();
        else
            return null;
    }

    /**
     * Sets the Id atribute value on <EncryptionProperties> child element
     * 
     * @param id
     *            value of Id atribute
     */
    public void setEncryptionPropertiesId(String id)
    {
        if (m_encProperties == null)
            m_encProperties = new EncryptionProperties(id);
        else
            m_encProperties.setId(id);
    }

    /**
     * Adds an <EncryptionProperty> object to the array of properties
     * 
     * @param prop
     *            new property object to be added
     */
    public void addProperty(EncryptionProperty prop)
    {
        if (m_encProperties == null)
            m_encProperties = new EncryptionProperties(null);
        m_encProperties.addProperty(prop);
    }

    /**
     * Simply adds an <EncryptionProperty> object with the given Name atribute and content to the
     * list
     * 
     * @param name
     *            <EncryptionProperty> object's Name atribute value
     * @param content
     *            <EncryptionProperty> object's content
     */
    public void addProperty(String name, String content) throws DigiDocException
    {
        if (m_encProperties == null)
            m_encProperties = new EncryptionProperties(null);
        m_encProperties.addProperty(new EncryptionProperty(name, content));
    }

    /**
     * Rturns the number of <EncryptionProperty> objects in the list
     * 
     * @return number of <EncryptionProperty> objects
     */
    public int getNumProperties()
    {
        return ((m_encProperties == null) ? 0 : m_encProperties.getNumProperties());
    }

    /**
     * Returns the n-th <EncryptionProperty> object
     * 
     * @param nIdx
     *            index of the property
     * @return the desired <EncryptionProperty> object or null
     */
    public EncryptionProperty getProperty(int nIdx)
    {
        if (nIdx < getNumProperties())
            return m_encProperties.getProperty(nIdx);
        else
            return null;
    }

    /**
     * Returns the <EncryptionProperty> object with the given Id atribute
     * 
     * @param id
     *            the desired objects Id atribute value
     * @return the desired <EncryptionProperty> object or null
     */
    public EncryptionProperty findPropertyById(String id)
    {
        if (m_encProperties != null)
            return m_encProperties.findPropertyById(id);
        else
            return null;
    }

    /**
     * Returns the <EncryptionProperty> object with the given Id atribute
     * 
     * @param name
     *            the desired objects Name atribute value
     * @return the desired <EncryptionProperty> object or null
     */
    public EncryptionProperty findPropertyByName(String name)
    {
        if (m_encProperties != null)
            return m_encProperties.findPropertyByName(name);
        else
            return null;
    }

    /**
     * Returns the last <EncryptionProperty> object
     * 
     * @return the desired <EncryptionProperty> object or null
     */
    public EncryptionProperty getLastProperty()
    {
        if (m_encProperties != null && m_encProperties.getNumProperties() > 0)
            return m_encProperties.getProperty(m_encProperties.getNumProperties() - 1);
        else
            return null;
    }

    /**
     * Returns the content of the <EncryptionProperty> object with the gine Name atribute value
     * 
     * @param name
     *            Name atribute value
     * @return content of the <EncryptionProperty> object or null
     */
    public String findPropertyContentByName(String name)
    {
        EncryptionProperty prop = findPropertyByName(name);
        if (prop != null)
            return prop.getContent();
        else
            return null;
    }

    /**
     * Creates a new <EncryptionProperty> or uses and existing one to store the library namd and
     * version used to create this encrypted document
     * 
     * @throws DigiDocException
     */
    public void setPropLibraryNameAndVersion() throws DigiDocException
    {
        EncryptionProperty prop = findPropertyByName(ENCPROP_LIB_VER);
        StringBuffer sb = new StringBuffer();
        sb.append(SignedDoc.LIB_NAME);
        sb.append("|");
        sb.append(SignedDoc.LIB_VERSION);
        if (prop == null)
        {
            prop = new EncryptionProperty(ENCPROP_LIB_VER, sb.toString());
            addProperty(prop);
        }
        else
            prop.setContent(sb.toString());
    }

    /**
     * Returns the library name that created this document. This is stored in an
     * <EncryptionProperty> element
     * 
     * @throws DigiDocException
     */
    public String getPropLibraryName()
    {
        StringBuffer sb = new StringBuffer();
        EncryptionProperty prop = findPropertyByName(ENCPROP_LIB_VER);
        if (prop != null)
        {
            String content = prop.getContent();
            int nIdx1 = 0;
            if ((content != null) && ((nIdx1 = content.indexOf("|")) != -1))
            {
                sb.append(content.substring(0, nIdx1));
            }
        }
        return sb.toString();
    }

    /**
     * Returns the library version that created this document. This is stored in an
     * <EncryptionProperty> element
     * 
     * @throws DigiDocException
     */
    public String getPropLibraryVersion()
    {
        StringBuffer sb = new StringBuffer();
        EncryptionProperty prop = findPropertyByName(ENCPROP_LIB_VER);
        if (prop != null)
        {
            String content = prop.getContent();
            int nIdx1 = 0;
            if ((content != null) && ((nIdx1 = content.indexOf("|")) != -1))
            {
                sb.append(content.substring(nIdx1 + 1));
            }
        }
        return sb.toString();
    }

    /**
     * Creates a new <EncryptionProperty> or uses and existing one to store the encrypted document
     * format name and version
     * 
     * @throws DigiDocException
     */
    public void setPropFormatNameAndVersion() throws DigiDocException
    {
        EncryptionProperty prop = findPropertyByName(ENCPROP_FORMAT_VER);
        StringBuffer sb = new StringBuffer();
        sb.append(FORMAT_ENCDOC_XML);
        sb.append("|");
        sb.append(VERSION_1_0);
        if (prop == null)
        {
            prop = new EncryptionProperty(ENCPROP_FORMAT_VER, sb.toString());
            addProperty(prop);
        }
        else
            prop.setContent(sb.toString());
    }

    /**
     * Returns the encrypted document format name. This is stored in an <EncryptionProperty> element
     * 
     * @throws DigiDocException
     */
    public String getPropFormatName()
    {
        StringBuffer sb = new StringBuffer();
        EncryptionProperty prop = findPropertyByName(ENCPROP_FORMAT_VER);
        if (prop != null)
        {
            String content = prop.getContent();
            int nIdx1 = 0;
            if ((content != null) && ((nIdx1 = content.indexOf("|")) != -1))
            {
                sb.append(content.substring(0, nIdx1));
            }
        }
        return sb.toString();
    }

    /**
     * Returns the encrypted document format version. This is stored in an <EncryptionProperty>
     * element
     * 
     * @throws DigiDocException
     */
    public String getPropFormatVersion()
    {
        StringBuffer sb = new StringBuffer();
        EncryptionProperty prop = findPropertyByName(ENCPROP_FORMAT_VER);
        if (prop != null)
        {
            String content = prop.getContent();
            int nIdx1 = 0;
            if ((content != null) && ((nIdx1 = content.indexOf("|")) != -1))
            {
                sb.append(content.substring(nIdx1 + 1));
            }
        }
        return sb.toString();
    }

    /**
     * Creates a number of <EncryptionProperty> objects to store the meta info about the contents of
     * this digidoc
     * 
     * @throws DigiDocException
     */
    public void setPropRegisterDigiDoc(SignedDoc sdoc) throws DigiDocException
    {
        for (int i = 0; i < sdoc.countDataFiles(); i++)
        {
            DataFile df = sdoc.getDataFile(i);
            StringBuffer sb = new StringBuffer();
            sb.append(df.getFileName());
            sb.append("|");
            sb.append(new Long(df.getSize()).toString());
            sb.append("|");
            sb.append(df.getMimeType());
            sb.append("|");
            sb.append(df.getId());
            addProperty(new EncryptionProperty(ENCPROP_ORIG_FILE, sb.toString()));
        }
    }

    /**
     * counts the number of <EncryptionProperty> objects used for stroring digidoc meta info
     * 
     * @return count of such <EncryptionProperty> objects
     * @throws DigiDocException
     */
    public int getPropOrigFileCount()
    {
        int n = 0;
        for (int i = 0; (m_encProperties != null) && (i < m_encProperties.getNumProperties()); i++)
        {
            EncryptionProperty prop = m_encProperties.getProperty(i);
            if (prop.getName() != null && prop.getName().equals(ENCPROP_ORIG_FILE))
                n++;
        }
        return n;
    }

    /**
     * Returns the filename part of the given embedded digidoc metadata item.
     * 
     * @param nProp
     *            index of digidoc metadata properties
     * @return filename part of the given property
     * @throws DigiDocException
     */
    public String getPropOrigFileName(int nProp)
    {
        String str = null;
        int n = 0, nIdx1 = 0;
        for (int i = 0; (m_encProperties != null) && (i < m_encProperties.getNumProperties()); i++)
        {
            EncryptionProperty prop = m_encProperties.getProperty(i);
            if (prop.getName() != null && prop.getName().equals(ENCPROP_ORIG_FILE))
            {
                n++;
                if (n == nProp)
                { // the right property
                    String content = prop.getContent();
                    if ((content != null) && ((nIdx1 = content.indexOf("|")) != -1))
                    {
                        str = content.substring(0, nIdx1);
                    }
                    break;
                }
            }
        }
        return str;
    }

    /**
     * Returns the filesize part of the given embedded digidoc metadata item.
     * 
     * @param nProp
     *            index of digidoc metadata properties
     * @return filesize part of the given property
     * @throws DigiDocException
     */
    public String getPropOrigFileSize(int nProp)
    {
        String str = null;
        int n = 0, nIdx1 = 0, nIdx2 = 0;
        for (int i = 0; (m_encProperties != null) && (i < m_encProperties.getNumProperties()); i++)
        {
            EncryptionProperty prop = m_encProperties.getProperty(i);
            if (prop.getName() != null && prop.getName().equals(ENCPROP_ORIG_FILE))
            {
                n++;
                if (n == nProp)
                { // the right property
                    String content = prop.getContent();
                    if ((content != null) && ((nIdx1 = content.indexOf("|")) != -1)
                            && ((nIdx2 = content.indexOf("|", nIdx1 + 1)) != -1))
                    {
                        str = content.substring(nIdx1 + 1, nIdx2);
                    }
                    break;
                }
            }
        }
        return str;
    }

    /**
     * Returns the mimetype part of the given embedded digidoc metadata item.
     * 
     * @param nProp
     *            index of digidoc metadata properties
     * @return mimetype part of the given property
     * @throws DigiDocException
     */
    public String getPropOrigFileMime(int nProp)
    {
        String str = null;
        int n = 0, nIdx1 = 0, nIdx2 = 0, nIdx3 = 0;
        for (int i = 0; (m_encProperties != null) && (i < m_encProperties.getNumProperties()); i++)
        {
            EncryptionProperty prop = m_encProperties.getProperty(i);
            if (prop.getName() != null && prop.getName().equals(ENCPROP_ORIG_FILE))
            {
                n++;
                if (n == nProp)
                { // the right property
                    String content = prop.getContent();
                    if ((content != null) && ((nIdx3 = content.indexOf("|")) != -1)
                            && ((nIdx1 = content.indexOf("|", nIdx3 + 1)) != -1)
                            && ((nIdx2 = content.indexOf("|", nIdx1 + 1)) != -1))
                    {
                        str = content.substring(nIdx1 + 1, nIdx2);
                    }
                    break;
                }
            }
        }
        return str;
    }

    /**
     * Returns the id part of the given embedded digidoc metadata item.
     * 
     * @param nProp
     *            index of digidoc metadata properties
     * @return id part of the given property
     * @throws DigiDocException
     */
    public String getPropOrigFileId(int nProp)
    {
        String str = null;
        int n = 0, nIdx1 = 0;
        for (int i = 0; (m_encProperties != null) && (i < m_encProperties.getNumProperties()); i++)
        {
            EncryptionProperty prop = m_encProperties.getProperty(i);
            if (prop.getName() != null && prop.getName().equals(ENCPROP_ORIG_FILE))
            {
                n++;
                if (n == nProp)
                { // the right property
                    String content = prop.getContent();
                    if ((content != null) && ((nIdx1 = content.lastIndexOf("|")) != -1))
                    {
                        str = content.substring(nIdx1 + 1);
                    }
                    break;
                }
            }
        }
        return str;
    }

    /**
     * Adds an <EncryptedKey> object to the array of keys
     * 
     * @param prop
     *            new property object to be added
     */
    public void addEncryptedKey(EncryptedKey key)
    {
        if (m_arrEncryptedKeys == null)
            m_arrEncryptedKeys = new ArrayList();
        m_arrEncryptedKeys.add(key);
    }

    /**
     * Rturns the number of <EncryptedKey> objects in the list
     * 
     * @return number of <EncryptedKey> objects
     */
    public int getNumKeys()
    {
        return ((m_arrEncryptedKeys == null) ? 0 : m_arrEncryptedKeys.size());
    }

    /**
     * Returns the n-th <EncryptedKey> object
     * 
     * @param nIdx
     *            index of the key
     * @return the desired <EncryptedKey> object or null
     */
    public EncryptedKey getEncryptedKey(int nIdx)
    {
        if (nIdx < getNumKeys())
            return (EncryptedKey) m_arrEncryptedKeys.get(nIdx);
        else
            return null;
    }

    /**
     * Returns the last <EncryptedKey> object
     * 
     * @return the last <EncryptedKey> object or null
     */
    public EncryptedKey getLastEncryptedKey()
    {
        if (m_arrEncryptedKeys != null && m_arrEncryptedKeys.size() > 0)
            return (EncryptedKey) m_arrEncryptedKeys.get(m_arrEncryptedKeys.size() - 1);
        else
            return null;
    }

    /**
     * Returns the <EncryptedKey> object with the given Id atribute
     * 
     * @param id
     *            the desired objects Id atribute value
     * @return the desired <EncryptedKey> object or null
     */
    public EncryptedKey findKeyById(String id)
    {
        for (int i = 0; (m_arrEncryptedKeys != null) && (i < m_arrEncryptedKeys.size()); i++)
        {
            EncryptedKey key = (EncryptedKey) m_arrEncryptedKeys.get(i);
            if (key.getId() != null && key.getId().equals(id))
                return key;
        }
        return null;
    }

    /**
     * Returns the <EncryptedKey> object with the given Recipient atribute
     * 
     * @param recv
     *            the desired objects Recipient atribute value
     * @return the desired <EncryptedKey> object or null
     */
    public EncryptedKey findKeyByRecipient(String recv)
    {
        for (int i = 0; (m_arrEncryptedKeys != null) && (i < m_arrEncryptedKeys.size()); i++)
        {
            EncryptedKey key = (EncryptedKey) m_arrEncryptedKeys.get(i);
            if (key.getRecipient() != null && key.getRecipient().equals(recv))
                return key;
        }
        return null;
    }

    /**
     * Returns the <EncryptedKey> object with the given recipients cert that has this subject DN
     * atribute
     * 
     * @param subjectDN
     *            the desired objects cert's subject DN
     * @return the desired <EncryptedKey> object or null
     */
    /*
     * public EncryptedKey findKeyByCertSubjectDN(String subjectDN) throws IOException {
     * X509CertSelector certSelector = new X509CertSelector(); certSelector.setSubject(subjectDN);
     * for(int i = 0; (m_arrEncryptedKeys != null) && (i < m_arrEncryptedKeys.size()); i++) {
     * EncryptedKey key = (EncryptedKey)m_arrEncryptedKeys.get(i); if(key.getRecipientsCertificate()
     * != null && certSelector.match(key.getRecipientsCertificate())) return key; } return null; }
     */

    /**
     * Generates the session key
     * 
     * @throws DigiDocException
     *             for all initialization errors
     */
    private void initKey() throws DigiDocException
    {
        // add BouncyCastle provider if not done yet
        try
        {
            Security.addProvider((Provider) Class.forName(
                    ConfigManager.instance().getProperty("DIGIDOC_SECURITY_PROVIDER"))
                    .newInstance());
        }
        catch (Exception ex)
        {
            DigiDocException.handleException(ex, DigiDocException.ERR_NO_PROVIDER);
        }
        // check key status first
        if (m_transportKey != null)
            throw new DigiDocException(DigiDocException.ERR_XMLENC_KEY_STATUS,
                    "Transport key allready initialized!", null);
        try
        {
            SecureRandom random = SecureRandom.getInstance(ConfigManager.instance().getProperty(
                    "DIGIDOC_SECRANDOM_ALGORITHM"));
            KeyGenerator keygen = KeyGenerator.getInstance(ConfigManager.instance().getProperty(
                    "DIGDOC_ENCRYPT_KEY_ALG"), ConfigManager.instance().getProperty(
                    "DIGIDOC_SECURITY_PROVIDER_NAME"));
            if (m_logger.isDebugEnabled())
                m_logger.debug("Keygen:" + keygen.getClass().getName() + " algorithm: "
                        + keygen.getAlgorithm());
            keygen.init(128, random);
            m_transportKey = keygen.generateKey();
            if (m_logger.isDebugEnabled())
            {
                m_logger.debug("key0: " + m_transportKey.getEncoded().length);
            }
        }
        catch (Exception ex)
        {
            DigiDocException.handleException(ex, DigiDocException.ERR_XMLENC_KEY_GEN);
        }
        // check the result
        if (m_transportKey == null)
            throw new DigiDocException(DigiDocException.ERR_XMLENC_KEY_GEN,
                    "Failure to initialize the transport key!", null);
    }

    /**
     * Helper method to convert secret key to a Cipher
     * 
     * @param mode
     *            ciphers mode: encrypt or decrypt
     * @param transportKey
     *            secret key. Use null for default
     * @param iv
     *            init vector data. Use null for no IV
     * @return Cipher object
     */
    public Cipher getCipher(int mode, SecretKey transportKey, byte[] iv) throws DigiDocException
    {
        Cipher cip = null;
        byte[] ivdata = null;
        // check key status first - nothing to encrypt?
        if (m_transportKey == null && transportKey == null)
            throw new DigiDocException(DigiDocException.ERR_XMLENC_KEY_STATUS,
                    "Transport key has not been initialized!", null);
        try
        {
            cip = Cipher.getInstance(ConfigManager.instance().getProperty(
                    "DIGIDOC_ENCRYPTION_ALOGORITHM"), ConfigManager.instance().getProperty(
                    "DIGIDOC_SECURITY_PROVIDER_NAME"));
            if (mode == Cipher.DECRYPT_MODE)
            {
                IvParameterSpec ivSpec = new IvParameterSpec(iv);
                cip.init(mode, ((transportKey == null) ? m_transportKey : transportKey), ivSpec);
            }
            else
            {
                cip.init(mode, ((transportKey == null) ? m_transportKey : transportKey));
                ivdata = cip.getIV();
                System.arraycopy(ivdata, 0, iv, 0, 16); // copy the iv used
            }
            if (m_logger.isDebugEnabled())
            {
                m_logger.debug("Cipher: " + cip.getAlgorithm() + " provider: "
                        + cip.getProvider().getName());
                ivdata = cip.getIV();
                for (int i = 0; i < ivdata.length; i++)
                    System.out.println("IV pos: " + i + " = " + ivdata[i]);
                // cip.getProvider().list(System.out);
            }
        }
        catch (Exception ex)
        {
            DigiDocException.handleException(ex, DigiDocException.ERR_XMLENC_ENCRYPT);
        }
        return cip;
    }

    /**
     * Encrypts the data with the given
     * 
     * @param nCompressOption
     *            compression option: allways, never or best effort
     * @throws DigiDocException
     *             for encryption errors
     */
    public void encrypt(int nCompressOption) throws DigiDocException
    {
        byte[] ivdata = new byte[16];
        // check the transport key
        if (m_transportKey == null)
            initKey();
        // check data
        if (m_data == null
                || (m_nDataStatus != DENC_DATA_STATUS_UNENCRYPTED_AND_COMPRESSED && m_nDataStatus != DENC_DATA_STATUS_UNENCRYPTED_AND_NOT_COMPRESSED))
            throw new DigiDocException(DigiDocException.ERR_XMLENC_DATA_STATUS,
                    "Invalid data status for encryption operation!", null);
        int nTotalInput = m_data.length, nTotalCompressed = 0, nTotalEncrypted = 0;
        // compress data if necessary
        compress(nCompressOption);
        nTotalCompressed = m_data.length;
        // get cipher to encrypt the data
        Cipher cipher = getCipher(Cipher.ENCRYPT_MODE, null, ivdata);
        try
        {

            // get the cipher
            if (m_logger.isDebugEnabled())
                m_logger.debug("Encrypt - algorithm: " + cipher.getAlgorithm() + " blocksize: "
                        + cipher.getBlockSize());
            int nBlockSize = cipher.getBlockSize();
            // encrypt full data blocks
            int nLastBlockSize = m_data.length % nBlockSize;
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            bos.write(m_data, 0, m_data.length - nLastBlockSize);
            int nOrigLen = m_data.length;
            if (m_logger.isDebugEnabled())
                m_logger.debug("Encrypt - body: " + m_data.length + " full-data: "
                        + (m_data.length - nLastBlockSize) + " left: " + nLastBlockSize);
            // compose the last block
            byte[] cdata = new byte[nBlockSize];
            System.arraycopy(m_data, m_data.length - nLastBlockSize, cdata, 0, nLastBlockSize);
            for (int i = nLastBlockSize; i < nBlockSize; i++)
                cdata[i] = 0; // pad with zeros
            // last byte contains the amount of pad-bytes in this block
            cdata[nBlockSize - 1] = new Integer(nBlockSize - nLastBlockSize).byteValue();
            bos.write(cdata);
            if (m_logger.isDebugEnabled())
            {
                for (int i = 0; i < nBlockSize; i++)
                    m_logger.debug("Byte at: " + i + " = " + cdata[i]);
            }
            // encrypt data
            cdata = cipher.doFinal(bos.toByteArray());
            nTotalEncrypted = cdata.length;
            if (m_logger.isDebugEnabled())
                m_logger.debug("Encrypt - orig: " + nOrigLen + " input: "
                        + (nOrigLen - nLastBlockSize + nBlockSize) + " encrypted: " + cdata.length);
            // encrypted data
            m_data = new byte[cdata.length + 16];
            System.arraycopy(ivdata, 0, m_data, 0, 16);
            System.arraycopy(cdata, 0, m_data, 16, cdata.length);
            m_nDataStatus = DENC_DATA_STATUS_ENCRYPTED_AND_NOT_COMPRESSED;
            // encrypt transport key for all recipients
            for (int i = 0; i < getNumKeys(); i++)
            {
                EncryptedKey ekey = getEncryptedKey(i);
                ekey.encryptKey(this);
            }
            if (m_logger.isInfoEnabled())
                m_logger.info("Encrypt total - input: " + nTotalInput + " compressed: "
                        + nTotalCompressed + " encrypted: " + nTotalEncrypted);
        }
        catch (Exception ex)
        {
            DigiDocException.handleException(ex, DigiDocException.ERR_XMLENC_ENCRYPT);
        }
    }

    /**
     * Decrypts the data with the given
     * 
     * @throws DigiDocException
     *             for decryption errors
     */
    public void decrypt(int nKey, int token, String pin) throws DigiDocException
    {
        byte[] ivdata = new byte[16];
        // check data
        if (m_data == null
                || (m_nDataStatus != DENC_DATA_STATUS_ENCRYPTED_AND_COMPRESSED && m_nDataStatus != DENC_DATA_STATUS_ENCRYPTED_AND_NOT_COMPRESSED))
            throw new DigiDocException(DigiDocException.ERR_XMLENC_DATA_STATUS,
                    "Invalid data status for decryption operation!", null);
        if (m_logger.isDebugEnabled())
            m_logger.debug("Decrypting " + m_data.length + " using iv " + ivdata.length + " left: "
                    + (m_data.length - ivdata.length));
        // use the first 16 bytes as IV value and remove it from decryption process
        System.arraycopy(m_data, 0, ivdata, 0, ivdata.length);
        for (int i = 0; i < ivdata.length; i++)
            System.out.println("IV pos: " + i + " = " + ivdata[i]);
        EncryptedKey ekey = getEncryptedKey(nKey);
        try
        {
            // decrypt transport key
            SignatureFactory sfac = ConfigManager.instance().getSignatureFactory();
            if (m_logger.isDebugEnabled())
                m_logger.debug("Decrypting key: " + nKey + " with token: " + token);
            byte[] decdata = sfac.decrypt(ekey.getTransportKeyData(), token, pin);
            m_transportKey = (SecretKey) new SecretKeySpec(decdata, ConfigManager.instance()
                    .getProperty("DIGIDOC_ENCRYPTION_ALOGORITHM"));
            // decrypt data
            Cipher cipher = getCipher(Cipher.DECRYPT_MODE, m_transportKey, ivdata);
            if (m_logger.isDebugEnabled())
                m_logger.debug("Decrypting: " + m_data.length + " bytes");
            m_data = cipher.update(m_data, 16, m_data.length - 16);
            // m_data = cipher.doFinal(m_data, 16, m_data.length - 16);
            if (m_logger.isDebugEnabled())
                m_logger.debug("Decrypted data: " + m_data.length + " bytes");
            for (int i = m_data.length - 16; i < m_data.length; i++)
                if (m_logger.isDebugEnabled())
                    m_logger.debug("byte at: " + i + " = " + m_data[i]);
            if (m_nDataStatus == DENC_DATA_STATUS_ENCRYPTED_AND_COMPRESSED)
                m_nDataStatus = DENC_DATA_STATUS_UNENCRYPTED_AND_COMPRESSED;
            if (m_nDataStatus == DENC_DATA_STATUS_ENCRYPTED_AND_NOT_COMPRESSED)
                m_nDataStatus = DENC_DATA_STATUS_UNENCRYPTED_AND_NOT_COMPRESSED;
            int nPadLen = new Integer(m_data[m_data.length - 1]).intValue();
            if (m_logger.isDebugEnabled())
                m_logger.debug("Decrypted: " + m_data.length + " bytes, check padding: " + nPadLen);
            // remove padding
            boolean bPadOk = true;
            for (int i = m_data.length - nPadLen; i < m_data.length - 1; i++)
            {
                if (m_data[i] != 0)
                {
                    if (m_logger.isDebugEnabled())
                        m_logger.debug("Data at: " + i + " = " + m_data[i] + " cancel padding");
                    bPadOk = false;
                    break;
                }
            }
            if (bPadOk)
            {
                if (m_logger.isDebugEnabled())
                    m_logger.debug("Padding: " + nPadLen + " bytes");
                byte[] data2 = new byte[m_data.length - nPadLen];
                System.arraycopy(m_data, 0, data2, 0, m_data.length - nPadLen);
                m_data = data2;
            }
            if (m_nDataStatus == DENC_DATA_STATUS_UNENCRYPTED_AND_COMPRESSED)
                decompress();
        }
        catch (Exception ex)
        {
            DigiDocException.handleException(ex, DigiDocException.ERR_XMLENC_DECRYPT);
        }
    }

    /**
     * Compresses the unencrypted data using ZLIB algorithm
     * 
     * @param nCompressOption
     *            compression option: allways, never or best effort
     * @throws DigiDocException
     *             for compression errors
     */
    private void compress(int nCompressOption) throws DigiDocException
    {
        // check the flag
        if (nCompressOption == DENC_COMPRESS_NEVER)
            return; // nothing to do
        // check data
        if (m_data == null || m_nDataStatus != DENC_DATA_STATUS_UNENCRYPTED_AND_NOT_COMPRESSED)
            throw new DigiDocException(DigiDocException.ERR_XMLENC_DATA_STATUS,
                    "Invalid data status for compression operation!", null);
        try
        {
            int nOldSize = m_data.length;
            if (m_logger.isDebugEnabled())
                m_logger.debug("Compressing: " + m_data.length + " bytes");
            ByteArrayOutputStream bout = new ByteArrayOutputStream();
            DeflaterOutputStream gout = new DeflaterOutputStream(bout);
            gout.write(m_data);
            gout.flush();
            gout.close();
            bout.close();
            byte[] n_data = bout.toByteArray();
            int nNewSize = n_data.length;
            if (nCompressOption == DENC_COMPRESS_ALLWAYS
                    || (nCompressOption == DENC_COMPRESS_BEST_EFFORT && nNewSize < nOldSize))
            {
                m_nDataStatus = DENC_DATA_STATUS_UNENCRYPTED_AND_COMPRESSED;
                m_data = n_data;
                // store original size and mime type
                addProperty(ENCPROP_ORIG_SIZE, new Integer(nOldSize).toString());
                if (m_mimeType != null)
                    addProperty(ENCPROP_ORIG_MIME, m_mimeType);
                // mark this as compressed data
                m_mimeType = DENC_ENCDATA_MIME_ZLIB;
                if (m_logger.isDebugEnabled())
                    m_logger.debug("Keeping compressed: " + m_data.length + " bytes");
            }
            else
            {
                if (m_logger.isDebugEnabled())
                    m_logger.debug("Discarding compressed: " + m_data.length + " bytes");
            }
        }
        catch (Exception ex)
        {
            DigiDocException.handleException(ex, DigiDocException.ERR_XMLENC_COMPRESS);
        }
    }

    /**
     * Decompresses the unencrypted data using ZLIB algorithm
     * 
     * @throws DigiDocException
     *             for decompression errors
     */
    private void decompress() throws DigiDocException
    {
        // check data
        if (m_data == null || m_nDataStatus != DENC_DATA_STATUS_UNENCRYPTED_AND_COMPRESSED)
            throw new DigiDocException(DigiDocException.ERR_XMLENC_DATA_STATUS,
                    "Invalid data status for decompression operation!", null);
        try
        {
            if (m_logger.isDebugEnabled())
                m_logger.debug("Decompressing: " + m_data.length + " bytes");
            ByteArrayInputStream bin = new ByteArrayInputStream(m_data);
            InflaterInputStream gin = new InflaterInputStream(bin);
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] data = new byte[2048];
            int nRead = 0;
            while ((nRead = gin.read(data)) > 0)
                bos.write(data, 0, nRead);
            gin.close();
            bin.close();
            bos.close();
            m_data = bos.toByteArray();
            m_nDataStatus = DENC_DATA_STATUS_UNENCRYPTED_AND_NOT_COMPRESSED;
            if (m_logger.isDebugEnabled())
                m_logger.debug("Decompressed: " + m_data.length + " bytes");
        }
        catch (Exception ex)
        {
            DigiDocException.handleException(ex, DigiDocException.ERR_XMLENC_DECOMPRESS);
        }
    }

    /**
     * Encrypts all input data coming from this stream, compresses it if necessary converts to
     * base64 and writes as an XML encrypted document to output stream. Use this method to encrypt
     * big amunts of data. Please note that you must first inittialize the recipients (e.g.
     * EncryptedKey objects) but not the data. Data comes from the input stream, thus data status
     * should be UNINITIALIZED when you call this method.
     * 
     * @param in
     *            stream with data to encrypt
     * @param out
     *            output stream for encrypted data
     * @param nCompressOption
     *            compression option: allways, never. Best-effort is not supported here because we
     *            don't know it before we have encrypted eveything end then we don't want to redo
     *            this.
     * @throws DigiDocException
     *             for encryption errors
     */
    public void encryptStream(InputStream in, OutputStream out, int nCompressOption)
            throws DigiDocException
    {
        byte[] ivdata = new byte[16];
        // check the transport key
        if (m_transportKey == null)
            initKey();
        // check data
        if (m_data != null || m_nDataStatus != DENC_DATA_STATUS_UNINITIALIZED)
            throw new DigiDocException(DigiDocException.ERR_XMLENC_DATA_STATUS,
                    "Invalid data status for encryption operation!", null);
        // get cipher to encrypt the data
        Cipher cipher = getCipher(Cipher.ENCRYPT_MODE, null, ivdata);
        Deflater compressor = null;
        if (nCompressOption == DENC_COMPRESS_ALLWAYS)
        {
            compressor = new Deflater();
            if (m_mimeType != null)
                addProperty(ENCPROP_ORIG_MIME, m_mimeType);
            // mark this as compressed data
            m_mimeType = DENC_ENCDATA_MIME_ZLIB;
        }
        int nCiphBlockSize = cipher.getBlockSize();
        int nBlockSize = 2048;
        int nTotalInput = 0, nTotalCompressed = 0, nTotalEncrypted = 0, nTotalBase64 = 0;
        int nLen1, nLen2, nB64left = 0;
        byte[] data1 = new byte[nBlockSize];
        byte[] data2 = new byte[nBlockSize * 10];
        byte[] b64leftover = new byte[65];
        try
        {
            // get the cipher
            if (m_logger.isDebugEnabled())
                m_logger.debug("EncryptStream - algorithm: " + cipher.getAlgorithm()
                        + " blocksize: " + nCiphBlockSize);
            // encrypt transport key for all recipients
            for (int i = 0; i < getNumKeys(); i++)
            {
                EncryptedKey ekey = getEncryptedKey(i);
                ekey.encryptKey(this);
            }
            // write xml header
            out.write(xmlHeader());

            // read input data
            while ((nLen1 = in.read(data1)) != -1)
            {
                nTotalInput += nLen1;
                if (nCompressOption == DENC_COMPRESS_ALLWAYS)
                { // compress
                    compressor.setInput(data1, 0, nLen1);
                    if (nLen1 < nBlockSize) // last block
                        compressor.finish();
                    nLen2 = compressor.deflate(data2);
                    nTotalCompressed += nLen2;
                    if (m_logger.isDebugEnabled())
                        m_logger.debug("EncryptStream - input: " + nLen1 + " compressed: " + nLen2
                                + " needin: " + compressor.needsInput());
                }
                else
                { // don't compress
                    System.arraycopy(data1, 0, data2, 0, nLen1);
                    nLen2 = nLen1;
                }
                // encrypt data
                byte[] encdata = null;

                if (nLen1 < nBlockSize)
                { // last block
                    // encrypt full cipher blocks of data first
                    int nLastBlockSize = nLen2 % nCiphBlockSize;
                    ByteArrayOutputStream bos = new ByteArrayOutputStream();
                    bos.write(data2, 0, nLen2 - nLastBlockSize);
                    // compose the last block
                    byte[] ldata = new byte[nCiphBlockSize];
                    System.arraycopy(data2, nLen2 - nLastBlockSize, ldata, 0, nLastBlockSize);
                    for (int i = nLastBlockSize; i < nCiphBlockSize; i++)
                        ldata[i] = 0; // pad with zeros
                    // last byte contains the amount of pad-bytes in this block
                    ldata[nCiphBlockSize - 1] = new Integer(nCiphBlockSize - nLastBlockSize)
                            .byteValue();
                    bos.write(ldata);
                    ldata = bos.toByteArray();
                    encdata = cipher.doFinal(ldata);
                    if (m_logger.isDebugEnabled())
                        m_logger.debug("EncryptStream - last input: " + nLen2 + " padded: "
                                + ldata.length + " encrypted: "
                                + ((encdata != null) ? encdata.length : 0));

                }
                else
                { // not the last block
                    encdata = cipher.update(data2, 0, nLen2);
                    if (m_logger.isDebugEnabled())
                        m_logger.debug("EncryptStream - norm input: " + nLen2 + " encrypted: "
                                + ((encdata != null) ? encdata.length : 0));
                }
                if (encdata != null)
                {
                    // if this is the first block then add the IV vector
                    // to the beginning of data that is subsequently encoded
                    if (nTotalEncrypted == 0)
                    {
                        byte[] tdata = new byte[encdata.length + 16];
                        System.arraycopy(ivdata, 0, tdata, 0, 16);
                        System.arraycopy(encdata, 0, tdata, 16, encdata.length);
                        nTotalEncrypted += encdata.length;
                        encdata = tdata;
                    }
                    else
                        nTotalEncrypted += encdata.length;
                    // use also data left over from last block
                    if (nB64left > 0)
                    {
                        if (m_logger.isDebugEnabled())
                            m_logger.debug("EncryptStream - input: " + encdata.length + " left: "
                                    + nB64left);
                        byte[] data3 = new byte[encdata.length + nB64left];
                        System.arraycopy(b64leftover, 0, data3, 0, nB64left);
                        System.arraycopy(encdata, 0, data3, nB64left, encdata.length);
                        encdata = data3;
                    }
                    int nUsed = Base64Util.encodeToStream(encdata, out, (nLen1 < nBlockSize));
                    nB64left = encdata.length - nUsed;
                    if (m_logger.isDebugEnabled())
                        m_logger.debug("EncryptStream - input: " + encdata.length + " used: "
                                + nUsed + " copy: " + nB64left + " pos: " + nUsed);
                    if (nB64left > 0)
                    {
                        System.arraycopy(encdata, nUsed, b64leftover, 0, nB64left);
                        nTotalBase64 += (nUsed / 3) * 4;
                        if (m_logger.isDebugEnabled())
                            m_logger.debug("EncryptStream - input: " + encdata.length + " used: "
                                    + nUsed + " base64: " + ((nUsed / 3) * 4) + " left: "
                                    + nB64left);
                    }
                }
            } // end reading input data

            addProperty(ENCPROP_ORIG_SIZE, new Integer(nTotalInput).toString());

            // write xml trailer
            out.write(xmlTrailer());
            out.flush();
            if (m_logger.isInfoEnabled())
                m_logger.info("EncryptStream total - input: " + nTotalInput + " compressed: "
                        + nTotalCompressed + " encrypted: " + nTotalEncrypted + " base64: "
                        + nTotalBase64);
        }
        catch (Exception ex)
        {
            DigiDocException.handleException(ex, DigiDocException.ERR_XMLENC_ENCRYPT);
        }
    }

    /**
     * Converts the EncryptedData to XML form
     * 
     * @return XML representation of EncryptedData
     */
    public byte[] toXML() throws DigiDocException
    {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try
        {
            bos.write(xmlHeader());
            byte[] b64data = ConvertUtils.str2data(Base64Util.encode(m_data, 64));
            int nTotalBase64 = b64data.length;
            bos.write(b64data);
            if (m_logger.isInfoEnabled())
                m_logger.info("Encrypt total - base64: " + nTotalBase64);
            bos.write(xmlTrailer());
        }
        catch (IOException ex)
        {
            DigiDocException.handleException(ex, DigiDocException.ERR_XML_CONVERT);
        }
        return bos.toByteArray();
    }

    /**
     * Converts the EncryptedData header (until payload data) to XML form
     * 
     * @return XML representation of EncryptedData header
     */
    private byte[] xmlHeader() throws DigiDocException
    {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try
        {
            bos.write(ConvertUtils.str2data("<?xml version=\"1.0\" encoding=\"UTF-8\" ?>"));
            bos.write(ConvertUtils.str2data("<denc:EncryptedData xmlns:denc=\"" + m_xmlns + "\""));
            if (m_id != null)
                bos.write(ConvertUtils.str2data(" Id=\"" + m_id + "\""));
            if (m_mimeType != null)
                bos.write(ConvertUtils.str2data(" MimeType=\"" + m_mimeType + "\""));
            if (m_type != null)
                bos.write(ConvertUtils.str2data(" Type=\"" + m_type + "\""));

            bos.write(ConvertUtils.str2data(">"));
            bos.write(ConvertUtils.str2data("<denc:EncryptionMethod Algorithm=\""));
            bos.write(ConvertUtils.str2data(m_encryptionMethod));
            bos.write(ConvertUtils.str2data("\"></denc:EncryptionMethod>"));
            bos
                    .write(ConvertUtils.str2data("<ds:KeyInfo xmlns:ds=\"" + DENC_XMLNS_XMLDSIG
                            + "\">"));
            for (int i = 0; i < getNumKeys(); i++)
            {
                EncryptedKey key = getEncryptedKey(i);
                bos.write(key.toXML());
            }
            bos.write(ConvertUtils.str2data("</ds:KeyInfo>"));
            bos.write(ConvertUtils.str2data("<denc:CipherData><denc:CipherValue>"));
            // after this comes payload data
        }
        catch (IOException ex)
        {
            DigiDocException.handleException(ex, DigiDocException.ERR_XML_CONVERT);
        }
        return bos.toByteArray();
    }

    /**
     * Converts the EncryptedData header (until payload data) to XML form
     * 
     * @return XML representation of EncryptedData header
     */
    private byte[] xmlTrailer() throws DigiDocException
    {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try
        {
            // header and encrypted data comes before this
            bos.write(ConvertUtils.str2data("</denc:CipherValue></denc:CipherData>"));
            if (getNumProperties() > 0)
            {
                bos.write(ConvertUtils.str2data("<denc:EncryptionProperties"));
                if (getEncryptionPropertiesId() != null)
                    bos.write(ConvertUtils.str2data(" Id=\"" + getEncryptionPropertiesId() + "\""));
                bos.write(ConvertUtils.str2data(">"));
                for (int i = 0; i < getNumProperties(); i++)
                {
                    EncryptionProperty prop = getProperty(i);
                    bos.write(prop.toXML());
                }
                bos.write(ConvertUtils.str2data("</denc:EncryptionProperties>"));
            }
            bos.write(ConvertUtils.str2data("</denc:EncryptedData>"));
        }
        catch (IOException ex)
        {
            DigiDocException.handleException(ex, DigiDocException.ERR_XML_CONVERT);
        }
        return bos.toByteArray();
    }

    /**
     * Helper method to validate the whole EncryptedData object
     * 
     * @return a possibly empty list of DigiDocException objects
     */
    public ArrayList validate()
    {
        ArrayList errs = new ArrayList();
        DigiDocException ex = validateEncryptionMethod(m_encryptionMethod);
        if (ex != null)
            errs.add(ex);
        ex = validateXmlns(m_xmlns);
        if (ex != null)
            errs.add(ex);
        if (m_encProperties != null)
        {
            ArrayList e = m_encProperties.validate();
            if (!e.isEmpty())
                errs.addAll(e);
        }
        for (int i = 0; i < getNumKeys(); i++)
        {
            EncryptedKey ekey = getEncryptedKey(i);
            ArrayList e = ekey.validate();
            if (!e.isEmpty())
                errs.addAll(e);
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
