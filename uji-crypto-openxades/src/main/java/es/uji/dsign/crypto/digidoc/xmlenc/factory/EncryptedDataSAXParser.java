/*
 * EncryptedDataSAXParser.java
 * PROJECT: JDigiDoc
 * DESCRIPTION: Digi Doc functions for creating
 *	and reading encrypted documents.  Implementation using SAX parser.
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
package es.uji.dsign.crypto.digidoc.xmlenc.factory;

import java.io.InputStream;
import java.io.FileInputStream;
import java.util.Stack;
import java.security.cert.X509Certificate;

import javax.xml.parsers.SAXParserFactory;
import javax.xml.parsers.SAXParser;

import es.uji.dsign.crypto.digidoc.Base64Util;
import es.uji.dsign.crypto.digidoc.DigiDocException;
import es.uji.dsign.crypto.digidoc.SignedDoc;
import es.uji.dsign.crypto.digidoc.factory.SAXDigiDocException;
import es.uji.dsign.crypto.digidoc.xmlenc.EncryptedData;
import es.uji.dsign.crypto.digidoc.xmlenc.EncryptedKey;
import es.uji.dsign.crypto.digidoc.xmlenc.EncryptionProperty;

import org.xml.sax.SAXException;
import org.xml.sax.Attributes;
import org.xml.sax.helpers.DefaultHandler;

import org.apache.log4j.Logger;

/**
 * Implementation class for reading and writing encrypted files using a SAX parser
 * 
 * @author Veiko Sinivee
 * @version 1.0
 */
public class EncryptedDataSAXParser extends DefaultHandler implements EncryptedDataParser
{
    private Stack m_tags;
    private EncryptedData m_doc;
    private StringBuffer m_sbCollectChars;
    /** log4j logger */
    private Logger m_logger = null;

    /**
     * Creates new EncyptedDataSAXParser and initializes the variables
     */
    public EncryptedDataSAXParser()
    {
        m_tags = new Stack();
        m_doc = null;
        m_sbCollectChars = null;
        m_logger = Logger.getLogger(EncryptedDataSAXParser.class);
    }

    /**
     * initializes the implementation class
     * 
     * @see es.uji.dsign.crypto.digidoc.xmlenc.factory.EncryptedDataParser#init()
     */
    public void init() throws DigiDocException
    {

    }

    /**
     * Reads in a EncryptedData file (.cdoc)
     * 
     * @param dencStream
     *            opened stream with EncrypyedData data The user must open and close it.
     * @return EncryptedData object if successfully parsed
     * @see es.uji.dsign.crypto.digidoc.xmlenc.factory.EncryptedDataParser#readEncryptedData(java.io.InputStream)
     */
    public EncryptedData readEncryptedData(InputStream dencStream) throws DigiDocException
    {
        // Use an instance of ourselves as the SAX event handler
        EncryptedDataSAXParser handler = this;
        // Use the default (non-validating) parser
        SAXParserFactory factory = SAXParserFactory.newInstance();
        // factory.setNamespaceAware(true);
        try
        {
            SAXParser saxParser = factory.newSAXParser();
            saxParser.parse(dencStream, handler);
        }
        catch (SAXDigiDocException ex)
        {
            throw ex.getDigiDocException();
        }
        catch (Exception ex)
        {
            DigiDocException.handleException(ex, DigiDocException.ERR_PARSE_XML);
        }
        if (m_doc == null)
            throw new DigiDocException(DigiDocException.ERR_DIGIDOC_FORMAT,
                    "This document is not in EncryptedData format", null);
        return m_doc;
    }

    /**
     * Reads in a EncryptedData file
     * 
     * @param fileName
     *            file name
     * @return EncryptedData document object if successfully parsed
     */
    public EncryptedData readEncryptedData(String fileName) throws DigiDocException
    {
        // Use an instance of ourselves as the SAX event handler
        EncryptedDataSAXParser handler = this;
        // Use the default (non-validating) parser
        SAXParserFactory factory = SAXParserFactory.newInstance();
        // factory.setNamespaceAware(true);
        try
        {
            SAXParser saxParser = factory.newSAXParser();
            FileInputStream is = new FileInputStream(fileName);
            saxParser.parse(is, handler);
            is.close();
        }
        catch (SAXDigiDocException ex)
        {
            throw ex.getDigiDocException();
        }
        catch (Exception ex)
        {
            DigiDocException.handleException(ex, DigiDocException.ERR_PARSE_XML);
        }
        if (m_doc == null)
            throw new DigiDocException(DigiDocException.ERR_DIGIDOC_FORMAT,
                    "This document is not in EncryptedData format", null);
        return m_doc;
    }

    /**
     * Start Document handler
     */
    public void startDocument() throws SAXException
    {
        m_doc = null;
        m_sbCollectChars = null;
    }

    /**
     * End Document handler
     */
    public void endDocument() throws SAXException
    {
    }

    /**
     * Finds the value of an atribute by name
     * 
     * @param atts
     *            atributes
     * @param attName
     *            name of atribute
     * @return value of the atribute
     */
    private String findAtributeValue(Attributes attrs, String attName)
    {
        String value = null;
        for (int i = 0; i < attrs.getLength(); i++)
        {
            String key = attrs.getQName(i);
            if (key.equals(attName) || key.indexOf(attName) != -1)
            {
                value = attrs.getValue(i);
                break;
            }
        }
        return value;
    }

    /**
     * Checks if this document is in <EncryptedData> format
     * 
     * @throws SAXDigiDocException
     *             if the document is not in <EncryptedData> format
     */
    private void checkEncryptedData() throws SAXDigiDocException
    {
        if (m_doc == null)
            throw new SAXDigiDocException(DigiDocException.ERR_XMLENC_NO_ENCRYPTED_DATA,
                    "This document is not in EncryptedData format!");
    }

    /**
     * Checks if the <EncryptedKey> objects exists
     * 
     * @throws SAXDigiDocException
     *             if the objects <EncryptedKey> does not exist
     */
    private void checkEncryptedKey(EncryptedKey key) throws SAXDigiDocException
    {
        if (key == null)
            throw new SAXDigiDocException(DigiDocException.ERR_XMLENC_NO_ENCRYPTED_KEY,
                    "This <EncryptedKey> object does not exist!");
    }

    /**
     * Start Element handler
     * 
     * @param namespaceURI
     *            namespace URI
     * @param lName
     *            local name
     * @param qName
     *            qualified name
     * @param attrs
     *            attributes
     */
    public void startElement(String namespaceURI, String lName, String qName, Attributes attrs)
            throws SAXDigiDocException
    {
        String tName = qName;
        if (tName.indexOf(":") != -1)
            tName = qName.substring(qName.indexOf(":") + 1);
        if (m_logger.isDebugEnabled())
            m_logger.debug("Start Element: " + tName + " qname: " + qName + " lname: " + lName
                    + " uri: " + namespaceURI);
        m_tags.push(tName);
        if (tName.equals("KeyName") || tName.equals("CarriedKeyName")
                || tName.equals("X509Certificate") || tName.equals("CipherValue")
                || tName.equals("EncryptionProperty"))
            m_sbCollectChars = new StringBuffer();

        // <EncryptedData>
        if (tName.equals("EncryptedData"))
        {
            String str = findAtributeValue(attrs, "xmlns");
            try
            {
                m_doc = new EncryptedData(str);
                str = findAtributeValue(attrs, "Id");
                if (str != null)
                    m_doc.setId(str);
                str = findAtributeValue(attrs, "Type");
                if (str != null)
                    m_doc.setType(str);
                str = findAtributeValue(attrs, "MimeType");
                if (str != null)
                    m_doc.setMimeType(str);
            }
            catch (DigiDocException ex)
            {
                SAXDigiDocException.handleException(ex);
            }
        }
        // <EncryptionMethod>
        if (tName.equals("EncryptionMethod"))
        {
            checkEncryptedData();
            if (m_tags.search("EncryptedKey") != -1)
            { // child of <EncryptedKey>
                EncryptedKey ekey = m_doc.getLastEncryptedKey();
                checkEncryptedKey(ekey);
                try
                {
                    ekey.setEncryptionMethod(findAtributeValue(attrs, "Algorithm"));
                }
                catch (DigiDocException ex)
                {
                    SAXDigiDocException.handleException(ex);
                }
            }
            else
            { // child of <EncryptedData>
                try
                {
                    m_doc.setEncryptionMethod(findAtributeValue(attrs, "Algorithm"));
                }
                catch (DigiDocException ex)
                {
                    SAXDigiDocException.handleException(ex);
                }
            }
        }
        // <EncryptedKey>
        if (tName.equals("EncryptedKey"))
        {
            checkEncryptedData();
            EncryptedKey ekey = new EncryptedKey();
            m_doc.addEncryptedKey(ekey);
            String str = findAtributeValue(attrs, "Recipient");
            if (str != null)
                ekey.setRecipient(str);
            str = findAtributeValue(attrs, "Id");
            if (str != null)
                ekey.setId(str);
        }
        // <EncryptionProperties>
        if (tName.equals("EncryptionProperties"))
        {
            checkEncryptedData();
            String str = findAtributeValue(attrs, "Id");
            if (str != null)
                m_doc.setEncryptionPropertiesId(str);
        }
        // <EncryptionProperty>
        if (tName.equals("EncryptionProperty"))
        {
            checkEncryptedData();
            EncryptionProperty eprop = new EncryptionProperty();
            m_doc.addProperty(eprop);
            String str = findAtributeValue(attrs, "Id");
            if (str != null)
                eprop.setId(str);
            str = findAtributeValue(attrs, "Target");
            if (str != null)
                eprop.setTarget(str);
            str = findAtributeValue(attrs, "Name");
            try
            {
                if (str != null)
                    eprop.setName(str);
            }
            catch (DigiDocException ex)
            {
                SAXDigiDocException.handleException(ex);
            }
        }
    }

    /**
     * End Element handler
     * 
     * @param namespaceURI
     *            namespace URI
     * @param lName
     *            local name
     * @param qName
     *            qualified name
     */
    public void endElement(String namespaceURI, String sName, String qName) throws SAXException
    {
        String tName = qName;
        if (tName.indexOf(":") != -1)
            tName = qName.substring(tName.indexOf(":") + 1);
        if (m_logger.isDebugEnabled())
            m_logger.debug("End Element: " + tName);
        // remove last tag from stack
        String currTag = (String) m_tags.pop();
        // <KeyName>
        if (tName.equals("KeyName"))
        {
            checkEncryptedData();
            EncryptedKey ekey = m_doc.getLastEncryptedKey();
            checkEncryptedKey(ekey);
            ekey.setKeyName(m_sbCollectChars.toString());
            m_sbCollectChars = null; // stop collecting
        }
        // <CarriedKeyName>
        if (tName.equals("CarriedKeyName"))
        {
            checkEncryptedData();
            EncryptedKey ekey = m_doc.getLastEncryptedKey();
            checkEncryptedKey(ekey);
            ekey.setCarriedKeyName(m_sbCollectChars.toString());
            m_sbCollectChars = null; // stop collecting
        }
        // <X509Certificate>
        if (tName.equals("X509Certificate"))
        {
            checkEncryptedData();
            EncryptedKey ekey = m_doc.getLastEncryptedKey();
            checkEncryptedKey(ekey);
            try
            {
                X509Certificate cert = SignedDoc.readCertificate(Base64Util.decode(m_sbCollectChars
                        .toString().getBytes()));
                ekey.setRecipientsCertificate(cert);
            }
            catch (DigiDocException ex)
            {
                SAXDigiDocException.handleException(ex);
            }
            m_sbCollectChars = null; // stop collecting
        }
        // <CipherValue>
        if (tName.equals("CipherValue"))
        {
            checkEncryptedData();
            if (m_tags.search("EncryptedKey") != -1)
            { // child of <EncryptedKey>
                EncryptedKey ekey = m_doc.getLastEncryptedKey();
                checkEncryptedKey(ekey);
                ekey.setTransportKeyData(Base64Util.decode(m_sbCollectChars.toString().getBytes()));
            }
            else
            { // child of <EncryptedData>
                m_doc.setData(Base64Util.decode(m_sbCollectChars.toString().getBytes()));
                if (m_doc.getMimeType() != null
                        && m_doc.getMimeType().equals(EncryptedData.DENC_ENCDATA_MIME_ZLIB))
                    m_doc.setDataStatus(EncryptedData.DENC_DATA_STATUS_ENCRYPTED_AND_COMPRESSED);
                else
                    m_doc
                            .setDataStatus(EncryptedData.DENC_DATA_STATUS_ENCRYPTED_AND_NOT_COMPRESSED); // ???
            }
            m_sbCollectChars = null; // stop collecting
        }
        // <EncryptionProperty>
        if (tName.equals("EncryptionProperty"))
        {
            checkEncryptedData();
            EncryptionProperty eprop = m_doc.getLastProperty();
            try
            {
                eprop.setContent(m_sbCollectChars.toString());
            }
            catch (DigiDocException ex)
            {
                SAXDigiDocException.handleException(ex);
            }
            m_sbCollectChars = null; // stop collecting
        }

    }

    /**
     * SAX characters event handler
     * 
     * @param buf
     *            received bytes array
     * @param offset
     *            offset to the array
     * @param len
     *            length of data
     */
    public void characters(char buf[], int offset, int len) throws SAXException
    {
        String s = new String(buf, offset, len);
        // System.out.println("Chars: " + s);
        // just collect the data since it could
        // be on many lines and be processed in many events
        if (s != null)
        {
            if (m_sbCollectChars != null)
                m_sbCollectChars.append(s);
        }
    }

}
