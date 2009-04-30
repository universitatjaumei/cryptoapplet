/*
 * EncryptionProperty.java
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
package es.uji.dsign.crypto.digidoc.xmlenc;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.util.ArrayList;

import es.uji.dsign.crypto.digidoc.DigiDocException;
import es.uji.dsign.crypto.digidoc.utils.ConvertUtils;

/**
 * Contains the data of an <EncryptionProperty> subelement of an <EncryptedData> object
 * 
 * @author Veiko Sinivee
 * @version 1.0
 */
public class EncryptionProperty implements Serializable
{
    /** Id atribute value (optional) */
    private String m_id;
    /** Target atribute value (optional) */
    private String m_target;
    /** Name atribute value (required in this implementation) */
    private String m_name;
    /** encryption property value itself (required) */
    private String m_content;
    /** we use this property to store the original filename of the encrypted file */
    public static String ENCPROP_FILENAME = "Filename";
    /** we use this property to store the original size of encrypted file */
    public static String ENCPROP_ORIG_SIZE = "OriginalSize";
    /** we use this property to store the original mime type of encrypted file */
    public static String ENCPROP_ORIG_MIME = "OriginalMimeType";

    /**
     * Default constructor for EncryptionProperty object. This should be used only in parser because
     * it intializes instance variable to default values that might be an invalid object state
     */
    public EncryptionProperty()
    {
        m_id = null;
        m_target = null;
        m_name = null;
        m_content = null;
    }

    /**
     * Constructor for EncryptionProperty object
     * 
     * @param name
     *            Name atribute value (required in this implementation)
     * @param content
     *            encryption property value itself (required)
     * @throws DigiDocException
     *             for validation errors
     */
    public EncryptionProperty(String name, String content) throws DigiDocException
    {
        setName(name);
        setContent(content);
    }

    /**
     * Constructor for EncryptionProperty object
     * 
     * @param id
     *            Id atribute value (optional)
     * @param target
     *            Target atribute value (optional)
     * @param name
     *            Name atribute value (required in this implementation)
     * @param content
     *            encryption property value itself (required)
     * @throws DigiDocException
     *             for validation errors
     */
    public EncryptionProperty(String id, String target, String name, String content)
            throws DigiDocException
    {
        setId(id);
        setTarget(target);
        setName(name);
        setContent(content);
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
     * Accessor for Target attribute
     * 
     * @return value of Target attribute
     */
    public String getTarget()
    {
        return m_target;
    }

    /**
     * Mutator for Target attribute
     * 
     * @param str
     *            new value for Target attribute
     */
    public void setTarget(String str)
    {
        m_target = str;
    }

    /**
     * Accessor for Name attribute
     * 
     * @return value of Name attribute
     */
    public String getName()
    {
        return m_name;
    }

    /**
     * Mutator for Name attribute
     * 
     * @param str
     *            new value for Name attribute
     * @throws DigiDocException
     *             for validation errors
     */
    public void setName(String str) throws DigiDocException
    {
        DigiDocException ex = validateName(str);
        if (ex != null)
            throw ex;
        m_name = str;
    }

    /**
     * Helper method to validate Name atribute
     * 
     * @param str
     *            input data
     * @return exception or null for ok
     */
    private DigiDocException validateName(String str)
    {
        DigiDocException ex = null;
        if (str == null)
            ex = new DigiDocException(DigiDocException.ERR_XMLENC_ENCPROP_NAME,
                    "Name atribute is required", null);
        return ex;
    }

    /**
     * Accessor for Content attribute
     * 
     * @return value of Content attribute
     */
    public String getContent()
    {
        return m_content;
    }

    /**
     * Mutator for Content attribute
     * 
     * @param str
     *            new value for Content attribute
     * @throws DigiDocException
     *             for validation errors
     */
    public void setContent(String str) throws DigiDocException
    {
        DigiDocException ex = validateContent(str);
        if (ex != null)
            throw ex;
        m_content = str;
    }

    /**
     * Helper method to validate Content atribute
     * 
     * @param str
     *            input data
     * @return exception or null for ok
     */
    private DigiDocException validateContent(String str)
    {
        DigiDocException ex = null;
        if (str == null)
            ex = new DigiDocException(DigiDocException.ERR_XMLENC_ENCPROP_CONTENT,
                    "content of <EncryptionProperty> element is required", null);
        return ex;
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
            bos.write(ConvertUtils.str2data("<denc:EncryptionProperty"));
            if (m_id != null)
                bos.write(ConvertUtils.str2data(" Id=\"" + m_id + "\""));
            if (m_target != null)
                bos.write(ConvertUtils.str2data(" Target=\"" + m_target + "\""));
            if (m_name != null)
                bos.write(ConvertUtils.str2data(" Name=\"" + m_name + "\""));
            bos.write(ConvertUtils.str2data(">"));
            if (m_name != null)
                bos.write(ConvertUtils.str2data(m_content));
            bos.write(ConvertUtils.str2data("</denc:EncryptionProperty>"));
        }
        catch (IOException ex)
        {
            DigiDocException.handleException(ex, DigiDocException.ERR_XML_CONVERT);
        }
        return bos.toByteArray();
    }

    /**
     * Helper method to validate the whole EncrypteionProperty object
     * 
     * @return a possibly empty list of DigiDocException objects
     */
    public ArrayList validate()
    {
        ArrayList errs = new ArrayList();
        DigiDocException ex = validateName(m_name);
        if (ex != null)
            errs.add(ex);
        ex = validateContent(m_content);
        if (ex != null)
            errs.add(ex);
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
