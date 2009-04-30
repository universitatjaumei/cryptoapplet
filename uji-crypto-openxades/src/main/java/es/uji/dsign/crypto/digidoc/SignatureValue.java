/*
 * SignatureValue.java
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

package es.uji.dsign.crypto.digidoc;

import java.io.Serializable;
import java.util.ArrayList;

import es.uji.dsign.crypto.digidoc.utils.ConvertUtils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * Models the SignatureValue element of XML-DSIG
 * 
 * @author Veiko Sinivee
 * @version 1.0
 */
public class SignatureValue implements Serializable
{
    /** signature value id */
    private String m_id;
    /** actual signature value data */
    private byte[] m_value;

    /** RSA signatures have 128 bytes */
    public static final int SIGNATURE_VALUE_LENGTH = 128;

    /**
     * Creates new SignatureValue
     */
    public SignatureValue()
    {
        m_id = null;
        m_value = null;
    }

    /**
     * Creates new SignatureValue
     * 
     * @param id
     *            SignatureValue id
     * @param value
     *            actual RSA signature value
     * @throws DigiDocException
     *             for validation errors
     */
    public SignatureValue(String id, byte[] value) throws DigiDocException
    {
        setId(id);
        setValue(value);
    }

    /**
     * Creates new SignatureValue
     * 
     * @param id
     *            SignatureValue id
     * @param value
     *            actual RSA signature value
     * @throws DigiDocException
     *             for validation errors
     */
    public SignatureValue(Signature sig, byte[] value) throws DigiDocException
    {
        setId(sig.getId() + "-SIG");
        setValue(value);
    }

    /**
     * Accessor for id attribute
     * 
     * @return value of id attribute
     */
    public String getId()
    {
        return m_id;
    }

    /**
     * Mutator for id attribute
     * 
     * @param str
     *            new value for id attribute
     * @throws DigiDocException
     *             for validation errors
     */
    public void setId(String str) throws DigiDocException
    {
        DigiDocException ex = validateId(str);
        if (ex != null)
            throw ex;
        m_id = str;
    }

    /**
     * Helper method to validate an id
     * 
     * @param str
     *            input data
     * @return exception or null for ok
     */
    private DigiDocException validateId(String str)
    {
        DigiDocException ex = null;
        if (str == null)
            ex = new DigiDocException(DigiDocException.ERR_SIGNATURE_VALUE_ID,
                    "Id is a required attribute", null);
        return ex;
    }

    /**
     * Accessor for value attribute
     * 
     * @return value of value attribute
     */
    public byte[] getValue()
    {
        return m_value;
    }

    /**
     * Mutator for value attribute
     * 
     * @param str
     *            new value for value attribute
     * @throws DigiDocException
     *             for validation errors
     */
    public void setValue(byte[] data) throws DigiDocException
    {
        DigiDocException ex = validateValue(data);
        if (ex != null)
            throw ex;
        m_value = data;
    }

    /**
     * Helper method to validate a signature value
     * 
     * @param str
     *            input data
     * @return exception or null for ok
     */
    private DigiDocException validateValue(byte[] value)
    {
        DigiDocException ex = null;
        if (value == null || value.length < SIGNATURE_VALUE_LENGTH)
            ex = new DigiDocException(DigiDocException.ERR_SIGNATURE_VALUE_ID,
                    "RSA signature value must be at least 128 bytes", null);
        return ex;
    }

    /**
     * Helper method to validate the whole SignatureValue object
     * 
     * @return a possibly empty list of DigiDocException objects
     */
    public ArrayList validate()
    {
        ArrayList errs = new ArrayList();
        DigiDocException ex = validateId(m_id);
        if (ex != null)
            errs.add(ex);
        ex = validateValue(m_value);
        if (ex != null)
            errs.add(ex);
        return errs;
    }

    /**
     * Converts the SignatureValue to XML form
     * 
     * @return XML representation of SignatureValue
     */
    public byte[] toXML() throws DigiDocException
    {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try
        {
            bos.write(ConvertUtils.str2data("<SignatureValue Id=\""));
            bos.write(ConvertUtils.str2data(m_id));
            bos.write(ConvertUtils.str2data("\">"));
            bos.write(ConvertUtils.str2data(Base64Util.encode(m_value, 64)));
            bos.write(ConvertUtils.str2data("</SignatureValue>"));
        }
        catch (IOException ex)
        {
            DigiDocException.handleException(ex, DigiDocException.ERR_XML_CONVERT);
        }
        return bos.toByteArray();
    }

    /**
     * Returns the stringified form of SignatureValue
     * 
     * @return SignatureValue string representation
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
