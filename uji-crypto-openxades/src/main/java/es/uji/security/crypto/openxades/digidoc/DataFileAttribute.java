/*
 * DataFileAttribute.java
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

package es.uji.security.crypto.openxades.digidoc;

import java.io.Serializable;
import java.util.ArrayList;

//import ee.sk.utils.ConvertUtils;

/**
 * Represents and additional DataFile attribute. All DataFile attributes will be signed.
 * 
 * @author Veiko Sinivee
 * @version 1.0
 */
public class DataFileAttribute implements Serializable
{
    /** attribute name */
    private String m_name;
    /** attribute value */
    private String m_value;

    /**
     * Creates new DataFileAttribute
     * 
     * @param name
     *            attribute name
     * @param value
     *            attribute value
     * @throws DigiDocException
     *             for validation errors
     */
    public DataFileAttribute(String name, String value) throws DigiDocException
    {
        setName(name);
        setValue(value);
    }

    /**
     * Accessor for name attribute
     * 
     * @return value of name attribute
     */
    public String getName()
    {
        return m_name;
    }

    /**
     * Mutator for name attribute
     * 
     * @param str
     *            new value for name attribute
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
     * Helper method to validate attribute name
     * 
     * @param str
     *            input data
     * @return exception or null for ok
     */
    private DigiDocException validateName(String str)
    {
        DigiDocException ex = null;
        if (str == null)
            ex = new DigiDocException(DigiDocException.ERR_DATA_FILE_ATTR_NAME,
                    "Attribute name is required", null);
        return ex;
    }

    /**
     * Accessor for value attribute
     * 
     * @return value of value attribute
     */
    public String getValue()
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
    public void setValue(String str) throws DigiDocException
    {
        DigiDocException ex = validateValue(str);
        if (ex != null)
            throw ex;
        m_value = str;
    }

    /**
     * Helper method to validate attribute value
     * 
     * @param str
     *            input data
     * @return exception or null for ok
     */
    private DigiDocException validateValue(String str)
    {
        DigiDocException ex = null;
        if (str == null)
            ex = new DigiDocException(DigiDocException.ERR_DATA_FILE_ATTR_VALUE,
                    "Attribute value is required", null);
        return ex;
    }

    /**
     * Helper method to validate the whole DataFileAttribute object
     * 
     * @return a possibly empty list of DigiDocException objects
     */
    public ArrayList validate()
    {
        ArrayList errs = new ArrayList();
        DigiDocException ex = validateName(m_name);
        if (ex != null)
            errs.add(ex);
        ex = validateValue(m_value);
        if (ex != null)
            errs.add(ex);
        return errs;
    }

    /**
     * Converts the SignedInfo to XML form
     * 
     * @return XML representation of SignedInfo
     */
    public String toXML() throws DigiDocException
    {
        StringBuffer sb = new StringBuffer(m_name);
        sb.append("=\"");
        sb.append(m_value);
        sb.append("\"");
        return sb.toString();
    }

    /**
     * Returns the stringified form of SignedInfo
     * 
     * @return SignedInfo string representation
     */
    public String toString()
    {
        String str = null;
        try
        {
            str = toXML();
        }
        catch (Exception ex)
        {
        }
        return str;
    }
}
