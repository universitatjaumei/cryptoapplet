/*
 * EncryptionProperties.java
 * PROJECT: JDigiDoc
 * DESCRIPTION: a set of properties of encrypted object 
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

import java.io.Serializable;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import es.uji.security.crypto.openxades.digidoc.DigiDocException;
import es.uji.security.crypto.openxades.digidoc.utils.ConvertUtils;

import java.util.ArrayList;

/**
 * Contains the data of an <EncryptionProperties> subelement of an <EncryptedData> object. This
 * element in turn can contain one or many <EncryptionProperty> sublements and it can have an Id
 * atribute
 * 
 * @author Veiko Sinivee
 * @version 1.0
 */
public class EncryptionProperties implements Serializable
{
    /** Id atribute value (optional) */
    private String m_id;
    /** array of encryption properties */
    private ArrayList m_arrProperties;

    /**
     * Constructor for EncryptionProperties object
     * 
     * @param id
     *            Id atribute value (optional)
     */
    public EncryptionProperties(String id)
    {
        setId(id);
        m_arrProperties = null;
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
     * Adds an <EncryptionProperty> object to the array of properties
     * 
     * @param prop
     *            new property object to be added
     */
    public void addProperty(EncryptionProperty prop)
    {
        if (m_arrProperties == null)
            m_arrProperties = new ArrayList();
        m_arrProperties.add(prop);
    }

    /**
     * Rturns the number of <EncryptionProperty> objects in the list
     * 
     * @return number of <EncryptionProperty> objects
     */
    public int getNumProperties()
    {
        return ((m_arrProperties == null) ? 0 : m_arrProperties.size());
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
            return (EncryptionProperty) m_arrProperties.get(nIdx);
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
        for (int i = 0; (m_arrProperties != null) && (i < m_arrProperties.size()); i++)
        {
            EncryptionProperty prop = (EncryptionProperty) m_arrProperties.get(i);
            if (prop.getId() != null && prop.getId().equals(id))
                return prop;
        }
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
        for (int i = 0; (m_arrProperties != null) && (i < m_arrProperties.size()); i++)
        {
            EncryptionProperty prop = (EncryptionProperty) m_arrProperties.get(i);
            if (prop.getName() != null && prop.getName().equals(name))
                return prop;
        }
        return null;
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
            bos.write(ConvertUtils.str2data("<denc:EncryptionProperties"));
            if (m_id != null)
            {
                bos.write(ConvertUtils.str2data(" Id=\"" + m_id + "\""));
            }
            bos.write(ConvertUtils.str2data(">"));
            for (int i = 0; i < getNumProperties(); i++)
            {
                EncryptionProperty prop = getProperty(i);
                bos.write(prop.toXML());
            }
            bos.write(ConvertUtils.str2data("</denc:EncryptionProperties>"));
        }
        catch (IOException ex)
        {
            DigiDocException.handleException(ex, DigiDocException.ERR_XML_CONVERT);
        }
        return bos.toByteArray();
    }

    /**
     * Helper method to validate the whole EncrypteionProperties object
     * 
     * @return a possibly empty list of DigiDocException objects
     */
    public ArrayList validate()
    {
        ArrayList errs = new ArrayList();
        for (int i = 0; i < getNumProperties(); i++)
        {
            EncryptionProperty eprop = getProperty(i);
            ArrayList e = eprop.validate();
            if (!e.isEmpty())
                errs.addAll(e);
        }
        ;
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
