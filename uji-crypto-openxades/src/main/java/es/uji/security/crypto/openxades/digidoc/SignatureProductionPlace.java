/*
 * SignatureProductionPlace.java
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

import es.uji.security.crypto.openxades.digidoc.utils.ConvertUtils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * Models the SignatureProductionPlace element of an XML-DSIG/ETSI Signature.
 * 
 * @author Veiko Sinivee
 * @version 1.0
 */
public class SignatureProductionPlace implements Serializable
{
    /** city name */
    private String m_city;
    /** state name */
    private String m_state;
    /** county name */
    private String m_country;
    /** postal code */
    private String m_zip;

    /**
     * Creates new SignatureProductionPlace Initializes everything to null
     */
    public SignatureProductionPlace()
    {
        m_city = null;
        m_state = null;
        m_country = null;
        m_zip = null;
    }

    /**
     * Creates new SignatureProductionPlace
     * 
     * @param city
     *            city name
     * @param state
     *            state or province name
     * @param country
     *            country name
     * @param zip
     *            postal code
     */
    public SignatureProductionPlace(String city, String state, String country, String zip)
    {
        m_city = city;
        m_state = state;
        m_country = country;
        m_zip = zip;
    }

    /**
     * Accessor for city attribute
     * 
     * @return value of city attribute
     */
    public String getCity()
    {
        return m_city;
    }

    /**
     * Mutator for city attribute
     * 
     * @param str
     *            new value for city attribute
     */
    public void setCity(String str)
    {
        m_city = str;
    }

    /**
     * Accessor for stateOrProvince attribute
     * 
     * @return value of stateOrProvince attribute
     */
    public String getStateOrProvince()
    {
        return m_state;
    }

    /**
     * Mutator for stateOrProvince attribute
     * 
     * @param str
     *            new value for stateOrProvince attribute
     */
    public void setStateOrProvince(String str)
    {
        m_state = str;
    }

    /**
     * Accessor for countryName attribute
     * 
     * @return value of countryName attribute
     */
    public String getCountryName()
    {
        return m_country;
    }

    /**
     * Mutator for countryName attribute
     * 
     * @param str
     *            new value for countryName attribute
     */
    public void setCountryName(String str)
    {
        m_country = str;
    }

    /**
     * Accessor for postalCode attribute
     * 
     * @return value of postalCode attribute
     */
    public String getPostalCode()
    {
        return m_zip;
    }

    /**
     * Mutator for postalCode attribute
     * 
     * @param str
     *            new value for postalCode attribute
     */
    public void setPostalCode(String str)
    {
        m_zip = str;
    }

    /**
     * Converts the SignatureProductionPlace to XML form
     * 
     * @return XML representation of SignatureProductionPlace
     */
    public byte[] toXML() throws DigiDocException
    {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        // just in case ...
        // make sure we only output if there is any data
        try
        {
            if (m_city != null || m_state != null || m_zip != null || m_country != null)
            {
                bos.write(ConvertUtils.str2data("<SignatureProductionPlace>\n"));
                if (m_city != null)
                {
                    bos.write(ConvertUtils.str2data("<City>"));
                    bos.write(ConvertUtils.str2data(m_city));
                    bos.write(ConvertUtils.str2data("</City>\n"));
                }
                if (m_state != null)
                {
                    bos.write(ConvertUtils.str2data("<StateOrProvince>"));
                    bos.write(ConvertUtils.str2data(m_state));
                    bos.write(ConvertUtils.str2data("</StateOrProvince>\n"));
                }
                if (m_zip != null)
                {
                    bos.write(ConvertUtils.str2data("<PostalCode>"));
                    bos.write(ConvertUtils.str2data(m_zip));
                    bos.write(ConvertUtils.str2data("</PostalCode>\n"));
                }
                if (m_country != null)
                {
                    bos.write(ConvertUtils.str2data("<CountryName>"));
                    bos.write(ConvertUtils.str2data(m_country));
                    bos.write(ConvertUtils.str2data("</CountryName>\n"));
                }
                bos.write(ConvertUtils.str2data("</SignatureProductionPlace>"));
            }
        }
        catch (IOException ex)
        {
            DigiDocException.handleException(ex, DigiDocException.ERR_XML_CONVERT);
        }
        return bos.toByteArray();
    }

    /**
     * Returns the stringified form of SignatureProductionPlace
     * 
     * @return SignatureProductionPlace string representation
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
