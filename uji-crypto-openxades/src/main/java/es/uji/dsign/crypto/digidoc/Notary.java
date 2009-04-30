/*
 * Notary.java
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
import java.util.Date;

import es.uji.dsign.crypto.digidoc.utils.ConvertUtils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * Models an OCSP confirmation of the validity of a given signature in the given context.
 * 
 * @author Veiko Sinivee
 * @version 1.0
 */
public class Notary implements Serializable
{
    /** notary id (in XML) */
    private String m_id;
    /** OCSP response data */
    private byte[] m_ocspResponseData;
    /** OCSP responder id */
    private String m_responderId;
    /** response production timestamp */
    private Date m_producedAt;
    /** certificate serial number used for this notary */
    private String m_certNr;

    /**
     * Creates new Notary and initializes everything to null
     */
    public Notary()
    {
        m_ocspResponseData = null;
        m_id = null;
        m_responderId = null;
        m_producedAt = null;
        m_certNr = null;
    }

    /**
     * Creates new Notary and
     * 
     * @param id
     *            new Notary id
     * @param resp
     *            OCSP response data
     */
    public Notary(String id, byte[] resp, String respId, Date prodAt)
    {
        m_ocspResponseData = resp;
        m_id = id;
        m_responderId = respId;
        m_producedAt = prodAt;
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
    public void setId(String str)
    // throws DigiDocException
    {
        // DigiDocException ex = validateId(str);
        // if(ex != null)
        // throw ex;
        m_id = str;
    }

    /**
     * Accessor for certNr attribute
     * 
     * @return value of certNr attribute
     */
    public String getCertNr()
    {
        return m_certNr;
    }

    /**
     * Mutator for certNr attribute
     * 
     * @param nr
     *            new value of certNr attribute
     */
    public void setCertNr(String nr)
    {
        m_certNr = nr;
    }

    /**
     * Accessor for producedAt attribute
     * 
     * @return value of producedAt attribute
     */
    public Date getProducedAt()
    {
        return m_producedAt;
    }

    /**
     * Mutator for producedAt attribute
     * 
     * @param dt
     *            new value for producedAt attribute
     */
    public void setProducedAt(Date dt)
    {
        m_producedAt = dt;
    }

    /**
     * Accessor for responderId attribute
     * 
     * @return value of responderId attribute
     */
    public String getResponderId()
    {
        return m_responderId;
    }

    /**
     * Mutator for responderId attribute
     * 
     * @param str
     *            new value for responderId attribute
     */
    public void setResponderId(String str)
    {
        m_responderId = str;
    }

    /**
     * Mutator for ocspResponseData attribute
     * 
     * @param data
     *            new value for ocspResponseData attribute
     */
    public void setOcspResponseData(byte[] data)
    {
        m_ocspResponseData = data;
    }

    /**
     * Accessor for ocspResponseData attribute
     * 
     * @return value of ocspResponseData attribute
     */
    public byte[] getOcspResponseData()
    {
        return m_ocspResponseData;
    }

    /**
     * Helper method to validate the whole SignedProperties object
     * 
     * @return a possibly empty list of DigiDocException objects
     */
    public ArrayList validate()
    {
        ArrayList errs = new ArrayList();

        return errs;
    }

    /**
     * Converts the Notary to XML form
     * 
     * @return XML representation of Notary
     */
    public byte[] toXML(String ver) throws DigiDocException
    {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try
        {
            bos.write(ConvertUtils.str2data("<RevocationValues>"));
            if (ver.equals(SignedDoc.VERSION_1_3))
                bos.write(ConvertUtils.str2data("<OCSPValues>"));
            bos.write(ConvertUtils.str2data("<EncapsulatedOCSPValue Id=\""));
            bos.write(ConvertUtils.str2data(m_id));
            bos.write(ConvertUtils.str2data("\">\n"));
            bos.write(ConvertUtils.str2data(Base64Util.encode(m_ocspResponseData, 64)));
            bos.write(ConvertUtils.str2data("</EncapsulatedOCSPValue>\n"));
            if (ver.equals(SignedDoc.VERSION_1_3))
                bos.write(ConvertUtils.str2data("</OCSPValues>"));
            bos.write(ConvertUtils.str2data("</RevocationValues>"));
        }
        catch (IOException ex)
        {
            DigiDocException.handleException(ex, DigiDocException.ERR_XML_CONVERT);
        }
        return bos.toByteArray();
    }

    /**
     * Returns the stringified form of Notary
     * 
     * @return Notary string representation
     */
    public String toString()
    {
        String str = null;
        try
        {
            str = new String(toXML(SignedDoc.VERSION_1_3));
        }
        catch (Exception ex)
        { // cannot throw any exception!!!
        }
        return str;
    }
}
