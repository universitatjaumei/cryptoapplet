/*
 * CertValue.java
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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import es.uji.security.crypto.openxades.digidoc.utils.ConvertUtils;
import es.uji.security.util.Base64;

/**
 * Models the ETSI <X509Certificate> and <EncapsulatedX509Certificate> elements. Holds certificate
 * data. Such elements will be serialized under the <CertificateValues> and <X509Data> elements
 * 
 * @author Veiko Sinivee
 * @version 1.0
 */
public class CertValue
{
    /** elements id atribute if present */
    private String m_id;
    /** parent object - Signature ref */
    private Signature m_signature;
    /** CertID type - signer, responder, tsa */
    private int m_type;
    /** certificate */
    private X509Certificate m_cert;

    /** possible cert value type values */
    public static final int CERTVAL_TYPE_UNKNOWN = 0;
    public static final int CERTVAL_TYPE_SIGNER = 1;
    public static final int CERTVAL_TYPE_RESPONDER = 2;
    public static final int CERTVAL_TYPE_TSA = 3;

    /**
     * Creates new CertValue and initializes everything to null
     */
    public CertValue()
    {
        m_id = null;
        m_signature = null;
        m_cert = null;
        m_type = CERTVAL_TYPE_UNKNOWN;
    }

    /**
     * Accessor for Signature attribute
     * 
     * @return value of Signature attribute
     */
    public Signature getSignature()
    {
        return m_signature;
    }

    /**
     * Mutator for Signature attribute
     * 
     * @param uprops
     *            value of Signature attribute
     */
    public void setSignature(Signature sig)
    {
        m_signature = sig;
    }

    /**
     * Accessor for id attribute
     * 
     * @return value of certId attribute
     */
    public String getId()
    {
        return m_id;
    }

    /**
     * Mutator for id attribute
     * 
     * @param str
     *            new value for certId attribute
     */
    public void setId(String str)
    {
        m_id = str;
    }

    /**
     * Accessor for type attribute
     * 
     * @return value of type attribute
     */
    public int getType()
    {
        return m_type;
    }

    /**
     * Mutator for type attribute
     * 
     * @param n
     *            new value for issuer attribute
     * @throws DigiDocException
     *             for validation errors
     */
    public void setType(int n) throws DigiDocException
    {
        DigiDocException ex = validateType(n);
        if (ex != null)
            throw ex;
        m_type = n;
    }

    /**
     * Helper method to validate type
     * 
     * @param n
     *            input data
     * @return exception or null for ok
     */
    private DigiDocException validateType(int n)
    {
        DigiDocException ex = null;
        if (n < 0 || n > CERTVAL_TYPE_TSA)
            ex = new DigiDocException(DigiDocException.ERR_CERTID_TYPE, "Invalid CertValue type",
                    null);
        return ex;
    }

    /**
     * Accessor for Cert attribute
     * 
     * @return value of Cert attribute
     */
    public X509Certificate getCert()
    {
        return m_cert;
    }

    /**
     * Mutator for Cert attribute
     * 
     * @param uprops
     *            value of Cert attribute
     */
    public void setCert(X509Certificate cert)
    {
        m_cert = cert;
    }

    /**
     * Converts the CompleteCertificateRefs to XML form
     * 
     * @return XML representation of CompleteCertificateRefs
     */
    public byte[] toXML() throws DigiDocException
    {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try
        {
            if (m_type == CERTVAL_TYPE_SIGNER)
            {
                bos.write(ConvertUtils.str2data("<X509Certificate>"));
                try
                {
                    bos.write(ConvertUtils.str2data(Base64.encodeBytes(m_cert.getEncoded())));
                }
                catch (CertificateEncodingException ex)
                {
                    DigiDocException.handleException(ex, DigiDocException.ERR_ENCODING);
                }
                bos.write(ConvertUtils.str2data("</X509Certificate>"));
            }
            if (m_type == CERTVAL_TYPE_RESPONDER || m_type == CERTVAL_TYPE_TSA)
            {
                bos.write(ConvertUtils.str2data("<EncapsulatedX509Certificate Id=\""));
                bos.write(ConvertUtils.str2data(m_id));
                bos.write(ConvertUtils.str2data("\">\n"));
                try
                {
                    bos.write(ConvertUtils.str2data(Base64.encodeBytes(m_cert.getEncoded())));
                }
                catch (CertificateEncodingException ex)
                {
                    DigiDocException.handleException(ex, DigiDocException.ERR_ENCODING);
                }
                bos.write(ConvertUtils.str2data("</EncapsulatedX509Certificate>\n"));

            }
        }
        catch (IOException ex)
        {
            DigiDocException.handleException(ex, DigiDocException.ERR_XML_CONVERT);
        }
        return bos.toByteArray();
    }

    /**
     * Returns the stringified form of CompleteCertificateRefs
     * 
     * @return CompleteCertificateRefs string representation
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
