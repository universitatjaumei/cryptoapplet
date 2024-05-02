/*
 * CompleteRevocationRefs.java
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
import java.util.Date;
import java.util.ArrayList;

import es.uji.security.crypto.openxades.digidoc.utils.ConvertUtils;
import es.uji.security.util.Base64;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * Models the ETSI CompleteRevocationRefs element This contains some data from the OCSP response and
 * it's digest
 * 
 * @author Veiko Sinivee
 * @version 1.0
 */
public class CompleteRevocationRefs implements Serializable
{
    /** <OCSPIdentifier> URI attribute */
    private String m_uri;
    /** <ResponderId> element */
    private String m_responderId;
    /** ProducedAt element */
    private Date m_producedAt;
    /** digesta lgorithm uri/id */
    private String m_digestAlgorithm;
    /** digest value */
    private byte[] m_digestValue;
    /** parent object - UnsignedProperties ref */
    private UnsignedProperties m_unsignedProps;

    /**
     * Creates new CompleteRevocationRefs Initializes everything to null
     */
    public CompleteRevocationRefs()
    {
        m_uri = null;
        m_responderId = null;
        m_producedAt = null;
        m_digestAlgorithm = null;
        m_digestValue = null;
        m_unsignedProps = null;
    }

    /**
     * Creates new CompleteRevocationRefs
     * 
     * @param uri
     *            notary uri value
     * @param respId
     *            responder id
     * @param producedAt
     *            OCSP producedAt timestamp
     * @param digAlg
     *            notary digest algorithm
     * @param digest
     *            notary digest
     * @throws DigiDocException
     *             for validation errors
     */
    public CompleteRevocationRefs(String uri, String respId, Date producedAt, String digAlg,
            byte[] digest) throws DigiDocException
    {
        setUri(uri);
        setResponderId(respId);
        setProducedAt(producedAt);
        setDigestAlgorithm(digAlg);
        setDigestValue(digest);
    }

    /**
     * Creates new CompleteRevocationRefs by using data from an existing Notary object
     * 
     * @param not
     *            Notary object
     * @throws DigiDocException
     *             for validation errors
     */
    public CompleteRevocationRefs(Notary not) throws DigiDocException
    {
        setUri("#" + not.getId());
        setResponderId(not.getResponderId());
        setProducedAt(not.getProducedAt());
        setDigestAlgorithm(SignedDoc.SHA256_DIGEST_ALGORITHM);
        byte[] digest = null;
        try
        {
            byte[] ocspData = not.getOcspResponseData();
            digest = SignedDoc.digest(ocspData, "SHA-256");
            // System.out.println("OCSP data len: " + ocspData.length);
            // System.out.println("Calculated digest: " + Base64Util.encode(digest, 0));
        }
        catch (Exception ex)
        {
            DigiDocException.handleException(ex, DigiDocException.ERR_CALCULATE_DIGEST);
        }
        setDigestValue(digest);
    }

    /**
     * Accessor for UnsignedProperties attribute
     * 
     * @return value of UnsignedProperties attribute
     */
    public UnsignedProperties getUnsignedProperties()
    {
        return m_unsignedProps;
    }

    /**
     * Mutator for UnsignedProperties attribute
     * 
     * @param uprops
     *            value of UnsignedProperties attribute
     */
    public void setUnsignedProperties(UnsignedProperties uprops)
    {
        m_unsignedProps = uprops;
    }

    /**
     * Accessor for uri attribute
     * 
     * @return value of uri attribute
     */
    public String getUri()
    {
        return m_uri;
    }

    /**
     * Mutator for uri attribute
     * 
     * @param str
     *            new value for uri attribute
     * @throws DigiDocException
     *             for validation errors
     */
    public void setUri(String str) throws DigiDocException
    {
        DigiDocException ex = validateUri(str);
        if (ex != null)
            throw ex;
        m_uri = str;
    }

    /**
     * Helper method to validate an uri
     * 
     * @param str
     *            input data
     * @return exception or null for ok
     */
    private DigiDocException validateUri(String str)
    {
        DigiDocException ex = null;
        if (str == null)
            ex = new DigiDocException(DigiDocException.ERR_REVREFS_URI,
                    "Notary uri must be in form: #<notary-id>", null);
        return ex;
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
     * @throws DigiDocException
     *             for validation errors
     */
    public void setResponderId(String str) throws DigiDocException
    {
        DigiDocException ex = validateResponderId(str);
        if (ex != null)
            throw ex;
        m_responderId = str;
    }

    /**
     * Returns reponder-ids CN
     * 
     * @returns reponder-ids CN or null
     */
    public String getResponderCommonName()
    {
        String name = null;
        if (m_responderId != null)
        {
            int idx1 = m_responderId.indexOf("CN=");
            if (idx1 != -1)
            {
                idx1 += 2;
                while (idx1 < m_responderId.length()
                        && !Character.isLetter(m_responderId.charAt(idx1)))
                    idx1++;
                int idx2 = idx1;
                while (idx2 < m_responderId.length() && m_responderId.charAt(idx2) != ','
                        && m_responderId.charAt(idx2) != '/')
                    idx2++;
                name = m_responderId.substring(idx1, idx2);
            }
        }
        return name;
    }

    /**
     * Helper method to validate a ResponderId
     * 
     * @param str
     *            input data
     * @return exception or null for ok
     */
    private DigiDocException validateResponderId(String str)
    {
        DigiDocException ex = null;
        if (str == null)
            ex = new DigiDocException(DigiDocException.ERR_REVREFS_RESP_ID,
                    "ResponderId cannot be empty!", null);
        return ex;
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
     * @param str
     *            new value for producedAt attribute
     * @throws DigiDocException
     *             for validation errors
     */
    public void setProducedAt(Date d) throws DigiDocException
    {
        DigiDocException ex = validateProducedAt(d);
        if (ex != null)
            throw ex;
        m_producedAt = d;
    }

    /**
     * Helper method to validate producedAt timestamp
     * 
     * @param str
     *            input data
     * @return exception or null for ok
     */
    private DigiDocException validateProducedAt(Date d)
    {
        DigiDocException ex = null;
        if (d == null)
            ex = new DigiDocException(DigiDocException.ERR_REVREFS_PRODUCED_AT,
                    "ProducedAt timestamp cannot be empty!", null);
        return ex;
    }

    /**
     * Accessor for digestAlgorithm attribute
     * 
     * @return value of digestAlgorithm attribute
     */
    public String getDigestAlgorithm()
    {
        return m_digestAlgorithm;
    }

    /**
     * Mutator for digestAlgorithm attribute
     * 
     * @param str
     *            new value for digestAlgorithm attribute
     * @throws DigiDocException
     *             for validation errors
     */
    public void setDigestAlgorithm(String str) throws DigiDocException
    {
        DigiDocException ex = validateDigestAlgorithm(str);
        if (ex != null)
            throw ex;
        m_digestAlgorithm = str;
    }

    /**
     * Helper method to validate a digest algorithm
     * 
     * @param str
     *            input data
     * @return exception or null for ok
     */
    private DigiDocException validateDigestAlgorithm(String str)
    {
        DigiDocException ex = null;
        if (str == null || (!str.equals(SignedDoc.SHA256_DIGEST_ALGORITHM) && !str.equals(SignedDoc.SHA1_DIGEST_ALGORITHM)))
            ex = new DigiDocException(DigiDocException.ERR_CERT_DIGEST_ALGORITHM,
                    "Currently supports only SHA256 digest algorithm", null);
        return ex;
    }

    /**
     * Accessor for digestValue attribute
     * 
     * @return value of digestValue attribute
     */
    public byte[] getDigestValue()
    {
        return m_digestValue;
    }

    /**
     * Mutator for digestValue attribute
     * 
     * @param data
     *            new value for digestValue attribute
     * @throws DigiDocException
     *             for validation errors
     */
    public void setDigestValue(byte[] data) throws DigiDocException
    {
        DigiDocException ex = validateDigestValue(data);
        if (ex != null)
            throw ex;
        m_digestValue = data;
    }

    /**
     * Helper method to validate a digest value
     * 
     * @param data
     *            input data
     * @return exception or null for ok
     */
    private DigiDocException validateDigestValue(byte[] data)
    {
        DigiDocException ex = null;
        if (data == null || (m_digestAlgorithm.equals(SignedDoc.SHA256_DIGEST_ALGORITHM) && data.length != SignedDoc.SHA256_DIGEST_LENGTH
                || (m_digestAlgorithm.equals(SignedDoc.SHA1_DIGEST_ALGORITHM) && data.length != SignedDoc.SHA1_DIGEST_LENGTH)))
            ex = new DigiDocException(DigiDocException.ERR_DIGEST_LENGTH,
                    "SHA1 digest data is always 20 bytes of length and SHA256 digest data is always 32 bytes of length", null);
        return ex;
    }

    /**
     * Helper method to validate the whole CompleteRevocationRefs object
     * 
     * @return a possibly empty list of DigiDocException objects
     */
    public ArrayList validate()
    {
        ArrayList errs = new ArrayList();
        DigiDocException ex = validateUri(m_uri);
        if (ex != null)
            errs.add(ex);
        ex = validateResponderId(m_responderId);
        if (ex != null)
            errs.add(ex);
        ex = validateProducedAt(m_producedAt);
        if (ex != null)
            errs.add(ex);
        ex = validateDigestAlgorithm(m_digestAlgorithm);
        if (ex != null)
            errs.add(ex);
        ex = validateDigestValue(m_digestValue);
        if (ex != null)
            errs.add(ex);
        return errs;
    }

    /**
     * Converts the CompleteRevocationRefs to XML form
     * 
     * @return XML representation of CompleteRevocationRefs
     */
    public byte[] toXML() throws DigiDocException
    {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try
        {
            bos.write(ConvertUtils.str2data("<CompleteRevocationRefs>\n"));
            bos.write(ConvertUtils.str2data("<OCSPRefs>\n<OCSPRef>\n"));
            bos.write(ConvertUtils.str2data("<OCSPIdentifier URI=\""));
            bos.write(ConvertUtils.str2data(m_uri));
            bos.write(ConvertUtils.str2data("\">\n<ResponderID>"));
            bos.write(ConvertUtils.str2data(m_responderId));
            bos.write(ConvertUtils.str2data("</ResponderID>\n<ProducedAt>"));
            bos.write(ConvertUtils.str2data(ConvertUtils.date2string(m_producedAt, m_unsignedProps
                    .getSignature().getSignedDoc())));
            bos
                    .write(ConvertUtils
                            .str2data("</ProducedAt>\n</OCSPIdentifier>\n<DigestAlgAndValue>\n<DigestMethod Algorithm=\""));
            bos.write(ConvertUtils.str2data(m_digestAlgorithm));
            bos.write(ConvertUtils.str2data("\"></DigestMethod>\n<DigestValue>"));
            bos.write(ConvertUtils.str2data(Base64.encodeBytes(m_digestValue)));
            bos.write(ConvertUtils.str2data("</DigestValue>\n</DigestAlgAndValue>"));
            bos.write(ConvertUtils.str2data("</OCSPRef>\n</OCSPRefs>\n"));
            bos.write(ConvertUtils.str2data("</CompleteRevocationRefs>"));
        }
        catch (IOException ex)
        {
            DigiDocException.handleException(ex, DigiDocException.ERR_XML_CONVERT);
        }
        return bos.toByteArray();
    }

    /**
     * Returns the stringified form of CompleteRevocationRefs
     * 
     * @return CompleteRevocationRefs string representation
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
