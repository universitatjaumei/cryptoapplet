/*
 * TimestampInfo.java
 * PROJECT: JDigiDoc
 * DESCRIPTION: Holds data about timestamp source. 
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
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Date;

import es.uji.security.crypto.openxades.digidoc.utils.ConvertUtils;
import es.uji.security.crypto.timestamp.TSResponse;
import es.uji.security.crypto.timestamp.TimestampToken;

//import org.bouncycastle.cms.SignerId;
//import org.bouncycastle.cms.CMSSignedData;

/**
 * Models the ETSI timestamp element(s) Holds timestamp info and TS_RESP response.
 * 
 * @author Veiko Sinivee
 * @version 1.0
 */
public class TimestampInfo
{
    /** elements Id atribute */
    private String m_id;
    /** parent object - Signature ref */
    private Signature m_signature;
    /** timestamp type */
    private int m_type;
    /** Include sublements */
    private ArrayList m_includes;
    /** timestamp response */
    private TSResponse m_tsResp;
    /** real hash calculated over the corresponding xml block */
    private byte[] m_hash;

    /** possible values for type atribute */
    public static final int TIMESTAMP_TYPE_UNKNOWN = 0;
    public static final int TIMESTAMP_TYPE_ALL_DATA_OBJECTS = 1;
    public static final int TIMESTAMP_TYPE_INDIVIDUAL_DATA_OBJECTS = 2;
    public static final int TIMESTAMP_TYPE_SIGNATURE = 3;
    public static final int TIMESTAMP_TYPE_SIG_AND_REFS = 4;
    public static final int TIMESTAMP_TYPE_REFS_ONLY = 5;
    public static final int TIMESTAMP_TYPE_ARCHIVE = 6;

    /**
     * Creates new TimestampInfo and initializes everything to null
     */
    public TimestampInfo()
    {
        m_id = null;
        m_signature = null;
        m_includes = null;
        m_tsResp = null;
        m_hash = null;
        m_type = TIMESTAMP_TYPE_UNKNOWN;
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
     * Creates new TimestampInfo
     * 
     * @param id
     *            Id atribute value
     * @param type
     *            timestamp type
     * @throws DigiDocException
     *             for validation errors
     */
    public TimestampInfo(String id, int type) throws DigiDocException
    {
        setId(id);
        setType(type);
        m_includes = null;
    }

    /**
     * Accessor for Hash attribute
     * 
     * @return value of Hash attribute
     */
    public byte[] getHash()
    {
        return m_hash;
    }

    /**
     * Mutator for Hash attribute
     * 
     * @param str
     *            new value for Hash attribute
     */
    public void setHash(byte[] b)
    {
        m_hash = b;
    }

    /**
     * Accessor for Id attribute
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
     * Helper method to validate Id
     * 
     * @param str
     *            input data
     * @return exception or null for ok
     */
    private DigiDocException validateId(String str)
    {
        DigiDocException ex = null;
        if (str == null)
            ex = new DigiDocException(DigiDocException.ERR_TIMESTAMP_ID,
                    "Id atribute cannot be empty", null);
        return ex;
    }

    /**
     * Accessor for Type attribute
     * 
     * @return value of Type attribute
     */
    public int getType()
    {
        return m_type;
    }

    /**
     * Mutator for Type attribute
     * 
     * @param n
     *            new value for Type attribute
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
     * Helper method to validate Type
     * 
     * @param n
     *            input data
     * @return exception or null for ok
     */
    private DigiDocException validateType(int n)
    {
        DigiDocException ex = null;
        if (n < TIMESTAMP_TYPE_ALL_DATA_OBJECTS || n > TIMESTAMP_TYPE_ARCHIVE)
            ex = new DigiDocException(DigiDocException.ERR_TIMESTAMP_TYPE,
                    "Invalid timestamp type", null);
        return ex;
    }

    /**
     * Accessor for TimeStampResponse attribute
     * 
     * @return value of TimeStampResponse attribute
     */
    public TSResponse getTimeStampResponse()
    {
        return m_tsResp;
    }

    /**
     * Mutator for TimeStampResponse attribute
     * 
     * @param tsr
     *            new value for TimeStampResponse attribute
     * @throws DigiDocException
     *             for validation errors
     */
    public void setTimeStampResponse(TSResponse tsr) throws DigiDocException
    {
        DigiDocException ex = validateTimeStampResponse(tsr);
        if (ex != null)
            throw ex;
        m_tsResp = tsr;
    }

    /**
     * Helper method to validate TimeStampResponse
     * 
     * @param tsr
     *            input data
     * @return exception or null for ok
     */
    private DigiDocException validateTimeStampResponse(TSResponse tsr)
    {
        DigiDocException ex = null;
        if (tsr == null)
            ex = new DigiDocException(DigiDocException.ERR_TIMESTAMP_RESP,
                    "timestamp cannot be null", null);
        return ex;
    }

    /**
     * return the count of IncludeInfo objects
     * 
     * @return count of IncludeInfo objects
     */
    public int countIncludeInfos()
    {
        return ((m_includes == null) ? 0 : m_includes.size());
    }

    /**
     * Adds a new IncludeInfo object
     * 
     * @param inc
     *            new object to be added
     */
    public void addIncludeInfo(IncludeInfo inc)
    {
        if (m_includes == null)
            m_includes = new ArrayList();
        inc.setTimestampInfo(this);
        m_includes.add(inc);
    }

    /**
     * Retrieves IncludeInfo element with the desired index
     * 
     * @param idx
     *            IncludeInfo index
     * @return IncludeInfo element or null if not found
     */
    public IncludeInfo getIncludeInfo(int idx)
    {
        if (m_includes != null && idx < m_includes.size())
        {
            return (IncludeInfo) m_includes.get(idx);
        }
        else
            return null; // not found
    }

    /**
     * Retrieves the last IncludeInfo element
     * 
     * @return IncludeInfo element or null if not found
     */
    public IncludeInfo getLastIncludeInfo()
    {
        if (m_includes != null && m_includes.size() > 0)
        {
            return (IncludeInfo) m_includes.get(m_includes.size() - 1);
        }
        else
            return null; // not found
    }

//    /**
//     * Retrieves timestamp responses signature algorithm OID.
//     * 
//     * @return responses signature algorithm OID
//     */
//    public String getAlgorithmOid()
//    {
//        String oid = null;
//        if (m_tsResp != null)
//        {
//            oid = m_tsResp.getTimeStampToken().getTimeStampInfo().getMessageImprintAlgOID();
//        }
//        return oid;
//    }
//
//    /**
//     * Retrieves timestamp responses policy
//     * 
//     * @return responses policy
//     */
//    public String getPolicy()
//    {
//        String oid = null;
//        if (m_tsResp != null)
//        {
//            oid = m_tsResp.getTimeStampToken().getTimeStampInfo().getPolicy();
//        }
//        return oid;
//    }

    /**
     * Retrieves timestamp issuing time
     * 
     * @return timestamp issuing time
     * @throws IOException 
     */
    public Date getTime()
    {
        Date d = null;
        
        if (m_tsResp != null)
        {
            try
            {
                TimestampToken timestampToken = new TimestampToken(this.m_tsResp.getToken().getContentInfo().getData());
                d = timestampToken.getDate();
            }
            catch (IOException e)
            {
            }            
        }
        
        return d;
    }

//    /**
//     * Retrieves timestamp msg-imprint digest
//     * 
//     * @return timestamp msg-imprint digest
//     */
//    public byte[] getMessageImprint()
//    {
//        byte[] b = null;
//        if (m_tsResp != null)
//        {
//            b = m_tsResp.getTimeStampToken().getTimeStampInfo().getMessageImprintDigest();
//        }
//        return b;
//    }
//
//    /**
//     * Retrieves timestamp nonce
//     * 
//     * @return timestamp nonce
//     */
//    public BigInteger getNonce()
//    {
//        BigInteger b = null;
//        if (m_tsResp != null)
//        {
//            b = m_tsResp.getTimeStampToken().getTimeStampInfo().getNonce();
//        }
//        return b;
//    }

    /**
     * Retrieves timestamp serial number
     * 
     * @return timestamp serial number
     */
    public BigInteger getSerialNumber()
    {
        BigInteger b = null;
        if (m_tsResp != null)
        {
            try
            {
                b = m_tsResp.getToken().getContentInfo().getContent().getBigInteger();
            }
            catch (IOException e)
            {
            }
        }
        return b;
    }

//    /**
//     * Retrieves timestamp is-ordered atribute
//     * 
//     * @return timestamp is-ordered atribute
//     */
//    public boolean isOrdered()
//    {
//        boolean b = false;
//        if (m_tsResp != null)
//        {
//            b = m_tsResp.getTimeStampToken().getTimeStampInfo().isOrdered();
//        }
//        return b;
//    }

    /**
     * Retrieves timestamp is-ordered atribute
     * 
     * @return timestamp is-ordered atribute
     */
    public String getSignerCN()
    {
        String s = null;
        if (m_tsResp != null)
        {
            // SignerId = m_tsResp.getTimeStampToken().getSignedAttributes()
            // org.bouncycastle.cms.CMSSignedData cms = m_tsResp.getTimeStampToken().

        }
        return s;
    }

    /**
     * Helper method to validate the whole TimestampInfo object
     * 
     * @return a possibly empty list of DigiDocException objects
     */
    public ArrayList validate()
    {
        ArrayList errs = new ArrayList();
        DigiDocException ex = validateId(m_id);
        if (ex != null)
            errs.add(ex);
        ex = validateType(m_type);
        if (ex != null)
            errs.add(ex);
        return errs;
    }

    /**
     * Converts the TimestampInfo to XML form
     * 
     * @return XML representation of TimestampInfo
     */
    public byte[] toXML() throws DigiDocException
    {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try
        {
            switch (m_type)
            {
            case TIMESTAMP_TYPE_ALL_DATA_OBJECTS:
                bos.write(ConvertUtils.str2data("<AllDataObjectsTimeStamp Id=\""));
                break;
            case TIMESTAMP_TYPE_INDIVIDUAL_DATA_OBJECTS:
                bos.write(ConvertUtils.str2data("<IndividualDataObjectsTimeStamp Id=\""));
                break;
            case TIMESTAMP_TYPE_SIGNATURE:
                bos.write(ConvertUtils.str2data("<SignatureTimeStamp Id=\""));
                break;
            case TIMESTAMP_TYPE_SIG_AND_REFS:
                bos.write(ConvertUtils.str2data("<SigAndRefsStamp Id=\""));
                break;
            case TIMESTAMP_TYPE_REFS_ONLY:
                bos.write(ConvertUtils.str2data("<RefsOnlyTimeStamp Id=\""));
                break;
            case TIMESTAMP_TYPE_ARCHIVE:
                bos.write(ConvertUtils.str2data("<ArchiveTimeStamp Id=\""));
                break;
            }
            bos.write(ConvertUtils.str2data(m_id));
            bos.write(ConvertUtils.str2data("\">"));
            for (int i = 0; i < countIncludeInfos(); i++)
            {
                IncludeInfo inc = getIncludeInfo(i);
                bos.write(inc.toXML());
            }
            bos.write(ConvertUtils.str2data("<EncapsulatedTimeStamp>"));
            if (m_tsResp != null)
                bos.write(ConvertUtils.str2data(Base64Util.encode(m_tsResp.getEncodedToken(), 64)));
            bos.write(ConvertUtils.str2data("</EncapsulatedTimeStamp>"));
            switch (m_type)
            {
            case TIMESTAMP_TYPE_ALL_DATA_OBJECTS:
                bos.write(ConvertUtils.str2data("</AllDataObjectsTimeStamp>"));
                break;
            case TIMESTAMP_TYPE_INDIVIDUAL_DATA_OBJECTS:
                bos.write(ConvertUtils.str2data("</IndividualDataObjectsTimeStamp>"));
                break;
            case TIMESTAMP_TYPE_SIGNATURE:
                bos.write(ConvertUtils.str2data("</SignatureTimeStamp>"));
                break;
            case TIMESTAMP_TYPE_SIG_AND_REFS:
                bos.write(ConvertUtils.str2data("</SigAndRefsStamp>"));
                break;
            case TIMESTAMP_TYPE_REFS_ONLY:
                bos.write(ConvertUtils.str2data("</RefsOnlyTimeStamp>"));
                break;
            case TIMESTAMP_TYPE_ARCHIVE:
                bos.write(ConvertUtils.str2data("</ArchiveTimeStamp>"));
                break;
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
