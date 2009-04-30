/*
 * BouncyCastleTimestampFactory.java
 * PROJECT: JDigiDoc
 * DESCRIPTION: Digi Doc functions for 
 *	handling timestamps 
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

package es.uji.security.crypto.openxades.digidoc.factory;

import es.uji.security.crypto.openxades.digidoc.Base64Util;
import es.uji.security.crypto.openxades.digidoc.DigiDocException;
import es.uji.security.crypto.openxades.digidoc.Signature;
import es.uji.security.crypto.openxades.digidoc.SignedDoc;
import es.uji.security.crypto.openxades.digidoc.TimestampInfo;
import es.uji.security.crypto.openxades.digidoc.factory.BouncyCastleTimestampFactory;
import es.uji.security.crypto.openxades.digidoc.factory.TimestampFactory;
import es.uji.security.crypto.openxades.digidoc.utils.ConfigManager;

import java.security.cert.X509Certificate;
import java.util.ArrayList;

import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.asn1.cmp.PKIStatus;

import org.apache.log4j.Logger;
import java.util.Date;

/**
 * Implements the TimestampFactory by using BouncyCastle JCE toolkit
 * 
 * @author Veiko Sinivee
 * @version 1.0
 */
public class BouncyCastleTimestampFactory implements TimestampFactory
{
    /** log4j logger object */
    private Logger m_logger = null;

    /**
     * Creates new BouncyCastleTimestampFactory
     */
    public BouncyCastleTimestampFactory()
    {
        m_logger = Logger.getLogger(BouncyCastleTimestampFactory.class);
    }

    /**
     * initializes the implementation class
     */
    public void init() throws DigiDocException
    {
    }

    /**
     * Verifies this one timestamp
     * 
     * @param ts
     *            TimestampInfo object
     * @param tsaCert
     *            TSA certificate
     * @returns result of verification
     */
    public boolean verifyTimestamp(TimestampInfo ts, X509Certificate tsaCert)
            throws DigiDocException
    {
        boolean bOk = false;

        if (m_logger.isDebugEnabled())
            m_logger.debug("Verifying TS: " + ts.getId() + " nr: " + ts.getSerialNumber());
        if (!SignedDoc.compareDigests(ts.getMessageImprint(), ts.getHash()))
        {
            m_logger.error("TS digest: " + Base64Util.encode(ts.getMessageImprint())
                    + " real digest: " + Base64Util.encode(ts.getHash()));
            throw new DigiDocException(DigiDocException.ERR_TIMESTAMP_VERIFY,
                    "Bad digest for timestamp: " + ts.getId(), null);
        }
        TimeStampResponse resp = ts.getTimeStampResponse();
        if (resp != null)
        {
            if (m_logger.isDebugEnabled())
                m_logger.debug("TS status: " + resp.getStatus());
            if (resp.getStatus() == PKIStatus.GRANTED
                    || resp.getStatus() == PKIStatus.GRANTED_WITH_MODS)
            {
                try
                {
                    // java.io.FileOutputStream fos= new java.io.FileOutputStream(new
                    // java.io.File("/tmp/token"));
                    // fos.write( resp.getTimeStampToken().getEncoded());
                    // fos.close();
                    bOk = true;
                    resp.getTimeStampToken().validate(tsaCert, "BC");

                }
                catch (Exception ex)
                {
                    bOk = false;
                    m_logger.error("Timestamp verification error: " + ex);
                    throw new DigiDocException(DigiDocException.ERR_TIMESTAMP_VERIFY,
                            "Invalid timestamp: " + ex.getMessage(), ex);
                }
            }
            else
                throw new DigiDocException(DigiDocException.ERR_TIMESTAMP_VERIFY,
                        "Invalid timestamp status: " + resp.getStatus(), null);
        }

        return bOk;
    }

    private int findTSAIndex(Signature sig, String cn)
    {
        int idx = 0;
        // hack - just look at first TSA
        if (m_logger.isDebugEnabled())
            m_logger.debug("Cearch index for: " + cn);
        int nTsas = ConfigManager.instance().getIntProperty("DIGIDOC_TSA_COUNT", 0);
        for (int i = 0; i < nTsas; i++)
        {
            String s1 = ConfigManager.instance().getProperty("DIGIDOC_TSA" + (i + 1) + "_CN");
            if (s1 != null && s1.equals(cn))
                return i + 1;
        }
        return idx;
    }

    private X509Certificate findTSACert(int idx) throws DigiDocException
    {
        return SignedDoc.readCertificate(ConfigManager.instance().getProperty(
                "DIGIDOC_TSA" + idx + "_CERT"));
    }

    private X509Certificate findTSACACert(int idx) throws DigiDocException
    {
        String fname = ConfigManager.instance().getProperty("DIGIDOC_TSA" + idx + "_CA_CERT");
        if (m_logger.isDebugEnabled())
            m_logger.debug("Read ca cert: " + fname);
        return SignedDoc.readCertificate(fname);
    }

    /**
     * Verifies all timestamps in this signature and return a list of errors.
     * 
     * @param sig
     *            signature to verify timestamps
     * @return list of errors. Empty if no errors.
     * @throws DigiDocException
     */
    public ArrayList verifySignaturesTimestamps(Signature sig)
    // throws DigiDocException
    {
        Date d1 = null, d2 = null;
        ArrayList errs = new ArrayList();
        ArrayList tsaCerts = sig.findTSACerts();
        for (int t = 0; t < sig.countTimestampInfos(); t++)
        {
            TimestampInfo ts = sig.getTimestampInfo(t);
            if (ts.getType() == TimestampInfo.TIMESTAMP_TYPE_SIGNATURE)
                d1 = ts.getTime();
            if (ts.getType() == TimestampInfo.TIMESTAMP_TYPE_SIG_AND_REFS)
                d2 = ts.getTime();
            boolean bVerified = false;
            DigiDocException ex2 = null;
            for (int j = 0; j < tsaCerts.size(); j++)
            {
                X509Certificate tsaCert = (X509Certificate) tsaCerts.get(j);
                if (m_logger.isDebugEnabled())
                    m_logger.debug("Verifying TS: " + ts.getId() + " with: "
                            + SignedDoc.getCommonName(tsaCert.getSubjectDN().getName()));
                // try verifying with all possible TSA certs
                try
                {
                    if (verifyTimestamp(ts, tsaCert))
                    {
                        bVerified = true;
                        if (m_logger.isDebugEnabled())
                            m_logger.debug("TS: " + ts.getId() + " - OK");
                        break;
                    }
                    else
                    {
                        m_logger.error("TS: " + ts.getId() + " - NOK");
                    }
                }
                catch (DigiDocException ex)
                {
                    ex2 = ex;
                    m_logger.error("TS: " + ts.getId() + " - ERROR: " + ex);
                    ex.printStackTrace(System.err);
                }
            }
            if (!bVerified)
            {
                errs.add(ex2);
            }
        }
        // now check that SignatureTimeStamp is before SigAndRefsTimeStamp
        if (d1 != null && d2 != null)
        {
            if (m_logger.isDebugEnabled())
                m_logger.debug("SignatureTimeStamp: " + d1 + " SigAndRefsTimeStamp: " + d2);
            if (d1.after(d2))
            {
                DigiDocException ex = new DigiDocException(DigiDocException.ERR_TIMESTAMP_VERIFY,
                        "SignatureTimeStamp time must be before SigAndRefsTimeStamp time!", null);
                errs.add(ex);
            }
        }
        return errs;
    }

}
