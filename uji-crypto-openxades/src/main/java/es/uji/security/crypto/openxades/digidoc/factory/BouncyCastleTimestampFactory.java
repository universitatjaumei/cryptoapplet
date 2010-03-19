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

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;

import org.apache.log4j.Logger;

import es.uji.security.crypto.config.ConfigManager;
import es.uji.security.crypto.openxades.digidoc.DigiDocException;
import es.uji.security.crypto.openxades.digidoc.Signature;
import es.uji.security.crypto.openxades.digidoc.SignedDoc;
import es.uji.security.crypto.openxades.digidoc.TimestampInfo;
import es.uji.security.crypto.timestamp.TSResponse;
import es.uji.security.crypto.timestamp.TSResponseToken;
import es.uji.security.util.Base64;

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

    private ConfigManager conf = ConfigManager.getInstance();

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
        byte[] messageImp = null;

        try
        {
            TSResponseToken tsResponseToken = new TSResponseToken(ts.getTimeStampResponse());
            messageImp = tsResponseToken.getMessageImprint();

            if (m_logger.isDebugEnabled())
                m_logger.debug("Verifying TS: " + ts.getId() + " nr: " + ts.getSerialNumber());
            if (!SignedDoc.compareDigests(messageImp, ts.getHash()))
            {
                m_logger.error("TS digest: " + Base64.encodeBytes(messageImp) + " real digest: "
                        + Base64.encodeBytes(ts.getHash()));
                throw new DigiDocException(DigiDocException.ERR_TIMESTAMP_VERIFY,
                        "Bad digest for timestamp: " + ts.getId(), null);
            }

            TSResponse resp = ts.getTimeStampResponse();

            if (resp != null)
            {
                if (m_logger.isDebugEnabled())
                    m_logger.debug("TS status: " + resp.getStatusCode());

                if (resp.getStatusCode() == TSResponse.GRANTED
                        || resp.getStatusCode() == TSResponse.GRANTED_WITH_MODS)
                {
                    tsResponseToken.verify(tsaCert);
                    bOk = true;
                }
                else
                {
                    throw new DigiDocException(DigiDocException.ERR_TIMESTAMP_VERIFY,
                            "Invalid timestamp status: " + resp.getStatusCode(), null);
                }
            }
        }
        catch (Exception iex)
        {
            bOk = false;
            m_logger.error("Timestamp verification error: " + iex);
            throw new DigiDocException(DigiDocException.ERR_TIMESTAMP_VERIFY, "Invalid timestamp: "
                    + iex.getMessage(), iex);
        }

        return bOk;
    }

    private int findTSAIndex(Signature sig, String cn)
    {
        int idx = 0;
        // hack - just look at first TSA
        if (m_logger.isDebugEnabled())
            m_logger.debug("Cearch index for: " + cn);
        int nTsas = conf.getIntProperty("DIGIDOC_TSA_COUNT", 0);
        for (int i = 0; i < nTsas; i++)
        {
            String s1 = conf.getProperty("DIGIDOC_TSA" + (i + 1) + "_CN");
            if (s1 != null && s1.equals(cn))
                return i + 1;
        }
        return idx;
    }

    private X509Certificate findTSACert(int idx) throws DigiDocException
    {
        X509Certificate certificate = null;

        try
        {
            certificate = ConfigManager.readCertificate(conf.getProperty("DIGIDOC_TSA" + idx
                    + "_CERT"));
        }
        catch (Exception e)
        {
            DigiDocException.handleException(e, DigiDocException.ERR_READ_FILE);
        }

        return certificate;
    }

    private X509Certificate findTSACACert(int idx) throws DigiDocException
    {
        String fname = conf.getProperty("DIGIDOC_TSA" + idx + "_CA_CERT");
        if (m_logger.isDebugEnabled())
            m_logger.debug("Read ca cert: " + fname);

        X509Certificate certificate = null;

        try
        {
            certificate = ConfigManager.readCertificate(fname);
        }
        catch (Exception e)
        {
            DigiDocException.handleException(e, DigiDocException.ERR_READ_FILE);
        }

        return certificate;
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
