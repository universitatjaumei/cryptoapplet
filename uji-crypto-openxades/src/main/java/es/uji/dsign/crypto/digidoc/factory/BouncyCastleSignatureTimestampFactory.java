package es.uji.dsign.crypto.digidoc.factory;

import es.uji.dsign.crypto.digidoc.DigiDocException;
import es.uji.dsign.crypto.digidoc.Signature;
import es.uji.dsign.crypto.digidoc.SignedDoc;
import es.uji.dsign.crypto.digidoc.TimestampInfo;

import java.security.cert.X509Certificate;
import java.util.ArrayList;

import org.apache.log4j.Logger;

public class BouncyCastleSignatureTimestampFactory extends BouncyCastleTimestampFactory
{
    private Logger m_logger = null;

    public BouncyCastleSignatureTimestampFactory()
    {
        super();
        this.m_logger = Logger.getLogger(BouncyCastleTimestampFactory.class);
    }

    public ArrayList verifySignaturesTimestamps(Signature sig)
    {
        ArrayList<DigiDocException> errs = new ArrayList<DigiDocException>();
        ArrayList tsaCerts = sig.findTSACerts();

        for (int t = 0; t < sig.countTimestampInfos(); t++)
        {
            TimestampInfo ts = sig.getTimestampInfo(t);

            boolean bVerified = false;
            DigiDocException ex2 = null;

            for (int j = 0; j < tsaCerts.size(); j++)
            {
                X509Certificate tsaCert = (X509Certificate) tsaCerts.get(j);

                if (m_logger.isDebugEnabled())
                {
                    m_logger.debug("Verifying TS: " + ts.getId() + " with: "
                            + SignedDoc.getCommonName(tsaCert.getSubjectDN().getName()));
                }

                // try verifying with all possible TSA certs
                try
                {
                    if (super.verifyTimestamp(ts, tsaCert))
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

        return errs;
    }
}