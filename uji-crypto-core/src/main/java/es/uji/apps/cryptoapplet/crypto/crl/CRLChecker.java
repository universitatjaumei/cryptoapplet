package es.uji.apps.cryptoapplet.crypto.crl;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;

import sun.security.x509.CRLDistributionPointsExtension;
import sun.security.x509.DistributionPoint;
import sun.security.x509.GeneralName;
import sun.security.x509.X509CertImpl;

public class CRLChecker
{
    private static HashMap<String, X509CRL> crl = new HashMap<String, X509CRL>();
    private static HashMap<String, Long> lastModified = new HashMap<String, Long>();

    public CRLResponseDetails getCertificateStatus(String crlURL, X509Certificate certificate)
    {
        CRLResponseDetails responseDetails = new CRLResponseDetails();

        X509CRL crl = null;

        try
        {
            crl = getCRL(crlURL);

            if (crl != null)
            {
                if (crl.isRevoked(certificate))
                {
                    responseDetails.setValid(false);
                    responseDetails.addError("Certificate is revoked");
                }
                else
                {
                    responseDetails.setValid(true);
                }
            }
        }
        catch (Exception e)
        {
            responseDetails.setValid(false);
            responseDetails.addError("Can not download CRL from " + crlURL + ": "
                    + e.getLocalizedMessage());
        }

        return responseDetails;
    }

    @SuppressWarnings({ "unchecked", "restriction" })
    public CRLResponseDetails getCertificateStatus(X509Certificate certificate)
    {
        CRLResponseDetails responseDetails = new CRLResponseDetails();
        String crlURL = null;

        // Try to extract CRL URL from the certificate

        try
        {
            X509CertImpl certificateImpl = (X509CertImpl) certificate;
            CRLDistributionPointsExtension crlDistributionPointsExtension = certificateImpl
                    .getCRLDistributionPointsExtension();

            for (DistributionPoint distributionPoint : ((List<DistributionPoint>) crlDistributionPointsExtension
                    .get(CRLDistributionPointsExtension.POINTS)))
            {
                for (GeneralName generalName : distributionPoint.getFullName().names())
                {
                    String generalNameString = generalName.toString();

                    if (generalNameString.startsWith("URIName: "))
                    {
                        crlURL = generalNameString.substring(9);
                        break;
                    }
                }

                if (crlURL != null)
                {
                    break;
                }
            }
        }
        catch (Exception e)
        {
            responseDetails.setValid(false);
            responseDetails.addError("Can not recover CRL URL from certificate");
        }

        if (crlURL != null)
        {
            responseDetails = getCertificateStatus(crlURL, certificate);
        }
        else
        {
            responseDetails.setValid(false);
            responseDetails.addError("Can not recover CRL URL from certificate");
        }

        return responseDetails;
    }

    private X509CRL getCRL(String crlURL) throws MalformedURLException, IOException, CRLException,
            CertificateException
    {
        HttpURLConnection conn = (HttpURLConnection) new URL(crlURL).openConnection();
        conn.setDoInput(true);
        conn.setConnectTimeout(5000);
        long now = conn.getLastModified();

        if (lastModified.get(crlURL) == null || now != lastModified.get(crlURL))
        {
            InputStream is = conn.getInputStream();
            BufferedInputStream bis = new BufferedInputStream(is);

            synchronized (crl)
            {
                synchronized (lastModified)
                {
                    crl.put(crlURL,
                            (X509CRL) CertificateFactory.getInstance("X.509").generateCRL(bis));
                    lastModified.put(crlURL, now);
                }
            }
        }

        return crl.get(crlURL);
    }
}
