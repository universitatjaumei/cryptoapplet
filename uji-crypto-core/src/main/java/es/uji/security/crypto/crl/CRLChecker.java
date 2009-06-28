package es.uji.security.crypto.crl;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
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
import es.uji.security.crypto.CRLResponseDetails;

public class CRLChecker
{
    private HashMap<String, X509CRL> crl;
    private HashMap<String, Long> lastModified;
    
    public CRLChecker()
    {
        this.crl = new HashMap<String, X509CRL>();
        this.lastModified = new HashMap<String, Long>();
    }

    public CRLResponseDetails getCertificateStatus(String crlURL, X509Certificate certificate) throws MalformedURLException, CRLException, CertificateException, IOException
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
            responseDetails.addError("Can not download CRL from " + crlURL + ": " + e.getLocalizedMessage());
        }

        return responseDetails;
    }

    @SuppressWarnings("unchecked")
    public CRLResponseDetails getCertificateStatus(X509Certificate certificate) throws MalformedURLException, CRLException, CertificateException, IOException
    {
        CRLResponseDetails responseDetails = new CRLResponseDetails();

        String crlURL = null;
        
        // Try to extract CRL URL from the certificate
        
        try
        {
            X509CertImpl certificateImpl = (X509CertImpl) certificate;
            CRLDistributionPointsExtension crlDistributionPointsExtension = certificateImpl.getCRLDistributionPointsExtension();
                 
            for (DistributionPoint distributionPoint : ((List<DistributionPoint>) crlDistributionPointsExtension.get(CRLDistributionPointsExtension.POINTS))) 
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
    
    private X509CRL getCRL(String crlURL) throws MalformedURLException, IOException, CRLException, CertificateException
    {
        HttpURLConnection conn = (HttpURLConnection) new URL(crlURL).openConnection();
        conn.setDoInput(true);
        conn.setConnectTimeout(5000);
        long now = conn.getLastModified();

        if (lastModified.get(crlURL) == null || now != lastModified.get(crlURL))
        {
            InputStream is = conn.getInputStream();
            BufferedInputStream bis = new BufferedInputStream(is);
            
            crl.put(crlURL, (X509CRL) CertificateFactory.getInstance("X.509").generateCRL(bis));
            lastModified.put(crlURL, now);
        }
        
        return crl.get(crlURL);
    }
    
    private void showStatus(CRLResponseDetails responseDetails)
    {
        if (responseDetails.isValid())
        {
            System.out.println("OK");
        }
        else
        {
            for (String e : responseDetails.getErrors())
            {
                System.out.println(e);
            }
        }
    }
    
    public static void main(String[] args) throws MalformedURLException, CRLException, CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException
    {
        String crlURL = "http://www.accv.es/gestcert/ciudadanos.crl";
        
        CRLChecker crl = new CRLChecker();
        
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(new FileInputStream("src/main/resources/uactivo951v_firma.p12"), "1234"
                .toCharArray());
        X509Certificate cagvaFirma = (X509Certificate) ks
                .getCertificate(ks.aliases().nextElement());
        crl.showStatus(crl.getCertificateStatus(crlURL, cagvaFirma));

        ks = KeyStore.getInstance("PKCS12");
        ks.load(new FileInputStream("src/main/resources/uactivo951v_cifrado.p12"), "1234"
                .toCharArray());
        X509Certificate cagvaCifrado = (X509Certificate) ks.getCertificate(ks.aliases()
                .nextElement());
        crl.showStatus(crl.getCertificateStatus(crlURL, cagvaCifrado));

        ks = KeyStore.getInstance("PKCS12");
        ks.load(new FileInputStream("src/main/resources/urevocado952h_firma.p12"), "1234"
                .toCharArray());
        X509Certificate cagvaFirmaRevocado = (X509Certificate) ks.getCertificate(ks.aliases()
                .nextElement());
        crl.showStatus(crl.getCertificateStatus(crlURL, cagvaFirmaRevocado));

        ks = KeyStore.getInstance("PKCS12");
        ks.load(new FileInputStream("src/main/resources/urevocado952h_cifrado.p12"), "1234"
                .toCharArray());
        X509Certificate cagvaCifradoRevocado = (X509Certificate) ks.getCertificate(ks.aliases()
                .nextElement());
        crl.showStatus(crl.getCertificateStatus(crlURL, cagvaCifradoRevocado));

        ks = KeyStore.getInstance("PKCS12");
        ks.load(new FileInputStream("src/main/resources/cpruebas104p_firma.p12"), "1234"
                .toCharArray());
        X509Certificate accvFirma = (X509Certificate) ks.getCertificate(ks.aliases().nextElement());
        crl.showStatus(crl.getCertificateStatus(crlURL, accvFirma));

        ks = KeyStore.getInstance("PKCS12");
        ks.load(new FileInputStream("src/main/resources/cpruebas104p_cifrado.p12"), "1234"
                .toCharArray());
        X509Certificate accvCifrado = (X509Certificate) ks.getCertificate(ks.aliases()
                .nextElement());
        crl.showStatus(crl.getCertificateStatus(crlURL, accvCifrado));

        ks = KeyStore.getInstance("PKCS12");
        ks.load(new FileInputStream("src/main/resources/AEATPF_F2.p12"), "AEATPF_F2".toCharArray());
        X509Certificate accvFirmaRevocado = (X509Certificate) ks.getCertificate(ks.aliases()
                .nextElement());
        crl.showStatus(crl.getCertificateStatus(crlURL, accvFirmaRevocado));

        ks = KeyStore.getInstance("PKCS12");
        ks.load(new FileInputStream("src/main/resources/AEATPF_C2.p12"), "AEATPF_C2".toCharArray());
        X509Certificate accvCifradoRevocado = (X509Certificate) ks.getCertificate(ks.aliases()
                .nextElement());
        crl.showStatus(crl.getCertificateStatus(crlURL, accvCifradoRevocado));
        
        //
        // Extract CRL URL from certificate
        //
        
        crl.showStatus(crl.getCertificateStatus(cagvaFirma));
        crl.showStatus(crl.getCertificateStatus(cagvaCifrado));
        crl.showStatus(crl.getCertificateStatus(cagvaFirmaRevocado));
        crl.showStatus(crl.getCertificateStatus(cagvaCifradoRevocado));
        crl.showStatus(crl.getCertificateStatus(accvFirma));
        crl.showStatus(crl.getCertificateStatus(accvCifrado));
        crl.showStatus(crl.getCertificateStatus(accvFirmaRevocado));
        crl.showStatus(crl.getCertificateStatus(accvCifradoRevocado));        
    }
}
