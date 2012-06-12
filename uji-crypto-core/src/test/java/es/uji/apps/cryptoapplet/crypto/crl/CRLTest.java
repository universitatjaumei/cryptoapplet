package es.uji.apps.cryptoapplet.crypto.crl;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.junit.Test;

public class CRLTest
{
    public void showStatus(CRLResponseDetails responseDetails)
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

    @Test
    public void crl() throws KeyStoreException, NoSuchAlgorithmException, CertificateException,
            FileNotFoundException, IOException
    {
        String crlURL = "http://www.accv.es/gestcert/ciudadanos.crl";

        CRLChecker crl = new CRLChecker();

        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(new FileInputStream("src/main/resources/uactivo951v_firma.p12"),
                "1234".toCharArray());
        X509Certificate cagvaFirma = (X509Certificate) ks
                .getCertificate(ks.aliases().nextElement());
        showStatus(crl.getCertificateStatus(crlURL, cagvaFirma));

        ks = KeyStore.getInstance("PKCS12");
        ks.load(new FileInputStream("src/main/resources/uactivo951v_cifrado.p12"),
                "1234".toCharArray());
        X509Certificate cagvaCifrado = (X509Certificate) ks.getCertificate(ks.aliases()
                .nextElement());
        showStatus(crl.getCertificateStatus(crlURL, cagvaCifrado));

        ks = KeyStore.getInstance("PKCS12");
        ks.load(new FileInputStream("src/main/resources/urevocado952h_firma.p12"),
                "1234".toCharArray());
        X509Certificate cagvaFirmaRevocado = (X509Certificate) ks.getCertificate(ks.aliases()
                .nextElement());
        showStatus(crl.getCertificateStatus(crlURL, cagvaFirmaRevocado));

        ks = KeyStore.getInstance("PKCS12");
        ks.load(new FileInputStream("src/main/resources/urevocado952h_cifrado.p12"),
                "1234".toCharArray());
        X509Certificate cagvaCifradoRevocado = (X509Certificate) ks.getCertificate(ks.aliases()
                .nextElement());
        showStatus(crl.getCertificateStatus(crlURL, cagvaCifradoRevocado));

        ks = KeyStore.getInstance("PKCS12");
        ks.load(new FileInputStream("src/main/resources/cpruebas104p_firma.p12"),
                "1234".toCharArray());
        X509Certificate accvFirma = (X509Certificate) ks.getCertificate(ks.aliases().nextElement());
        showStatus(crl.getCertificateStatus(crlURL, accvFirma));

        ks = KeyStore.getInstance("PKCS12");
        ks.load(new FileInputStream("src/main/resources/cpruebas104p_cifrado.p12"),
                "1234".toCharArray());
        X509Certificate accvCifrado = (X509Certificate) ks.getCertificate(ks.aliases()
                .nextElement());
        showStatus(crl.getCertificateStatus(crlURL, accvCifrado));

        ks = KeyStore.getInstance("PKCS12");
        ks.load(new FileInputStream("src/main/resources/AEATPF_F2.p12"), "AEATPF_F2".toCharArray());
        X509Certificate accvFirmaRevocado = (X509Certificate) ks.getCertificate(ks.aliases()
                .nextElement());
        showStatus(crl.getCertificateStatus(crlURL, accvFirmaRevocado));

        ks = KeyStore.getInstance("PKCS12");
        ks.load(new FileInputStream("src/main/resources/AEATPF_C2.p12"), "AEATPF_C2".toCharArray());
        X509Certificate accvCifradoRevocado = (X509Certificate) ks.getCertificate(ks.aliases()
                .nextElement());
        showStatus(crl.getCertificateStatus(crlURL, accvCifradoRevocado));

        //
        // Extract CRL URL from certificate
        //

        showStatus(crl.getCertificateStatus(cagvaFirma));
        showStatus(crl.getCertificateStatus(cagvaCifrado));
        showStatus(crl.getCertificateStatus(cagvaFirmaRevocado));
        showStatus(crl.getCertificateStatus(cagvaCifradoRevocado));
        showStatus(crl.getCertificateStatus(accvFirma));
        showStatus(crl.getCertificateStatus(accvCifrado));
        showStatus(crl.getCertificateStatus(accvFirmaRevocado));
        showStatus(crl.getCertificateStatus(accvCifradoRevocado));
    }
}