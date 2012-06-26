package es.uji.apps.cryptoapplet.crypto.ocsp;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

public class OCSPTest
{
    private void showStatus(OCSPResponseDetails responseDetails)
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
    public void ocsp() throws Exception
    {
        Provider provider = new BouncyCastleProvider();

        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(provider);
        }

        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");

        String ocspURL = "http://ocsp.accv.es";

        X509Certificate cagvaCertificate = (X509Certificate) certificateFactory
                .generateCertificate(new FileInputStream("src/main/resources/cagva.pem"));
        X509Certificate accvCertificate = (X509Certificate) certificateFactory
                .generateCertificate(new FileInputStream("src/main/resources/accv-ca2.pem"));
        X509Certificate ocspCertificate = (X509Certificate) certificateFactory
                .generateCertificate(new FileInputStream("src/main/resources/ocsp-gva.crt"));

        OCSPChecker oscp = new OCSPChecker();

        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(new FileInputStream("src/main/resources/uactivo951v_firma.p12"),
                "1234".toCharArray());
        X509Certificate cagvaFirma = (X509Certificate) ks
                .getCertificate(ks.aliases().nextElement());
        showStatus(oscp.getCertificateStatus(cagvaFirma, cagvaCertificate, ocspCertificate,
                provider));
        showStatus(oscp.getCertificateStatus(ocspURL, cagvaFirma, cagvaCertificate,
                ocspCertificate, provider));

        ks = KeyStore.getInstance("PKCS12");
        ks.load(new FileInputStream("src/main/resources/uactivo951v_cifrado.p12"),
                "1234".toCharArray());
        X509Certificate cagvaCifrado = (X509Certificate) ks.getCertificate(ks.aliases()
                .nextElement());
        showStatus(oscp.getCertificateStatus(ocspURL, cagvaCifrado, cagvaCertificate,
                ocspCertificate, provider));

        ks = KeyStore.getInstance("PKCS12");
        ks.load(new FileInputStream("src/main/resources/urevocado952h_firma.p12"),
                "1234".toCharArray());
        X509Certificate cagvaFirmaRevocado = (X509Certificate) ks.getCertificate(ks.aliases()
                .nextElement());
        showStatus(oscp.getCertificateStatus(ocspURL, cagvaFirmaRevocado, cagvaCertificate,
                ocspCertificate, provider));

        ks = KeyStore.getInstance("PKCS12");
        ks.load(new FileInputStream("src/main/resources/urevocado952h_cifrado.p12"),
                "1234".toCharArray());
        X509Certificate cagvaCifradoRevocado = (X509Certificate) ks.getCertificate(ks.aliases()
                .nextElement());
        showStatus(oscp.getCertificateStatus(ocspURL, cagvaCifradoRevocado, cagvaCertificate,
                ocspCertificate, provider));

        ks = KeyStore.getInstance("PKCS12");
        ks.load(new FileInputStream("src/main/resources/cpruebas104p_firma.p12"),
                "1234".toCharArray());
        X509Certificate accvFirma = (X509Certificate) ks.getCertificate(ks.aliases().nextElement());
        showStatus(oscp.getCertificateStatus(ocspURL, accvFirma, accvCertificate, ocspCertificate,
                provider));

        ks = KeyStore.getInstance("PKCS12");
        ks.load(new FileInputStream("src/main/resources/cpruebas104p_cifrado.p12"),
                "1234".toCharArray());
        X509Certificate accvCifrado = (X509Certificate) ks.getCertificate(ks.aliases()
                .nextElement());
        showStatus(oscp.getCertificateStatus(ocspURL, accvCifrado, accvCertificate,
                ocspCertificate, provider));

        ks = KeyStore.getInstance("PKCS12");
        ks.load(new FileInputStream("src/main/resources/AEATPF_F2.p12"), "AEATPF_F2".toCharArray());
        X509Certificate accvFirmaRevocado = (X509Certificate) ks.getCertificate(ks.aliases()
                .nextElement());
        showStatus(oscp.getCertificateStatus(ocspURL, accvFirmaRevocado, accvCertificate,
                ocspCertificate, provider));

        ks = KeyStore.getInstance("PKCS12");
        ks.load(new FileInputStream("src/main/resources/AEATPF_C2.p12"), "AEATPF_C2".toCharArray());
        X509Certificate accvCifradoRevocado = (X509Certificate) ks.getCertificate(ks.aliases()
                .nextElement());
        showStatus(oscp.getCertificateStatus(ocspURL, accvCifradoRevocado, accvCertificate,
                ocspCertificate, provider));
    }
}