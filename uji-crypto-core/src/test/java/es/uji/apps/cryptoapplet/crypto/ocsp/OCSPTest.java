package es.uji.apps.cryptoapplet.crypto.ocsp;

import static org.junit.Assert.assertTrue;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Test;

public class OCSPTest
{
    private Provider provider;

    private String ocspURL = "http://localhost:8080/ejbca/publicweb/status/ocsp";

    private CertificateFactory certificateFactory;
    private X509Certificate cagvaCertificate;
    // private X509Certificate ocspCertificate;

    private OCSPChecker checker;

    @Before
    public void initProviders() throws CertificateException, FileNotFoundException
    {
        provider = new BouncyCastleProvider();

        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(provider);
        }

        certificateFactory = CertificateFactory.getInstance("X.509");

        cagvaCertificate = (X509Certificate) certificateFactory
                .generateCertificate(new FileInputStream("src/test/resources/ca.pem"));
        // ocspCertificate = (X509Certificate) certificateFactory
        // .generateCertificate(new FileInputStream("src/main/resources/ocsp-gva.crt"));

        checker = new OCSPChecker();
    }

    @Test
    public void checkValidityFromOcspUrlInsideCertificate() throws Exception
    {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(new FileInputStream("src/test/resources/cryptoapplet.p12"), "1234".toCharArray());
        X509Certificate cagvaFirma = (X509Certificate) ks
                .getCertificate(ks.aliases().nextElement());

        OCSPResponseDetails certificateStatus = checker.getCertificateStatus(ocspURL, cagvaFirma,
                cagvaCertificate, cagvaFirma, provider);

        for (String e : certificateStatus.getErrors())
        {
            System.out.println(e);
        }

        assertTrue(certificateStatus.isValid());
    }

    /*
     * showStatus(checker.getCertificateStatus(ocspURL, cagvaFirma, cagvaCertificate,
     * ocspCertificate, provider));
     * 
     * ks = KeyStore.getInstance("PKCS12"); ks.load(new
     * FileInputStream("src/main/resources/uactivo951v_cifrado.p12"), "1234".toCharArray());
     * X509Certificate cagvaCifrado = (X509Certificate) ks.getCertificate(ks.aliases()
     * .nextElement()); showStatus(checker.getCertificateStatus(ocspURL, cagvaCifrado,
     * cagvaCertificate, ocspCertificate, provider));
     * 
     * ks = KeyStore.getInstance("PKCS12"); ks.load(new
     * FileInputStream("src/main/resources/urevocado952h_firma.p12"), "1234".toCharArray());
     * X509Certificate cagvaFirmaRevocado = (X509Certificate) ks.getCertificate(ks.aliases()
     * .nextElement()); showStatus(checker.getCertificateStatus(ocspURL, cagvaFirmaRevocado,
     * cagvaCertificate, ocspCertificate, provider));
     * 
     * ks = KeyStore.getInstance("PKCS12"); ks.load(new
     * FileInputStream("src/main/resources/urevocado952h_cifrado.p12"), "1234".toCharArray());
     * X509Certificate cagvaCifradoRevocado = (X509Certificate) ks.getCertificate(ks.aliases()
     * .nextElement()); showStatus(checker.getCertificateStatus(ocspURL, cagvaCifradoRevocado,
     * cagvaCertificate, ocspCertificate, provider));
     * 
     * ks = KeyStore.getInstance("PKCS12"); ks.load(new
     * FileInputStream("src/main/resources/cpruebas104p_firma.p12"), "1234".toCharArray());
     * X509Certificate accvFirma = (X509Certificate) ks.getCertificate(ks.aliases().nextElement());
     * showStatus(checker.getCertificateStatus(ocspURL, accvFirma, accvCertificate, ocspCertificate,
     * provider));
     * 
     * ks = KeyStore.getInstance("PKCS12"); ks.load(new
     * FileInputStream("src/main/resources/cpruebas104p_cifrado.p12"), "1234".toCharArray());
     * X509Certificate accvCifrado = (X509Certificate) ks.getCertificate(ks.aliases()
     * .nextElement()); showStatus(checker.getCertificateStatus(ocspURL, accvCifrado,
     * accvCertificate, ocspCertificate, provider));
     * 
     * ks = KeyStore.getInstance("PKCS12"); ks.load(new
     * FileInputStream("src/main/resources/AEATPF_F2.p12"), "AEATPF_F2".toCharArray());
     * X509Certificate accvFirmaRevocado = (X509Certificate) ks.getCertificate(ks.aliases()
     * .nextElement()); showStatus(checker.getCertificateStatus(ocspURL, accvFirmaRevocado,
     * accvCertificate, ocspCertificate, provider));
     * 
     * ks = KeyStore.getInstance("PKCS12"); ks.load(new
     * FileInputStream("src/main/resources/AEATPF_C2.p12"), "AEATPF_C2".toCharArray());
     * X509Certificate accvCifradoRevocado = (X509Certificate) ks.getCertificate(ks.aliases()
     * .nextElement()); showStatus(checker.getCertificateStatus(ocspURL, accvCifradoRevocado,
     * accvCertificate, ocspCertificate, provider));
     */

}