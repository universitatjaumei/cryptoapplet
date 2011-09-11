package es.uji.security.crypto.config;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.Provider;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertStore;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class CertificateUtilsTest
{

    public static void main(String args[]) throws Exception
    {
        InputStream certificateStream = new FileInputStream("/home/paul/mio_new.pem");
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) certificateFactory
                .generateCertificate(certificateStream);
        certificateStream.close();

        X509Certificate[] xchain = CertificateUtils.getCertificateChain(certificate);
        String sep = "";
        if (xchain != null)
        {
            for (int i = 0; i < xchain.length; i++)
            {
                System.out.println(sep + "\\--> " + xchain[i].getSubjectDN());
                sep += "     ";
            }
            System.out.println(sep + "\\--> " + certificate.getSubjectDN());
        }
        else
        {
            System.out.println("xchain is null");
            System.exit(-1);
        }

        // Now validate the chain against the certificate.
        List<X509Certificate> lcertChain = new ArrayList<X509Certificate>();

        for (int i = 0; i < xchain.length; i++)
        {
            lcertChain.add(xchain[i]);
        }
        lcertChain.add(certificate);

        Provider provider = new BouncyCastleProvider();
        CollectionCertStoreParameters ccsp = new CollectionCertStoreParameters(lcertChain);
        CertStore store = CertStore.getInstance("Collection", ccsp);
        CertPath cp = CertificateFactory.getInstance("X.509", provider)
                .generateCertPath(lcertChain);

        Set<TrustAnchor> trust = new HashSet<TrustAnchor>();
        trust.add(new TrustAnchor((X509Certificate) lcertChain.get(0), null));

        PKIXParameters param = new PKIXParameters(trust);
        param.addCertStore(store);
        param.setRevocationEnabled(false);
        param.setTrustAnchors(trust);

        CertPathValidator cpv = CertPathValidator.getInstance("PKIX", provider);
        try
        {
            cpv.validate(cp, param);
            System.out.println("[+] Validation is OK");
        }
        catch (Exception ex)
        {
            System.out.println("[-] Cannot validate The certificate chain!");
            ex.printStackTrace();
        }
    }
}