package es.uji.security.crypto;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;


public class CertificateUtils
{
    public static X509Certificate readCertificate(String certLocation) throws KeyStoreException,
            IOException, CertificateException, NoSuchAlgorithmException
    {
        ConfigManager configManager = ConfigManager.getInstance();
        InputStream certificateStream = null;

        if (certLocation.startsWith("http"))
        {
            URL url = new URL(certLocation);
            certificateStream = url.openStream();
        }
        else if (certLocation.startsWith("jar://"))
        {
            ClassLoader classLoader = ConfigManager.class.getClassLoader();
            certificateStream = classLoader.getResourceAsStream(certLocation.substring(6));
        }
        else if (certLocation.startsWith("keystore://"))
        {
            ClassLoader classLoader = ConfigManager.class.getClassLoader();
            certificateStream = classLoader.getResourceAsStream(configManager
                    .getProperty("DEFAULT_KEYSTORE"));

            String str_cert = certLocation.substring(11);
            KeyStore keystore = KeyStore.getInstance("JKS");

            keystore.load(certificateStream, configManager.getProperty("DEFAULT_KEYSTORE_PASSWORD")
                    .toCharArray());

            return (X509Certificate) keystore.getCertificate(str_cert);
        }
        else
        {
            certificateStream = new FileInputStream(certLocation);
        }

        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) certificateFactory
                .generateCertificate(certificateStream);
        certificateStream.close();

        return certificate;
    }
}
