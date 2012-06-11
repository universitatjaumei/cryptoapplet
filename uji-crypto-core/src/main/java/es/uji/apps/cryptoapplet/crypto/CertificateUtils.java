package es.uji.apps.cryptoapplet.crypto;

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

import es.uji.apps.cryptoapplet.config.ConfigManager;
import es.uji.apps.cryptoapplet.config.Configuration;

public class CertificateUtils
{
    public static X509Certificate readCertificate(String certLocation) throws KeyStoreException,
            IOException, CertificateException, NoSuchAlgorithmException
    {
        if (isKeystoreAlias(certLocation))
        {
            return loadCertificateFromKeystore(certLocation);
        }

        InputStream certificateStream = null;
        
        if (isHttpReference(certLocation))
        {
            URL url = new URL(certLocation);
            certificateStream = url.openStream();
        }
        else if (isJarReference(certLocation))
        {
            ClassLoader classLoader = ConfigManager.class.getClassLoader();
            certificateStream = classLoader.getResourceAsStream(certLocation.substring(6));
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

    private static X509Certificate loadCertificateFromKeystore(String certLocation)
            throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException
    {
        Configuration configManager = ConfigManager.getConfigurationInstance();
        ClassLoader classLoader = ConfigManager.class.getClassLoader();
        InputStream certificateStream = classLoader.getResourceAsStream(configManager.getKeystore()
                .getFileName());

        String str_cert = certLocation.substring(11);
        KeyStore keystore = KeyStore.getInstance(configManager.getKeystore().getType());

        keystore.load(certificateStream, configManager.getKeystore().getPassword().toCharArray());

        return (X509Certificate) keystore.getCertificate(str_cert);
    }

    private static boolean isKeystoreAlias(String certLocation)
    {
        return certLocation.startsWith("keystore://");
    }

    private static boolean isJarReference(String certLocation)
    {
        return certLocation.startsWith("jar://");
    }

    private static boolean isHttpReference(String certLocation)
    {
        return certLocation.startsWith("http");
    }
}
