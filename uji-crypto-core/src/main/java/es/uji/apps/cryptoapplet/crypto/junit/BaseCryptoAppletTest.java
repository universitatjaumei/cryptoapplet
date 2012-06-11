package es.uji.apps.cryptoapplet.crypto.junit;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;

import es.uji.apps.cryptoapplet.crypto.SignatureOptions;
import es.uji.apps.cryptoapplet.crypto.SignatureResult;
import es.uji.apps.cryptoapplet.crypto.VerificationResult;
import es.uji.apps.cryptoapplet.utils.FileSystemUtils;

public class BaseCryptoAppletTest
{
    protected Provider provider;
    protected KeyStore keystore;
    protected X509Certificate certificate;
    protected PrivateKey privateKey;

    protected byte[] data = "<root />".getBytes();

    protected SignatureOptions signatureOptions;

    public static String baseDir = "src/main/resources/";

    public BaseCryptoAppletTest()
    {
        String keyStoreFile = "../uji.keystore";
        String keyStoreType = KeyStore.getDefaultType();
        String keyStorePassword = "cryptoapplet";
        String keyPassword = "cryptoapplet";

        if (System.getProperty("uji.keystore.file") != null)
        {
            keyStoreFile = System.getProperty("uji.keystore.file");
        }

        if (System.getProperty("uji.keystore.type") != null)
        {
            keyStoreType = System.getProperty("uji.keystore.type");
        }

        if (System.getProperty("uji.keystore.password") != null)
        {
            keyStorePassword = System.getProperty("uji.keystore.password");
        }

        if (System.getProperty("uji.keystore.keypassword") != null)
        {
            keyPassword = System.getProperty("uji.keystore.keypassword");
        }

        provider = new BouncyCastleProvider();

        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(provider);
        }

        try
        {
            // Keystore almacenamiento certificados
            keystore = KeyStore.getInstance(keyStoreType);
            keystore.load(new FileInputStream(keyStoreFile), keyStorePassword.toCharArray());

            // Alias del certificado de firma
            String alias = (String) keystore.aliases().nextElement();

            if (System.getProperty("uji.keystore.alias") != null)
            {
                alias = System.getProperty("uji.keystore.alias");
            }

            // Certificado de firma
            certificate = (X509Certificate) keystore.getCertificate(alias);

            // Clave privada para firmar
            privateKey = (PrivateKey) keystore.getKey(alias, keyPassword.toCharArray());

            signatureOptions = new SignatureOptions();
            signatureOptions.setCertificate(certificate);
            signatureOptions.setPrivateKey(privateKey);
            signatureOptions.setProvider(provider);
        }
        catch (Exception e)
        {
            throw new RuntimeException(e);
        }
    }

    protected void showErrors(SignatureResult signatureResult, String dumpFile) throws IOException
    {
        if (signatureResult.getSignatureData() != null)
        {
            FileSystemUtils.dumpToFile(new File(dumpFile), signatureResult.getSignatureData());
        }

        if (!signatureResult.isValid())
        {
            for (String error : signatureResult.getErrors())
            {
                System.out.println(error);
            }
        }

        Assert.assertTrue(signatureResult.isValid());
    }

    protected void showErrors(VerificationResult verificationResult)
    {
        if (!verificationResult.isValid())
        {
            for (String error : verificationResult.getErrors())
            {
                System.out.println(error);
            }
        }

        Assert.assertTrue(verificationResult.isValid());
    }

    public void setData(byte[] data)
    {
        this.data = data;
    }
}