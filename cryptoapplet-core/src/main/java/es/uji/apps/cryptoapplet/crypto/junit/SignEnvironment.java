package es.uji.apps.cryptoapplet.crypto.junit;

import es.uji.apps.cryptoapplet.config.ConfigManager;
import es.uji.apps.cryptoapplet.config.ConfigurationLoadException;
import es.uji.apps.cryptoapplet.config.model.Configuration;
import es.uji.apps.cryptoapplet.crypto.signature.format.SignatureOptions;

import java.io.ByteArrayInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.X509Certificate;

public class SignEnvironment
{
    private Provider provider;
    private X509Certificate certificate;
    private PrivateKey privateKey;

    private SignatureOptions signatureOptions;
    private byte[] data;
    private Configuration configuration;

    public SignEnvironment(TestKeyStore testKeyStore) throws ConfigurationLoadException
    {
        this(testKeyStore, new ConfigManager().getConfiguration());
    }

    public SignEnvironment(TestKeyStore testKeyStore, Configuration configuration)
    {
        this.provider = new com.sun.net.ssl.internal.ssl.Provider();
        this.configuration = configuration;

        try
        {
            KeyStore keystore = KeyStore.getInstance(testKeyStore.getKeyStoreType(), this.provider);
            keystore.load(testKeyStore.getKeyStore(), testKeyStore.getKeyStorePin());

            String alias = (String) keystore.aliases().nextElement();
            certificate = (X509Certificate) keystore.getCertificate(alias);
            privateKey = (PrivateKey) keystore.getKey(alias, testKeyStore.getKeyStorePin());
            signatureOptions = new SignatureOptions(configuration);

            setData("<root />".getBytes());
        }
        catch (Exception e)
        {
            throw new RuntimeException(e);
        }
    }

    public Provider getProvider()
    {
        return provider;
    }

    public X509Certificate getCertificate()
    {
        return certificate;
    }

    public PrivateKey getPrivateKey()
    {
        return privateKey;
    }

    public SignatureOptions getSignatureOptions()
    {
        return signatureOptions;
    }

    public void setData(byte[] data)
    {
        this.data = data;
        signatureOptions.setDataToSign(new ByteArrayInputStream(data));
    }

    public byte[] getData()
    {
        return data;
    }

    public void enableCosign()
    {
        signatureOptions.setCoSignEnabled(true);
    }

    public Configuration getConfiguration()
    {
        return configuration;
    }

    public void disableEnveloped()
    {
        signatureOptions.setEnveloped(false);
    }
}