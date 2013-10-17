package es.uji.apps.cryptoapplet.crypto.signature.format;

import java.io.InputStream;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.X509Certificate;

import es.uji.apps.cryptoapplet.config.model.Configuration;

public class SignatureOptions
{
    private X509Certificate certificate;
    private Provider provider;
    private PrivateKey privateKey;

    private InputStream dataToSign;

    private boolean hash = false;
    private boolean localFile = false;
    private boolean swapToFile = false;
    private boolean coSignEnabled = false;
    private boolean enveloped = true;

    private Configuration configuration;

    public SignatureOptions(Configuration configuration)
    {
        this.configuration = configuration;
    }

    public void setConfiguration(Configuration configuration)
    {
        this.configuration = configuration;
    }
    
    public Configuration getConfiguration()
    {
        return this.configuration;
    }

    public boolean isHash()
    {
        return hash;
    }

    public void setHash(boolean hash)
    {
        this.hash = hash;
    }

    public boolean isLocalFile()
    {
        return localFile;
    }

    public void setLocalFile(boolean localFile)
    {
        this.localFile = localFile;
    }

    public void setSwapToFile(boolean swapToFile)
    {
        this.swapToFile = swapToFile;
    }

    public boolean getSwapToFile()
    {
        return this.swapToFile;
    }

    public InputStream getDataToSign()
    {
        return this.dataToSign;
    }

    public void setDataToSign(InputStream dataToSign)
    {
        this.dataToSign = dataToSign;
    }

    public boolean isCoSignEnabled()
    {
        return coSignEnabled;
    }

    public void setCoSignEnabled(boolean coSignEnabled)
    {
        this.coSignEnabled = coSignEnabled;
    }

    public boolean isEnveloped()
    {
        return enveloped;
    }

    public void setEnveloped(boolean enveloped)
    {
        this.enveloped = enveloped;
    }

    public X509Certificate getCertificate()
    {
        return certificate;
    }

    public void setCertificate(X509Certificate certificate)
    {
        this.certificate = certificate;
    }

    public Provider getProvider()
    {
        return provider;
    }

    public void setProvider(Provider provider)
    {
        this.provider = provider;
    }

    public PrivateKey getPrivateKey()
    {
        return privateKey;
    }

    public void setPrivateKey(PrivateKey privateKey)
    {
        this.privateKey = privateKey;
    }
}