package es.uji.apps.cryptoapplet.crypto;

import java.io.InputStream;

import es.uji.apps.cryptoapplet.config.model.Configuration;

public class SignatureOptions
{
    // General options

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
}