package es.uji.apps.cryptoapplet.crypto;

import java.io.InputStream;

public class ValidationOptions
{
    private InputStream signedData;
    private InputStream originalData;

    public void setSignedData(InputStream signedData)
    {
        this.signedData = signedData;
    }

    public InputStream getSignedData()
    {
        return this.signedData;
    }

    public void setOriginalData(InputStream originalData)
    {
        this.originalData = originalData;
    }

    public InputStream getOriginalData()
    {
        return this.originalData;
    }
}