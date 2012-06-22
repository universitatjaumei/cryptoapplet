package es.uji.apps.cryptoapplet.crypto;

public class ValidationOptions
{
    private byte[] signedData;
    private byte[] originalData;

    public void setSignedData(byte[] signedData)
    {
        this.signedData = signedData;
    }

    public byte[] getSignedData()
    {
        return this.signedData;
    }

    public void setOriginalData(byte[] originalData)
    {
        this.originalData = originalData;
    }

    public byte[] getOriginalData()
    {
        return this.originalData;
    }
}
