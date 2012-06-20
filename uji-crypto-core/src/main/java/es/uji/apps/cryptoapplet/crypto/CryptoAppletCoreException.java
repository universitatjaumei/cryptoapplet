package es.uji.apps.cryptoapplet.crypto;

@SuppressWarnings("serial")
public class CryptoAppletCoreException extends Exception 
{
    public CryptoAppletCoreException()
    {
        super();
    }

    public CryptoAppletCoreException(String message)
    {
        super(message);
    }

    public CryptoAppletCoreException(Throwable exception)
    {
        super(exception);
    }

    public CryptoAppletCoreException(String message, Throwable exception)
    {
        super(message, exception);
    }
}
