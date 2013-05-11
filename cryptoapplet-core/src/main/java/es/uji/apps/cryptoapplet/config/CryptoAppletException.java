package es.uji.apps.cryptoapplet.config;

@SuppressWarnings("serial")
public class CryptoAppletException extends Exception 
{
    public CryptoAppletException()
    {
        super();
    }

    public CryptoAppletException(String message)
    {
        super(message);
    }

    public CryptoAppletException(Throwable exception)
    {
        super(exception);
    }

    public CryptoAppletException(String message, Throwable exception)
    {
        super(message, exception);
    }
}
