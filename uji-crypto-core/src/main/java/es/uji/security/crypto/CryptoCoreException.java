package es.uji.security.crypto;

@SuppressWarnings("serial")
public class CryptoCoreException extends Exception
{
    public CryptoCoreException()
    {
        super();
    }

    public CryptoCoreException(String message)
    {
        super(message);
    }

    public CryptoCoreException(String message, Throwable exception)
    {
        super(message, exception);
    }
}
