package es.uji.security.keystore;

import es.uji.security.crypto.CryptoCoreException;

@SuppressWarnings("serial")
public class KeystoreException extends CryptoCoreException 
{
    public KeystoreException()
    {
        super();
    }

    public KeystoreException(String message)
    {
        super(message);
    }

    public KeystoreException(Throwable exception)
    {
        super(exception);
    }

    public KeystoreException(String message, Throwable exception)
    {
        super(message, exception);
    }
}