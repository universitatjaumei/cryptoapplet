package es.uji.security.crypto.ocsp;

import es.uji.security.crypto.CryptoCoreException;

@SuppressWarnings("serial")
public class CryptoCoreOCSPException extends CryptoCoreException
{
    public CryptoCoreOCSPException()
    {
        super();
    }

    public CryptoCoreOCSPException(String message)
    {
        super(message);
    }

    public CryptoCoreOCSPException(String message, Throwable exception)
    {
        super(message, exception);
    }
}
