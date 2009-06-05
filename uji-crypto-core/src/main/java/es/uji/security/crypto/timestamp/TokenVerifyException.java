package es.uji.security.crypto.timestamp;

import es.uji.security.crypto.CryptoCoreException;

@SuppressWarnings("serial")
public class TokenVerifyException extends CryptoCoreException
{
    public TokenVerifyException()
    {
        super();
    }

    public TokenVerifyException(String message)
    {
        super(message);
    }

    public TokenVerifyException(String message, Throwable exception)
    {
        super(message, exception);
    }
}
