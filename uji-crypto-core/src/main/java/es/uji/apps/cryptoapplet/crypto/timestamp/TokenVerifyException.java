package es.uji.apps.cryptoapplet.crypto.timestamp;

import es.uji.apps.cryptoapplet.crypto.CryptoAppletCoreException;

@SuppressWarnings("serial")
public class TokenVerifyException extends CryptoAppletCoreException
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
