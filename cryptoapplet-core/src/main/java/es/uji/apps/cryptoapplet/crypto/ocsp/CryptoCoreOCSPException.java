package es.uji.apps.cryptoapplet.crypto.ocsp;

import es.uji.apps.cryptoapplet.config.CryptoAppletException;

@SuppressWarnings("serial")
public class CryptoCoreOCSPException extends CryptoAppletException
{
    public CryptoCoreOCSPException(String message)
    {
        super(message);
    }

    public CryptoCoreOCSPException(String message, Throwable exception)
    {
        super(message, exception);
    }
}
