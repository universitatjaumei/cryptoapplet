package es.uji.apps.cryptoapplet.crypto.ocsp;

import es.uji.apps.cryptoapplet.crypto.CryptoAppletCoreException;

@SuppressWarnings("serial")
public class CryptoCoreOCSPException extends CryptoAppletCoreException
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
