package es.uji.apps.cryptoapplet.crypto.crl;

import es.uji.apps.cryptoapplet.config.CryptoAppletException;

@SuppressWarnings("serial")
public class CryptoCoreCRLException extends CryptoAppletException
{
    public CryptoCoreCRLException(String message)
    {
        super(message);
    }

    public CryptoCoreCRLException(String message, Throwable exception)
    {
        super(message, exception);
    }
}
