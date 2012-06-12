package es.uji.apps.cryptoapplet.crypto.crl;

import es.uji.apps.cryptoapplet.crypto.CryptoAppletCoreException;

@SuppressWarnings("serial")
public class CryptoCoreCRLException extends CryptoAppletCoreException
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
