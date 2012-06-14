package es.uji.apps.cryptoapplet.keystore;

import es.uji.apps.cryptoapplet.crypto.CryptoAppletCoreException;

@SuppressWarnings("serial")
public class KeystoreException extends CryptoAppletCoreException
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