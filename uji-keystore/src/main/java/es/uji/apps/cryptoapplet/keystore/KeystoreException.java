package es.uji.apps.cryptoapplet.keystore;

import es.uji.apps.cryptoapplet.config.CryptoAppletException;

@SuppressWarnings("serial")
public class KeystoreException extends CryptoAppletException
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