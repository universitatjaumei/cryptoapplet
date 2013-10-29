package es.uji.security.crypto.crl;

import es.uji.security.crypto.CryptoCoreException;

@SuppressWarnings("serial")
public class CryptoCoreCRLException extends CryptoCoreException
{
    public CryptoCoreCRLException()
    {
        super();
    }

    public CryptoCoreCRLException(String message)
    {
        super(message);
    }

    public CryptoCoreCRLException(String message, Throwable exception)
    {
        super(message, exception);
    }
}
