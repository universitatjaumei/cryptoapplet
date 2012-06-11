package es.uji.apps.cryptoapplet.crypto.timestamp;

import es.uji.apps.cryptoapplet.crypto.CryptoAppletCoreException;

@SuppressWarnings("serial")
public class ASN1ParseException extends CryptoAppletCoreException
{
    public ASN1ParseException()
    {
        super();
    }

    public ASN1ParseException(String message)
    {
        super(message);
    }

    public ASN1ParseException(String message, Throwable exception)
    {
        super(message, exception);
    }
}
