package es.uji.security.crypto.timestamp;

import es.uji.security.crypto.CryptoCoreException;

@SuppressWarnings("serial")
public class ASN1ParseException extends CryptoCoreException
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
