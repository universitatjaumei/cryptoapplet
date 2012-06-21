package es.uji.apps.cryptoapplet.crypto;

import es.uji.apps.cryptoapplet.config.CryptoAppletException;

@SuppressWarnings("serial")
public class SignatureException extends CryptoAppletException
{
    public SignatureException()
    {
        super();
    }
    
    public SignatureException(Throwable e)
    {
        super(e);
    }
}
