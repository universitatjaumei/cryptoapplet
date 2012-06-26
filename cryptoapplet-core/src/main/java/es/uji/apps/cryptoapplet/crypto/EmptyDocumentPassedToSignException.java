package es.uji.apps.cryptoapplet.crypto;

@SuppressWarnings("serial")
public class EmptyDocumentPassedToSignException extends SignatureException
{
    public EmptyDocumentPassedToSignException()
    {
        super();
    }
    
    public EmptyDocumentPassedToSignException(Throwable e)
    {
        super(e);
    }
}
