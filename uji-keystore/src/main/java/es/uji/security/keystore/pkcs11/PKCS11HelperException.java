package es.uji.security.keystore.pkcs11;

public class PKCS11HelperException extends Exception
{

    public enum errorType
    {
        ERR_FIND_OBJECTS, ERR_INVOKE_INITIALIZE, ERR_GET_INFO, ERR_GET_SLOT_INFO, ERR_GET_TOKEN_INFO, ERR_OPEN_SESSION, ERR_GET_SLOT_LIST, ERR_CLOSE_SESSION, ERR_FINALIZE
    };

    private final errorType _error;

    public PKCS11HelperException(String msg, errorType error)
    {
        super(msg);
        _error = error;
    }

    public int getError()
    {
        return _error.ordinal();
    }

    public String getErrorDesc()
    {
        return _error.toString();
    }
}
