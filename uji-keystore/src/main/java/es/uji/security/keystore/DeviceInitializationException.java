package es.uji.security.keystore;

@SuppressWarnings("serial")
public class DeviceInitializationException extends KeystoreException 
{
    public DeviceInitializationException()
    {
        super();
    }

    public DeviceInitializationException(String message)
    {
        super(message);
    }

    public DeviceInitializationException(Throwable exception)
    {
        super(exception);
    }
    
    public DeviceInitializationException(String message, Throwable exception)
    {
        super(message, exception);
    }
}