package es.uji.security.crypto.config;


public class ConfigException extends Exception {

	public ConfigException(String message)
    {
        super(message);
    }
	
	public ConfigException(Throwable cause)
    {
        super(cause);
    }

	public ConfigException(String message, String lineNumber)
    {
        super("Line: " + lineNumber + "::" + message);
    }
}
