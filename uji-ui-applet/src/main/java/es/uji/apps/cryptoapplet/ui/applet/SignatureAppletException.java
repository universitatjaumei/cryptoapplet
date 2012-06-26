package es.uji.apps.cryptoapplet.ui.applet;

@SuppressWarnings("serial")
public class SignatureAppletException extends Exception
{
    public SignatureAppletException(String message)
    {
        super(message);
    }

    public SignatureAppletException(String message, String lineNumber)
    {
        super("Line: " + lineNumber + "::" + message);
    }
}
