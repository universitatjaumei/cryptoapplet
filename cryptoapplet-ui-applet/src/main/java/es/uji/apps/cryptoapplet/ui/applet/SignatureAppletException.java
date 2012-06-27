package es.uji.apps.cryptoapplet.ui.applet;

import es.uji.apps.cryptoapplet.config.CryptoAppletException;

@SuppressWarnings("serial")
public class SignatureAppletException extends CryptoAppletException
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
