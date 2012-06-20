package es.uji.apps.cryptoapplet.ui.applet;

import es.uji.apps.cryptoapplet.config.i18n.LabelManager;

@SuppressWarnings("serial")
public class SignatureAppletException extends Exception
{
    private String message;

    public SignatureAppletException(String messageTag)
    {
        message = LabelManager.get(messageTag);
    }

    public SignatureAppletException(String messageTag, boolean translate)
    {
        if (translate)
        {
            message = LabelManager.get(messageTag);
        }
        else
        {
            message = messageTag;
        }
    }

    public String getMessage()
    {
        return message;
    }

    public SignatureAppletException(String messageTag, String lineNumber)
    {
        super("Line: " + lineNumber + "::" + LabelManager.get(messageTag));
    }
}
