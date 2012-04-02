package es.uji.security.ui.applet;

import org.mockito.Mockito;

import es.uji.security.crypto.DataEncoding;
import es.uji.security.crypto.SignatureFormat;
import es.uji.security.crypto.SupportedBrowser;

public class SignatureAppletTest
{
    public static void main(String[] args)
    {
        JSCommands jsCommands = Mockito.mock(JSCommands.class);
        Mockito.when(jsCommands.getSupportedBrowser()).thenReturn(SupportedBrowser.FIREFOX);

        SignatureApplet signatureApplet = new SignatureApplet(jsCommands);
        signatureApplet.init();
        signatureApplet.setInputDataEncoding(DataEncoding.PLAIN.name());
        signatureApplet.setOutputSignatureFormat(SignatureFormat.XADES.name());
        signatureApplet.showUI();
    }
}
