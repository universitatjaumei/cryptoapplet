package es.uji.security.ui.applet.io;

import java.io.IOException;
import java.util.Hashtable;

import javax.swing.JApplet;

import es.uji.security.ui.applet.SignatureApplet;

public interface OutputParams
{
    public void setSignFormat(byte[] signFormat) throws IOException;

    public void setSignData(byte[] data) throws IOException;

    public void signOk();

    public void flush();
}
