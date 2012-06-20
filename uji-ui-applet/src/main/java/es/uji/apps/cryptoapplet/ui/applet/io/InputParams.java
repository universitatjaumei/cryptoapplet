package es.uji.apps.cryptoapplet.ui.applet.io;

import java.io.InputStream;

import es.uji.apps.cryptoapplet.ui.applet.SignatureApplet;

public interface InputParams
{
    public int getInputCount() throws Exception;
    public String getSignFormat(SignatureApplet base);
    public InputStream getSignData() throws Exception;
    public InputStream getSignData(int item) throws Exception;
    public void flush();
}
