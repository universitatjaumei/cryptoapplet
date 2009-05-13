package es.uji.security.ui.applet.io;

import es.uji.security.ui.applet.SignatureApplet;

public interface InputParams
{
    public int getInputCount() throws Exception;
    public String getSignFormat(SignatureApplet base);
    public byte[] getSignData() throws Exception;
    public byte[] getSignData(int item) throws Exception;
    public void flush();
}
