package es.uji.security.ui.applet.io;

import java.io.IOException;

public interface OutputParams
{
    public void setSignFormat(byte[] signFormat) throws IOException;

    public void setSignData(byte[] data) throws IOException;

    public void signOk();

    public void flush();
}
