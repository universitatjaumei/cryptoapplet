package es.uji.security.ui.applet.io;

import java.io.IOException;
import java.io.InputStream;

public interface OutputParams
{
    public void setSignFormat(byte[] signFormat) throws IOException;

    public void setSignData(InputStream data) throws IOException;

    public void signOk();

    public void flush();
}
