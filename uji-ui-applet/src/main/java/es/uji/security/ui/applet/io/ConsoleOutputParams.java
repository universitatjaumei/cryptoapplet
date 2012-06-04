package es.uji.security.ui.applet.io;

import java.io.IOException;
import java.io.InputStream;

import org.apache.log4j.Logger;

import es.uji.security.crypto.StreamUtils;

public class ConsoleOutputParams implements OutputParams
{
    private Logger log = Logger.getLogger(ConsoleOutputParams.class);

    public void setSignData(InputStream is) throws IOException
    {
        byte[] data = StreamUtils.inputStreamToByteArray(is);
        System.out.println(new String(data));
    }

    public void setSignFormat(byte[] signFormat) throws IOException
    {
        log.debug("Called setSignFormat: " + new String(signFormat));
    }

    public void signOk()
    {
        log.debug("Called signOk function");
    }

    public void flush()
    {
    }
}