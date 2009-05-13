package es.uji.security.ui.applet.io;

import java.io.IOException;

import org.apache.log4j.Logger;

public class ConsoleOutputParams implements OutputParams
{
    private Logger log = Logger.getLogger(ConsoleOutputParams.class);
    
    public void setSignData(byte[] data) throws IOException
    {
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