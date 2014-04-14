package es.uji.security.ui.applet.io;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;

import org.apache.log4j.Logger;

import es.uji.security.ui.applet.SignatureApplet;

public class URLInputParams extends AbstractData implements InputParams
{
    private Logger log = Logger.getLogger(URLInputParams.class);

    boolean initialized = false;
    String[] inputs;
    int timeout = 10000;

    public URLInputParams(String[] sources)
    {
        inputs = sources;
        initialized = true;
    }

    public int getInputCount() throws Exception
    {
        if (!initialized)
        {
            throw new IOException("Uninitialized Input method");
        }

        return inputs.length;
    }

    public InputStream getSignData(int currentIndex) throws Exception
    {
        if (!initialized)
        {
            throw new IOException("Uninitialized Input method");
        }

        if (currentIndex >= inputs.length)
        {
            throw new IOException("Item count length exceeded");
        }

        log.debug("Retrieving data from " + inputs[currentIndex]);

        URL url = new URL(inputs[currentIndex]);
        URLConnection uc = url.openConnection();

        uc.setConnectTimeout(timeout);
        uc.setReadTimeout(timeout);

        uc.connect();

        log.debug("Retrieved " + uc.getHeaderField("Content-Length") + " bytes");

        InputStream in = uc.getInputStream();

        if (mustHash)
        {
            return new ByteArrayInputStream(AbstractData.getMessageDigest(in));
        }

        return in;
    }

    public String getSignFormat(SignatureApplet base)
    {
        return base.getParameter("signFormat");
    }

    public void flush()
    {
    }
}