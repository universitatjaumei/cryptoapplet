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
    int count = 0, current = 0;
    String[] inputs;
    int timeout = 10000;

    public URLInputParams(String[] sources)
    {
        inputs = sources;
        count = sources.length;
        initialized = true;
    }

    public int getInputCount() throws Exception
    {
        if (!initialized)
            throw new IOException("Uninitialized Input method");

        return count;
    }

    public InputStream getSignData() throws Exception
    {
        log.debug("Retrieving data from " + inputs[current]);
        
        URL url = new URL(inputs[current]);
        URLConnection uc = url.openConnection();

        uc.setConnectTimeout(timeout);
        uc.setReadTimeout(timeout);

        uc.connect();
        
        log.debug("Retrieved " + uc.getHeaderField("Content-Length") + " bytes");
        
        InputStream in = uc.getInputStream();

        current++;

        return in;
    }

    public InputStream getSignData(int item) throws Exception
    {
        if (!initialized)
        {
            throw new IOException("Uninitialized Input method");
        }

        if (item >= count)
        {
            throw new IOException("Item count length exceeded");
        }

        log.debug("Retrieving data from " + inputs[current]);

        URL url = new URL(inputs[item]);
        URLConnection uc = url.openConnection();

        uc.setConnectTimeout(timeout);
        uc.setReadTimeout(timeout);

        uc.connect();
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
        current = 0;
    }
}