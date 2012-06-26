package es.uji.apps.cryptoapplet.ui.applet.io;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;
import java.util.List;

import org.apache.log4j.Logger;

import es.uji.apps.cryptoapplet.ui.applet.SignatureApplet;

public class URLInputParams extends AbstractData implements InputParams
{
    private Logger log = Logger.getLogger(URLInputParams.class);

    private boolean initialized = false;
    private int count = 0;
    private int current = 0;
    private List<String> inputs;
    private int timeout = 10000;

    public URLInputParams(List<String> sources)
    {
        inputs = sources;
        count = sources.size();
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
        log.debug("Retrieving data from " + inputs.get(current));

        URL url = new URL(inputs.get(current));
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

        log.debug("Retrieving data from " + inputs.get(current));

        URL url = new URL(inputs.get(item));
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