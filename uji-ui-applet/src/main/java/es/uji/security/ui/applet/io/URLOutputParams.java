package es.uji.security.ui.applet.io;

import netscape.javascript.JSObject;

import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.util.StringTokenizer;

import org.apache.log4j.Logger;

import es.uji.security.crypto.config.OS;
import es.uji.security.ui.applet.JSCommands;
import es.uji.security.ui.applet.SignatureApplet;

public class URLOutputParams extends AbstractData implements OutputParams
{
    private Logger log = Logger.getLogger(URLOutputParams.class);

    private String[] urls = null;
    private boolean signOkInvoked = false;

    private int conn_timeout = 10000;
    private int read_timeout = 60000;
    private String postVariable = "content";

    public URLOutputParams(String[] urls)
    {
        this(urls, "content");
    }

    public URLOutputParams(String[] urls, String postVariable)
    {
        this.urls = urls;
        this.postVariable = postVariable;
    }

    public void setOutputCount(int oCount)
    {
    }

    public void setSignData(InputStream is, int currentIndex) throws IOException
    {
        String currentURL = this.urls[currentIndex];

        String urlWithoutParams = getBaseUrlWithoutParams(currentURL);
        String urlParams = getParamsFromUrl(currentURL);

        log.debug("Posting data to " + currentURL + ", with post parameter variable " + postVariable);

        URL url = new URL(urlWithoutParams);

        HttpURLConnection urlConn = (HttpURLConnection) url.openConnection();

        urlConn.setConnectTimeout(conn_timeout);
        urlConn.setReadTimeout(read_timeout);

        urlConn.setRequestMethod("POST");
        urlConn.setRequestProperty("Content-type", "application/x-www-form-urlencoded");

        urlConn.setDoOutput(true);
        urlConn.setDoInput(true);

        DataOutputStream out = new DataOutputStream(urlConn.getOutputStream());

        byte[] buffer = new byte[2048];
        int length = 0;

        out.writeBytes(postVariable + "=");

        while ((length = is.read(buffer)) >= 0)
        {
            out.writeBytes(URLEncoder.encode(new String(buffer, 0, length), "ISO-8859-1"));
        }

        out.writeBytes("&item=" + URLEncoder.encode("" + currentIndex, "ISO-8859-1"));

        StringTokenizer strTok = new StringTokenizer(urlParams, "&");

        while (strTok.hasMoreTokens())
        {
            String strAux = strTok.nextToken();
            log.debug("PROCESANDO TOKEN: " + strAux);

            if (strAux.indexOf("=") > -1)
            {
                String var = strAux.substring(0, strAux.indexOf("="));
                String value = strAux.substring(strAux.indexOf("=") + 1);
                log.debug("ENVIANDO EN EL POST : " + var + "=" + value);

                out.writeBytes("&" + var + "=" + URLEncoder.encode(new String(value), "ISO-8859-1"));
            }
        }

        out.flush();
        out.close();

        if (urlConn.getResponseCode() >= 400)
        {
            log.error("Error en el post: " + urlConn.getResponseCode());
            throw new IOException("Error en el post: " + urlConn.getResponseCode());
        }

        try
        {
            is.close();
            new File(OS.getSystemTmpDir() + "/signature.xsig").delete();
        }
        catch (Exception e)
        {
        }
    }

    private String getParamsFromUrl(String currentURL)
    {
        if (hasQueryParams(currentURL))
        {
            return currentURL.substring(currentURL.indexOf('?') + 1);
        }

        return "";
    }

    private boolean hasQueryParams(String currentURL)
    {
        return currentURL.indexOf('?') > 0;
    }

    private String getBaseUrlWithoutParams(String currentURL)
    {
        if (hasQueryParams(currentURL))
        {
            return currentURL.substring(0, currentURL.indexOf('?'));
        }

        return currentURL;
    }

    public void setSignFormat(SignatureApplet base, byte[] signFormat)
    {
    }

    public void setSignFormat(byte[] signFormat) throws IOException
    {
    }

    public void signOk()
    {
        if (!signOkInvoked)
        {
            log.debug("Call JavaScript method: onSignOk");
            JSCommands.getWindow().call("onSignOk", new String[]{""});
        }
    }

    public void flush()
    {
    }
}
