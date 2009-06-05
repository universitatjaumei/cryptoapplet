package es.uji.security.ui.applet.io;

import java.io.DataOutputStream;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.util.StringTokenizer;

import netscape.javascript.JSObject;

import org.apache.log4j.Logger;

import es.uji.security.ui.applet.SignatureApplet;

public class URLOutputParams extends AbstractData implements OutputParams
{

    private Logger log = Logger.getLogger(URLOutputParams.class);

    String url = null;
    boolean _initialized = false, signOkInvoked = false;
    int _count = 1, outputcount = 0, conn_timeout = 10000, read_timeout = 60000;
    String[] _inputs;
    String postVariable = "content";
    SignatureApplet _base = null;

    public URLOutputParams(SignatureApplet sa, String url)
    {
        _base = sa;
        this.postVariable = "content";
        this.url = url;
    }

    public URLOutputParams(SignatureApplet sa, String url, String postVariable)
    {
        _base = sa;
        this.postVariable = this.postVariable;
        this.url = url;
    }

    public void setOutputCount(int oCount)
    {
        this.outputcount = oCount;
    }

    public void setSignData(byte[] data) throws IOException
    {
        String strAux, var, value, strpost;

        JSObject browser = (JSObject) JSObject.getWindow(_base);
        JSObject document = (JSObject) browser.getMember("document");

        // We must obtain the cookies:
        String cookie = (String) document.getMember("cookie");
        // log.debug("COOKIES: " + cookie);

        String strUrl = url;
        String urlOk;

        if (strUrl.indexOf('?') > -1)
            urlOk = strUrl.substring(0, strUrl.indexOf('?'));
        else
            urlOk = strUrl;

        log.debug(" Utilizando como url de envío: " + urlOk);
        URL url = new URL(urlOk);

        StringTokenizer strTok = new StringTokenizer(strUrl.substring(strUrl.indexOf('?') + 1), "&");

        HttpURLConnection urlConn = (HttpURLConnection) url.openConnection();

        urlConn.setConnectTimeout(conn_timeout);
        urlConn.setReadTimeout(read_timeout);

        urlConn.setRequestMethod("POST");
        urlConn.setRequestProperty("Content-type", "application/x-www-form-urlencoded");
        urlConn.setRequestProperty("Cookie", "");

        urlConn.setDoOutput(true);
        urlConn.setDoInput(true);

        DataOutputStream out = new DataOutputStream(urlConn.getOutputStream());
        out.writeBytes(postVariable + "=" + URLEncoder.encode(new String(data), "ISO-8859-1"));
        out.writeBytes("&item=" + URLEncoder.encode("" + _count, "ISO-8859-1"));

        while (strTok.hasMoreTokens())
        {
            strAux = strTok.nextToken();
            log.debug("PROCESANDO TOKEN: " + strAux);
            if (strAux.indexOf("=") > -1)
            {
                var = strAux.substring(0, strAux.indexOf("="));
                value = strAux.substring(strAux.indexOf("=") + 1);
                log.debug("ENVIANDO EN EL POST : " + var + "=" + value);
                out
                        .writeBytes("&" + var + "="
                                + URLEncoder.encode(new String(value), "ISO-8859-1"));
            }
        }

        out.flush();
        out.close();

        if (urlConn.getResponseCode() != HttpURLConnection.HTTP_OK)
        {
            System.out.println("Error en el post " + urlConn.getResponseCode());
        }
        /*
         * else { if (outputcount == _count){ signOk(); signOkInvoked=true; } }
         */
        _count++;
    }

    public void setSignFormat(SignatureApplet base, byte[] signFormat)
    {

        // TODO Auto-generated method stub
    }

    public void setSignFormat(byte[] signFormat) throws IOException
    {
        // TODO Auto-generated method stub

    }

    public void signOk()
    {
        if (!signOkInvoked)
            netscape.javascript.JSObject.getWindow(_base).call("onSignOk", new String[] { "" });
    }

    public void flush()
    {
        _count = 1;

    }
}
